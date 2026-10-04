#![forbid(unsafe_code)]

//! Streams that arrive as files over SFTP. One file is one Stream, the peer
//! that put it kept beside it.
//!
//! SFTP is a file transfer that rides inside SSH rather than beside it: the
//! SSH transport layer (RFC 4253) exchanges keys and encrypts the line, user
//! authentication (RFC 4252) proves who is calling, one session channel
//! (RFC 4254) carries the `sftp` subsystem, and over that byte stream the
//! SFTP protocol (draft-ietf-secsh-filexfer-02, version 3) opens, writes,
//! reads, lists and removes files. A Send Location connects and puts a file
//! into a directory; a Receive Location connects, lists a directory and hands
//! each file back unread, read as the runtime asks and removed only when its
//! receive cycle accepted it ([`connection`]); a refused file is left where
//! it lies and not received again while it is unchanged. Everything up to
//! the subsystem is SSH, and is `xmip-core-library-ssh`'s; the SFTP protocol
//! is this crate's.
//!
//! This transport is its own far end (ADR-0051): the [`Loopback`] far end is
//! a minimal in-process SSH server that serves the subsystem from a directory
//! held in memory, so one exchange runs both ways on this machine. It is a
//! real handshake — Curve25519 key exchange, an Ed25519 host key, `aes256-ctr`
//! with `hmac-sha2-256` — not a stub; what it is not is a general server, and
//! it admits every well-formed credential rather than checking it against an
//! authorized one, because a loopback is a counterparty and not a
//! gatekeeper.
//!
//! Where the client authenticated by a public key, the far end promotes the
//! peer onto the arrival for the identity gate that follows: the origin URI
//! carries the key's fingerprint as `ssh.key`, the user as `ssh.user`, and the
//! signature and the signed data it covers (RFC 4252 section 7, the session
//! identifier first) as `ssh.signature` and `ssh.session` — the vocabulary
//! `xmip-core-identify-ssh-key` and `-username` read, each name declared once
//! in `context::property`, and what `xmip-core-authenticate-ssh-key` checks
//! the signature over. Until 2026-09-28 `ssh.session` carried the session
//! identifier alone, which no signature covers, so the gate could never
//! verify a key an SFTP arrival presented. A password authentication carries
//! only `ssh.user`.
//!
//! What is not here: only `aes256-ctr` with `hmac-sha2-256` is offered, so a
//! peer that will speak nothing else cannot connect; there is no known-hosts
//! check, so the host key is taken as presented (an inferred identity,
//! ADR-0019 clause 8); and the far end's subsystem holds each directory
//! whole in memory, a file no larger than `net::MAX_BODY`.

pub mod client;
pub mod connection;
pub mod directory;
mod loopback;
pub mod server;
pub mod subsystem;

use std::time::Duration;

use ed25519_dalek::SigningKey;

pub use client::{Client, Credential};
pub use connection::Connection;
use net::Target;
pub use server::Served;
pub use subsystem::Stamp;
use transport::error::Result;
use transport::loopback::LOOPBACK_TIMEOUT;
use transport::{
    Arrived, Configured, Directions, NoNativeClaim, Pool, Refused, ResourceClaim, Transport,
};
use xcore::settings::{Applies, Kind, Presence, Read, Setting, Settings};

/// Speak SFTP as a client, and stand up an in-process far end.
pub struct SftpTransport {
    endpoint: String,
    user: String,
    credential: Credential,
    timeout: Option<Duration>,
    /// The connections a send puts on and a receive harvests on, keys
    /// exchanged and authenticated once per server and kept, lent to a
    /// receive until its arrivals have their verdicts.
    clients: Pool<Connection>,
    /// The files this Location refused and left where they lie, each with
    /// its stamp; the node process's, so a node started again receives
    /// them once more.
    refused: Refused<String, Stamp>,
}

impl SftpTransport {
    /// The fixed key the loopback authenticates with, so its arrivals carry a
    /// stable fingerprint without drawing randomness at construction.
    const LOOPBACK_SEED: [u8; 32] = [0x7c; 32];

    /// Speak to the server at `endpoint` — `sftp://host:port/dir` or
    /// `host:port` — as user `xmip` with the password `xmip` until
    /// [`Self::as_user`], [`Self::with_password`] or [`Self::with_key`].
    #[must_use]
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            user: "xmip".to_string(),
            credential: Credential::Password("xmip".to_string()),
            timeout: None,
            clients: Pool::new(),
            refused: Refused::default(),
        }
    }

    /// Authenticate as this user.
    #[must_use]
    pub fn as_user(mut self, user: impl Into<String>) -> Self {
        self.user = user.into();
        self
    }

    /// Authenticate with this password.
    #[must_use]
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.credential = Credential::Password(password.into());
        self
    }

    /// Authenticate with this key, so the peer can be held to its fingerprint.
    #[must_use]
    pub fn with_key(mut self, key: SigningKey) -> Self {
        self.credential = Credential::PublicKey(Box::new(key));
        self
    }

    /// Give up on a peer that stops mid-exchange.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Both ends on this machine: an ephemeral local port, the loopback
    /// timeout, and a fixed key so every arrival carries the same fingerprint.
    #[must_use]
    pub fn loopback() -> Self {
        Self::new("127.0.0.1:0")
            .with_key(SigningKey::from_bytes(&Self::LOOPBACK_SEED))
            .timing_out_after(LOOPBACK_TIMEOUT)
    }

    /// The authority `endpoint` names, or `endpoint` itself where it is bare.
    fn authority(&self) -> &str {
        Target::under(&["sftp"], &self.endpoint)
            .map(|named| (named.authority(), named.path()))
            .map_or(self.endpoint.as_str(), |(authority, _)| authority)
    }

    /// Where a target names the server and file — `sftp://host/dir/name` — or
    /// is a name alone on this transport's server.
    fn resolve<'a>(&'a self, target: &'a str) -> (&'a str, &'a str) {
        match Target::under(&["sftp"], target).map(|named| (named.authority(), named.path())) {
            Some((authority, path)) => (authority, last_segment(path)),
            None => (self.authority(), target),
        }
    }

    /// Connect and authenticate, as both `send` and `receive` do.
    fn connect(&self, address: &str) -> Result<Client> {
        Client::connect(address, &self.user, &self.credential, self.timeout)
    }
}

impl Configured for SftpTransport {
    /// The address is the server and directory, `sftp://host:22/dir`, or
    /// `host:22` alone: where a Receive Location takes files from and a Send
    /// Location puts them.
    const SETTINGS: &'static Settings = &Settings {
        technology: env!("CARGO_PKG_NAME"),
        settings: &[
            Setting {
                name: "user",
                kind: Kind::Text,
                presence: Presence::Optional,
                meaning: "The user the session authenticates as; `xmip` when left out.",
                applies: Applies::Both,
            },
            Setting {
                name: "timeout",
                kind: Kind::Duration,
                presence: Presence::Optional,
                meaning: "How long a peer that stops mid-exchange is waited on; unbounded when \
                          left out.",
                applies: Applies::Both,
            },
        ],
    };

    /// The password or the key comes through the Location's credentials,
    /// not a setting.
    fn configured(address: &str, settings: &Read) -> Result<Self> {
        let mut transport = Self::new(address);
        if let Some(user) = settings.optional_text("user") {
            transport = transport.as_user(user);
        }
        if let Some(timeout) = settings.optional_duration("timeout") {
            transport = transport.timing_out_after(timeout);
        }
        Ok(transport)
    }
}

/// The last `/`-separated segment of `path`, the file's own name.
fn last_segment(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

impl Transport for SftpTransport {
    fn name(&self) -> &'static str {
        "sftp"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    fn arrivals(&self) -> transport::Arrivals {
        transport::Arrivals::Ordered("a receive lists again what is not yet told")
    }

    /// Every file in the directory, listed on the connection kept for the
    /// server — keys exchanged and authenticated on the first receive — and
    /// handed back unread: each body is read a request at a time as the
    /// runtime asks, `Accepted` removes the file, `Refused` leaves it and
    /// it is not listed again while its length and modification time stay
    /// as they were, `Failed` leaves it for the next receive
    /// ([`connection`]). A scheduled pickup, so the arrival carries no peer:
    /// the key in play was Xmip's own.
    fn receive(&self) -> Result<Vec<Arrived>> {
        let authority = self.authority();
        let origin = |name: &str| format!("sftp://{authority}/{name}");
        self.clients.exchange(
            authority,
            || self.connect(authority).map(Connection::new),
            |connection| connection.harvest(origin, &self.refused),
        )
    }

    /// Put the file on the connection kept for the server, keys exchanged
    /// and authenticated on the first send to it; a channel per file.
    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        let (address, name) = self.resolve(target);
        self.clients.exchange(
            address,
            || self.connect(address).map(Connection::new),
            |connection| connection.with(|client| client.put(name, bytes)),
        )
    }

    fn claims(&self) -> Option<&dyn ResourceClaim> {
        Some(&NoNativeClaim)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transport::loopback::Loopback;
    use transport::socket;

    #[test]
    fn sftp_declares_its_settings_and_reads_through_them() {
        use xcore::settings::Given;
        assert_eq!(SftpTransport::SETTINGS.problems(), Vec::<String>::new());
        let given = [
            ("user".to_string(), Given::Text("courier".to_string())),
            ("timeout".to_string(), Given::Text("2s".to_string())),
        ];
        let built =
            SftpTransport::open("sftp://host:22/in", Applies::Receive, &given).expect("configured");
        assert_eq!(built.authority(), "host:22");
        assert_eq!(built.user, "courier");
        assert_eq!(built.timeout, Some(Duration::from_secs(2)));
        let password = [("password".to_string(), Given::Text("x".to_string()))];
        let Err(refused) = SftpTransport::open("host:22", Applies::Send, &password) else {
            panic!("a password is a credential, not a setting");
        };
        assert!(refused.message.contains("\"password\""), "{refused}");
    }

    #[test]
    fn the_transport_names_itself_and_claims_without_locking() {
        let transport = SftpTransport::new("sftp://host:22/in");
        assert_eq!(transport.name(), "sftp");
        assert_eq!(transport.directions(), Directions::BOTH);
        assert!(transport.claims().is_some());
        assert_eq!(transport.authority(), "host:22");
        assert_eq!(
            transport.resolve("sftp://other:22/a/b.edi"),
            ("other:22", "b.edi")
        );
        assert_eq!(transport.resolve("plain.edi"), ("host:22", "plain.edi"));
    }

    #[test]
    fn a_hundred_puts_exchange_keys_once_and_a_connection_the_server_closed_is_replaced() {
        // A hundred: each put is a channel of its own, which is SFTP's.
        const SENDS: usize = 100;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address").to_string();
        let far_end = std::thread::spawn(move || {
            let host = SigningKey::from_bytes(&[0x5e; 32]);
            let mut served = Vec::new();
            for most in [SENDS, usize::MAX] {
                let (stream, _) =
                    socket::accept_tcp(&listener, Some(Duration::from_secs(5))).expect("accept");
                let files = subsystem::Files::new();
                served.push(server::serve_channels(stream, &host, files, most).expect("served"));
            }
            served
        });
        let near = SftpTransport::new(address).timing_out_after(Duration::from_secs(5));
        let began = std::time::Instant::now();
        for n in 0..SENDS {
            near.send(&format!("{n}.edi"), n.to_string().as_bytes())
                .expect("put");
        }
        let took = began.elapsed();
        // Generous for a debug build under load: five milliseconds a put.
        assert!(took < Duration::from_millis(5 * SENDS as u64), "{took:?}");
        near.send("last.edi", b"after the close")
            .expect("put again");
        assert_eq!(near.clients.opened(), 2);
        drop(near);
        let served = far_end.join().expect("far end");
        // One key exchange and one authentication for every put.
        assert_eq!(served[0].files.len(), SENDS);
        assert_eq!(
            served[1].files.get("last.edi").expect("kept"),
            b"after the close"
        );
    }

    #[test]
    fn a_hundred_receives_exchange_keys_once_and_a_connection_the_server_closed_is_replaced() {
        // A hundred: each harvest is a channel of its own, which is SFTP's.
        const RECEIVES: usize = 100;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address").to_string();
        let far_end = std::thread::spawn(move || {
            let host = SigningKey::from_bytes(&[0x5e; 32]);
            for most in [RECEIVES, usize::MAX] {
                let (stream, _) =
                    socket::accept_tcp(&listener, Some(Duration::from_secs(5))).expect("accept");
                let mut files = subsystem::Files::new();
                files.insert("1.edi".to_string(), b"harvested".to_vec());
                server::serve_channels(stream, &host, files, most).expect("served");
            }
        });
        let near = SftpTransport::new(address).timing_out_after(Duration::from_secs(5));
        let began = std::time::Instant::now();
        let mut arrived = Vec::new();
        for _ in 0..RECEIVES {
            for one in near.receive().expect("harvested") {
                arrived.push(one.taken().expect("taken"));
            }
        }
        let took = began.elapsed();
        // Generous for a debug build under load: five milliseconds a harvest.
        assert!(
            took < Duration::from_millis(5 * RECEIVES as u64),
            "{took:?}"
        );
        // One key exchange for every harvest: the file taken once.
        assert_eq!(arrived.len(), 1);
        assert_eq!(arrived[0].bytes, b"harvested");
        assert_eq!(near.receive().expect("harvested again").len(), 1);
        assert_eq!(near.clients.opened(), 2);
        drop(near);
        far_end.join().expect("far end");
    }

    #[test]
    fn a_failed_file_stays_a_refused_one_stays_unlisted_and_an_accepted_one_is_removed() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address").to_string();
        let far_end = std::thread::spawn(move || {
            let host = SigningKey::from_bytes(&[0x5e; 32]);
            let (stream, _) =
                socket::accept_tcp(&listener, Some(Duration::from_secs(5))).expect("accept");
            let mut files = subsystem::Files::new();
            files.insert("a.edi".to_string(), b"first".to_vec());
            files.insert("b.edi".to_string(), transport::payload::patterned(100_000));
            server::serve(stream, &host, files).expect("served")
        });
        let near = SftpTransport::new(address).timing_out_after(Duration::from_secs(5));
        let mut first = near.receive().expect("listed");
        assert_eq!(first.len(), 2);
        assert!(first.iter().all(Arrived::defers));
        // The first read through to its end and failed, the second refused
        // unread.
        let (_, mut body, acknowledgement) = first.remove(0).into_parts();
        let mut read = Vec::new();
        std::io::Read::read_to_end(&mut body, &mut read).expect("reading");
        assert_eq!(read, b"first");
        drop(body);
        acknowledgement
            .acknowledge(transport::Verdict::Failed)
            .expect("failed");
        first
            .remove(0)
            .refused(transport::Refusal::Unacceptable)
            .expect("refused");

        let again = near.receive().expect("listed again");
        assert_eq!(again.len(), 1, "the failed file, not the refused one");
        assert!(again[0].origin_uri.ends_with("/a.edi"));
        let taken = again
            .into_iter()
            .map(|one| one.taken().expect("taken"))
            .collect::<Vec<_>>();
        assert_eq!(taken[0].bytes, b"first");
        assert!(near.receive().expect("listed once more").is_empty());

        // Written again, the refused file is a new arrival.
        near.send("b.edi", b"written again").expect("put");
        let rewritten = near.receive().expect("listed after the write");
        assert_eq!(rewritten.len(), 1);
        let rewritten = rewritten.into_iter().next().expect("one");
        assert!(rewritten.origin_uri.ends_with("/b.edi"));
        rewritten
            .refused(transport::Refusal::Unacceptable)
            .expect("refused again");
        assert!(near.receive().expect("listed at last").is_empty());
        assert_eq!(near.clients.opened(), 1, "one connection for every receive");
        drop(near);
        let served = far_end.join().expect("far end");
        assert_eq!(served.files.len(), 1, "the accepted file is removed");
        assert_eq!(
            served
                .files
                .get("b.edi")
                .expect("the refused file lies there"),
            b"written again"
        );
    }

    #[test]
    fn the_loopback_puts_a_file_and_takes_it_with_the_peer_on_the_arrival() {
        let pair = SftpTransport::loopback();
        let arrived = pair.round(b"UNA:+.? '").expect("round");
        assert_eq!(arrived.bytes, b"UNA:+.? '");
        assert!(
            arrived.origin_uri.starts_with("sftp://127.0.0.1:"),
            "{}",
            arrived.origin_uri
        );
        assert!(
            arrived.origin_uri.contains("/probe.bin?"),
            "{}",
            arrived.origin_uri
        );
        assert!(
            arrived.origin_uri.contains("ssh.user=xmip"),
            "{}",
            arrived.origin_uri
        );
        assert!(
            arrived.origin_uri.contains("ssh.key=SHA256:"),
            "{}",
            arrived.origin_uri
        );
        assert!(
            arrived.origin_uri.contains("ssh.signature="),
            "{}",
            arrived.origin_uri
        );
        assert!(
            arrived.origin_uri.contains("ssh.session="),
            "{}",
            arrived.origin_uri
        );
    }
}
