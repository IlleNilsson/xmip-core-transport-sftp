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
//! into a directory; a Receive Location connects, lists a directory, takes
//! each file and removes it.
//!
//! This transport is its own far end (ADR-0051): the [`Loopback`] far end is
//! a minimal in-process SSH server that serves the subsystem from a directory
//! held in memory, so one exchange runs both ways on this machine. It is a
//! real handshake — Curve25519 key exchange, an Ed25519 host key, `aes256-ctr`
//! with `hmac-sha2-256` — not a stub; what it is not is a general server, and
//! it admits every credential rather than checking one, because a loopback is
//! a counterparty and not a gatekeeper.
//!
//! Where the client authenticated by a public key, the far end promotes the
//! peer onto the arrival for the identity gate that follows: the origin URI
//! carries the key's fingerprint as `ssh.key`, the user as `ssh.user`, and the
//! signature and session identifier as `ssh.signature` and `ssh.session` —
//! the vocabulary `xmip-core-identify-ssh-key` and `-username` read, each
//! name declared once in `context::property`. A password authentication
//! carries only `ssh.user`.
//!
//! What is not here: only `aes256-ctr` with `hmac-sha2-256` is offered, so a
//! peer that will speak nothing else cannot connect; there is no known-hosts
//! check, so the host key is taken as presented (an inferred identity,
//! ADR-0019 clause 8); and the subsystem holds each directory whole in
//! memory, which is the [`SftpTransport::CEILING`] a payload may not exceed.

pub mod channel;
pub mod cipher;
pub mod client;
pub mod directory;
pub mod kex;
mod loopback;
pub mod packet;
pub mod server;
pub mod subsystem;
pub mod userauth;

use std::time::Duration;

use ed25519_dalek::SigningKey;

pub use client::{Client, Credential};
pub use server::Served;
use transport::error::Result;
use transport::loopback::LOOPBACK_TIMEOUT;
use transport::socket;
use transport::{Arrived, Directions, NoNativeClaim, ResourceClaim, Transport};

/// Speak SFTP as a client, and stand up an in-process far end.
pub struct SftpTransport {
    endpoint: String,
    user: String,
    credential: Credential,
    timeout: Option<Duration>,
}

impl SftpTransport {
    /// The largest payload the in-memory far end carries whole in one round:
    /// sixteen mebibytes. A protocol fact of this loopback, not a wire limit
    /// of SFTP, which chunks and streams without a size of its own.
    pub const CEILING: usize = 16 * 1024 * 1024;

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
        socket::target("sftp", &self.endpoint)
            .map_or(self.endpoint.as_str(), |(authority, _)| authority)
    }

    /// Where a target names the server and file — `sftp://host/dir/name` — or
    /// is a name alone on this transport's server.
    fn resolve<'a>(&'a self, target: &'a str) -> (&'a str, &'a str) {
        match socket::target("sftp", target) {
            Some((authority, path)) => (authority, last_segment(path)),
            None => (self.authority(), target),
        }
    }

    /// Connect and authenticate, as both `send` and `receive` do.
    fn connect(&self, address: &str) -> Result<Client> {
        Client::connect(address, &self.user, &self.credential, self.timeout)
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

    /// Every file in the directory, taken and removed. A scheduled pickup, so
    /// the arrival carries no peer: the key in play was Xmip's own.
    fn receive(&self) -> Result<Vec<Arrived>> {
        let authority = self.authority().to_string();
        let taken = self.connect(&authority)?.harvest()?;
        Ok(taken
            .into_iter()
            .map(|(name, bytes)| Arrived::new(format!("sftp://{authority}/{name}"), bytes))
            .collect())
    }

    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        let (address, name) = self.resolve(target);
        self.connect(address)?.put(name, bytes)
    }

    fn claims(&self) -> Option<&dyn ResourceClaim> {
        Some(&NoNativeClaim)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transport::loopback::Loopback;

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
