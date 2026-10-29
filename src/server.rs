//! The in-process far end: a minimal SSH server that offers the `sftp`
//! subsystem over a directory held in memory, so the transport is both ends
//! of one exchange on this machine (ADR-0051). It is not a general SSH
//! server — one channel at a time per connection, one directory to a user,
//! every credential admitted — which is all a loopback and the Playground
//! need. A client that keeps its connection opens a channel per file, and
//! each is served in turn until the client hangs up; [`serving`] serves
//! every client a listener accepts at once, over one shared directory, and
//! [`serving_each`] each over the directory of the user it authenticated
//! as.

use std::net::TcpStream;
use std::ops::Deref;
use std::sync::{Mutex, PoisonError};

use ed25519_dalek::SigningKey;

use transport::concurrent::Concurrent;
use transport::error::Result;

use ssh::channel::Channel;
use ssh::kex;
use ssh::packet::Conn;
use ssh::userauth::{self, Authenticated};

use crate::directory;
use crate::subsystem::{self, Files};

/// What one served connection left behind: the files, and who the peer was.
pub struct Served {
    /// The directory as it stands after the exchange.
    pub files: Files,
    /// Who authenticated and how.
    pub who: Authenticated,
    /// The session identifier the public-key signature was made over.
    pub session_id: Vec<u8>,
}

/// Serve one connection on `stream`, signing as `host`, over `files`: its
/// channels one after another until the client hangs up.
///
/// # Errors
/// Where the key exchange, the authentication, the first channel or a
/// subsystem failed.
pub fn serve(stream: TcpStream, host: &SigningKey, files: Files) -> Result<Served> {
    serve_channels(stream, host, files, usize::MAX)
}

/// [`serve`], and hang up after `most` channels: a far end that goes away
/// while its client would carry on.
///
/// # Errors
/// As [`serve`].
pub fn serve_channels(
    stream: TcpStream,
    host: &SigningKey,
    files: Files,
    most: usize,
) -> Result<Served> {
    let held = Mutex::new(directory::Directory::new(files));
    let (who, session_id) = serve_directory(stream, host, &held, most)?;
    Ok(Served {
        files: held
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner)
            .files,
        who,
        session_id,
    })
}

/// Serve one connection on `stream` over `held`, a directory other
/// connections may be serving at the same time: its channels one after
/// another, at most `most`, until the client hangs up. Who authenticated,
/// and the session identifier.
///
/// # Errors
/// As [`serve`].
pub fn serve_directory(
    stream: TcpStream,
    host: &SigningKey,
    held: &Mutex<directory::Directory>,
    most: usize,
) -> Result<(Authenticated, Vec<u8>)> {
    serve_chosen(stream, host, |_| held, most)
}

/// Serve one connection on `stream` over the directory `chosen` gives the
/// user who authenticated, its channels one after another, at most `most`.
fn serve_chosen<D: Deref<Target = Mutex<directory::Directory>>>(
    stream: TcpStream,
    host: &SigningKey,
    chosen: impl FnOnce(&str) -> D,
    most: usize,
) -> Result<(Authenticated, Vec<u8>)> {
    let mut conn = Conn::new(stream)?;
    let peer = conn.banner(kex::IDENTIFICATION)?;
    let exchanged = kex::server(&mut conn, host, &peer, kex::IDENTIFICATION)?;
    let who = userauth::serve(&mut conn, &exchanged.session_id)?;
    let held = chosen(&who.user);
    let held = &*held;
    let mut channel = Channel::accept(&mut conn, subsystem::SUBSYSTEM)?;
    directory::serve(&mut channel, held)?;
    channel.close()?;
    // A channel that does not open is the client gone: the connection ends
    // there, as the one before it did.
    for _ in 1..most {
        let Ok(mut channel) = Channel::accept(&mut conn, subsystem::SUBSYSTEM) else {
            break;
        };
        directory::serve(&mut channel, held)?;
        channel.close()?;
    }
    Ok((who, exchanged.session_id))
}

/// Serve every client `listener` accepts at once over `shared`, signing as
/// `host`, each read given up after `timeout`: one server several
/// receiving nodes race at (ADR-0024, amendment 2026-10-13). Dropped, it
/// stops accepting.
///
/// # Errors
/// Where the listener's address could not be read.
pub fn serving(
    listener: std::net::TcpListener,
    host: SigningKey,
    shared: directory::Shared,
    timeout: Option<std::time::Duration>,
) -> Result<Concurrent> {
    Concurrent::start(listener, "sftp-session", move |stream| {
        if transport::socket::settle(&stream, timeout).is_ok() {
            let _ = serve_directory(stream, &host, &shared, usize::MAX);
        }
    })
}

/// Serve every client `listener` accepts at once, each over the directory
/// `of` gives the user it authenticated as, signing as `host`, each read
/// given up after `timeout`: one server whose every account has a directory
/// of its own, as a trading Party's server gives each Party one — the
/// Parties' far end the Playground serves the nodes on machines of their
/// own (ADR-0028, amendment 2026-10-22). Dropped, it stops accepting.
///
/// # Errors
/// Where the listener's address could not be read.
pub fn serving_each(
    listener: std::net::TcpListener,
    host: SigningKey,
    of: impl Fn(&str) -> directory::Shared + Send + Sync + 'static,
    timeout: Option<std::time::Duration>,
) -> Result<Concurrent> {
    Concurrent::start(listener, "sftp-session", move |stream| {
        if transport::socket::settle(&stream, timeout).is_ok() {
            let _ = serve_chosen(stream, &host, &of, usize::MAX);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{Client, Credential};
    use std::net::TcpListener;
    use std::time::Duration;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn a_client_puts_a_file_and_the_far_end_keeps_it_with_the_peers_key() {
        let host = kex::fresh_ed25519();
        let auth = kex::fresh_ed25519();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("addr").to_string();
        let far = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            stream.set_read_timeout(Some(secs(5))).expect("timeout");
            serve(stream, &host, Files::new())
        });
        let mut client = Client::connect(
            &address,
            "xmip",
            &Credential::PublicKey(Box::new(auth)),
            (Some(secs(5)), &transport::Pinned::in_memory()),
        )
        .expect("connect");
        client
            .put("probe.bin", &transport::Outgoing::held(b"one exchange"))
            .expect("put");
        // Hung up, so the far end stops waiting for another channel.
        drop(client);
        let served = far.join().expect("thread").expect("served");
        assert_eq!(
            served.files.get("probe.bin").expect("kept"),
            b"one exchange"
        );
        assert_eq!(served.who.user, "xmip");
        assert!(
            served
                .who
                .fingerprint
                .expect("a key")
                .to_string()
                .starts_with("SHA256:")
        );
    }

    #[test]
    fn a_client_harvests_a_populated_directory_and_leaves_it_empty() {
        let host = kex::fresh_ed25519();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("addr").to_string();
        let far = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            stream.set_read_timeout(Some(secs(5))).expect("timeout");
            let mut files = Files::new();
            files.insert("a.edi".to_string(), b"first".to_vec());
            files.insert("b.edi".to_string(), b"second".to_vec());
            serve(stream, &host, files)
        });
        let near = crate::SftpTransport::new(address.clone())
            .as_user("party")
            .with_password("open")
            .timing_out_after(secs(5));
        let found = transport::Transport::receive(&near).expect("found");
        assert!(
            found.is_empty(),
            "taken by the listing after the one that found it"
        );
        let mut taken = transport::Transport::receive(&near)
            .expect("harvest")
            .into_iter()
            .map(|one| one.taken().expect("taken"))
            .collect::<Vec<_>>();
        taken.sort_by(|a, b| a.origin_uri.cmp(&b.origin_uri));
        // Hung up, so the far end stops waiting for another channel.
        drop(near);
        let served = far.join().expect("thread").expect("served");
        assert_eq!(taken.len(), 2);
        assert_eq!(taken[0].origin_uri, format!("sftp://{address}/a.edi"));
        assert_eq!(taken[0].bytes, b"first");
        assert_eq!(taken[1].bytes, b"second");
        assert!(served.files.is_empty(), "harvested files are removed");
        assert!(served.who.fingerprint.is_none(), "a password keeps no key");
    }

    #[test]
    fn a_large_file_crosses_whole_through_many_write_chunks() {
        let host = kex::fresh_ed25519();
        let auth = kex::fresh_ed25519();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("addr").to_string();
        let far = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            stream.set_read_timeout(Some(secs(10))).expect("timeout");
            serve(stream, &host, Files::new())
        });
        let payload = transport::payload::patterned(200_000);
        let mut client = Client::connect(
            &address,
            "xmip",
            &Credential::PublicKey(Box::new(auth)),
            (Some(secs(10)), &transport::Pinned::in_memory()),
        )
        .expect("connect");
        client
            .put("big.bin", &transport::Outgoing::held(&payload))
            .expect("put");
        // Hung up, so the far end stops waiting for another channel.
        drop(client);
        let served = far.join().expect("thread").expect("served");
        assert_eq!(served.files.get("big.bin").expect("kept"), &payload);
    }

    /// The one secret a test sets, or none.
    struct One(Option<xcore::Secret>);

    impl xcore::Secrets for One {
        fn secret(
            &self,
            _name: &xcore::SecretName,
        ) -> std::result::Result<Option<xcore::Secret>, xcore::Failure> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn a_location_presents_the_key_its_secret_holds_and_says_one_not_set() {
        use transport::{Configured as _, Secured, Transport as _};
        let name = xcore::SecretName::new("partner-x.sftp").expect("a name");
        let unset = Secured::new(name.clone(), std::sync::Arc::new(One(None)));
        let near = crate::SftpTransport::new("127.0.0.1:9")
            .secured_by(unset)
            .expect("kept");
        let refused = near.send("probe.bin", b"x").expect_err("not set");
        assert!(
            refused.message.contains("'partner-x.sftp' is not set"),
            "{refused}"
        );

        let host = kex::fresh_ed25519();
        let auth = kex::fresh_ed25519();
        let pem = ssh::private_key::written(&auth);
        let secret = xcore::Secret::new(name.clone(), xcore::SecretKind::Key, pem.into_bytes());
        let set = Secured::new(name, std::sync::Arc::new(One(Some(secret.expect("a key")))));
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("addr").to_string();
        let far = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            stream.set_read_timeout(Some(secs(5))).expect("timeout");
            serve(stream, &host, Files::new())
        });
        let near = crate::SftpTransport::new(address)
            .as_user("party")
            .timing_out_after(secs(5))
            .secured_by(set)
            .expect("kept");
        near.send("probe.bin", b"keyed").expect("sent");
        drop(near);
        let served = far.join().expect("thread").expect("served");
        let expected = ssh::key::PublicKey::ed25519(&auth.verifying_key()).fingerprint();
        assert_eq!(
            served.who.fingerprint.map(|f| f.to_string()),
            Some(expected.to_string())
        );
    }
}
