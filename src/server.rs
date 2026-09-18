//! The in-process far end: a minimal SSH server that offers the `sftp`
//! subsystem over a directory held in memory, so the transport is both ends
//! of one exchange on this machine (ADR-0051). It is not a general SSH
//! server — one connection, one channel, one directory, every credential
//! admitted — which is all a loopback and the Playground need.

use std::net::TcpStream;

use ed25519_dalek::SigningKey;

use transport::error::Result;

use crate::channel::Channel;
use crate::directory;
use crate::kex;
use crate::packet::Conn;
use crate::subsystem::Files;
use crate::userauth::{self, Authenticated};

/// What one served connection left behind: the files, and who the peer was.
pub struct Served {
    /// The directory as it stands after the exchange.
    pub files: Files,
    /// Who authenticated and how.
    pub who: Authenticated,
    /// The session identifier the public-key signature was made over.
    pub session_id: Vec<u8>,
}

/// Serve one connection on `stream`, signing as `host`, over `files`.
///
/// # Errors
/// Where the key exchange, the authentication, the channel or the subsystem
/// failed.
pub fn serve(stream: TcpStream, host: &SigningKey, mut files: Files) -> Result<Served> {
    let mut conn = Conn::new(stream)?;
    let peer = conn.banner(kex::IDENTIFICATION)?;
    let exchanged = kex::server(&mut conn, host, &peer, kex::IDENTIFICATION)?;
    let who = userauth::serve(&mut conn, &exchanged.session_id)?;
    let mut channel = Channel::accept(&mut conn)?;
    directory::serve(&mut channel, &mut files)?;
    Ok(Served {
        files,
        who,
        session_id: exchanged.session_id,
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
        let host = kex::fresh_ed25519().expect("host");
        let auth = kex::fresh_ed25519().expect("auth");
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
            Some(secs(5)),
        )
        .expect("connect");
        client.put("probe.bin", b"one exchange").expect("put");
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
                .starts_with("SHA256:")
        );
    }

    #[test]
    fn a_client_harvests_a_populated_directory_and_leaves_it_empty() {
        let host = kex::fresh_ed25519().expect("host");
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
        let mut client = Client::connect(
            &address,
            "partner",
            &Credential::Password("open".into()),
            Some(secs(5)),
        )
        .expect("connect");
        let mut taken = client.harvest().expect("harvest");
        taken.sort();
        let served = far.join().expect("thread").expect("served");
        assert_eq!(taken.len(), 2);
        assert_eq!(taken[0], ("a.edi".to_string(), b"first".to_vec()));
        assert_eq!(taken[1], ("b.edi".to_string(), b"second".to_vec()));
        assert!(served.files.is_empty(), "harvested files are removed");
        assert!(served.who.fingerprint.is_none(), "a password keeps no key");
    }

    #[test]
    fn a_large_file_crosses_whole_through_many_write_chunks() {
        let host = kex::fresh_ed25519().expect("host");
        let auth = kex::fresh_ed25519().expect("auth");
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
            Some(secs(10)),
        )
        .expect("connect");
        client.put("big.bin", &payload).expect("put");
        let served = far.join().expect("thread").expect("served");
        assert_eq!(served.files.get("big.bin").expect("kept"), &payload);
    }
}
