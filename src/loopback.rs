//! SFTP at both ends on this machine (ADR-0051): a client putting one file
//! into an in-process SSH server's directory, and taking the one file back as
//! the arrival with the peer promoted onto it.

use std::fmt::Write as _;
use std::net::TcpListener;

use ed25519_dalek::SigningKey;

use context::property::{SSH_KEY, SSH_SESSION, SSH_SIGNATURE, SSH_USER};
use transport::error::{Result, protocol_error};
use transport::listening::Listening;
use transport::loopback::{FarEnd, Loopback};
use transport::taken::Taken;
use transport::{Pool, socket};

use crate::SftpTransport;
use crate::server::{self, Served};

/// The file name the loopback's near end puts.
const PROBE: &str = "probe.bin";

impl Loopback for SftpTransport {
    /// A bound SSH server waiting for its one client, serving one
    /// directory. Bound through the tcp carrier this transport is declared
    /// over.
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        let host = SigningKey::from_bytes(&[0x5e; 32]);
        let timeout = self.timeout;
        Ok(Box::new(Listening::new(
            move |listener: &TcpListener| {
                let (stream, peer) = socket::accept_tcp(listener, timeout)?;
                let served = server::serve(stream, &host, crate::subsystem::Files::new())?;
                arrival(&peer.to_string(), &served)
            },
            tcp::TcpTransport::new(self.authority()).bind()?,
        )))
    }

    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        let near = SftpTransport {
            endpoint: address.to_string(),
            user: self.user.clone(),
            credential: self.credential.clone(),
            timeout: self.timeout,
            clients: Pool::new(),
            refused: self.refused.clone(),
        };
        near.connect(address)?.put(PROBE, payload)
    }
}

/// The one file the client put, as an arrival with the peer promoted onto its
/// origin URI for the identity gate.
fn arrival(peer: &str, served: &Served) -> Result<Taken> {
    let (name, bytes) = served
        .files
        .iter()
        .next()
        .ok_or_else(|| protocol_error("a client that connected and put nothing"))?;
    let mut origin = format!("sftp://{peer}/{name}?{SSH_USER}={}", served.who.user);
    if let Some(fingerprint) = &served.who.fingerprint {
        let _ = write!(origin, "&{SSH_KEY}={fingerprint}");
    }
    if let (Some(signature), Some(signed)) = (&served.who.signature, &served.who.signed) {
        let _ = write!(
            origin,
            "&{SSH_SIGNATURE}={}",
            codec::base64::encode_unpadded(signature)
        );
        let _ = write!(
            origin,
            "&{SSH_SESSION}={}",
            codec::base64::encode_unpadded(signed)
        );
    }
    Ok(Taken::new(origin, bytes.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use transport::payload::edge_payloads;

    #[test]
    fn the_loopback_returns_the_edge_payloads_whole() {
        let transport = SftpTransport::loopback();
        assert!(transport.ceiling().is_none());
        for (name, bytes) in edge_payloads() {
            assert!(transport.refuses(&bytes).is_none(), "{name}");
            let arrived = transport
                .round(&bytes)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(arrived.bytes, bytes, "{name}");
        }
    }

    #[test]
    fn the_arrival_carries_what_the_key_signed_and_it_verifies_under_that_key() {
        let arrived = SftpTransport::loopback().round(b"signed").expect("round");
        let query = arrived.origin_uri.split_once('?').expect("a query").1;
        let field = |name: &str| {
            query
                .split('&')
                .find_map(|pair| pair.strip_prefix(&format!("{name}=")))
                .unwrap_or_else(|| panic!("no {name} in {query}"))
        };
        let signed = codec::base64::decode(field(SSH_SESSION)).expect("base64");
        let signature = codec::base64::decode(field(SSH_SIGNATURE)).expect("base64");

        let data = ssh::userauth::SignedData::read(&signed).expect("RFC 4252 signed data");
        let key = ssh::key::PublicKey::parse(data.blob).expect("a key");

        assert_eq!(data.user, field(SSH_USER));
        assert_eq!(key.fingerprint().to_string(), field(SSH_KEY));
        key.verify(&signed, &signature)
            .expect("the signature covers it");
    }

    #[test]
    fn the_loopback_stands_on_every_machine() {
        assert!(SftpTransport::loopback().unavailable().is_none());
    }
}
