//! SFTP at both ends on this machine (ADR-0051): a client putting one file
//! into an in-process SSH server's directory, and taking the one file back as
//! the arrival with the peer promoted onto it.

use std::fmt::Write as _;
use std::net::TcpListener;

use ed25519_dalek::SigningKey;

use transport::error::{Result, protocol_error};
use transport::loopback::{FarEnd, Loopback};
use transport::{Arrived, socket};

use crate::server::{self, Served};
use crate::{SSH_KEY, SSH_SESSION, SSH_SIGNATURE, SSH_USER, SftpTransport};

/// The file name the loopback's near end puts.
const PROBE: &str = "probe.bin";

impl Loopback for SftpTransport {
    fn ceiling(&self) -> Option<usize> {
        Some(Self::CEILING)
    }

    fn refuses(&self, payload: &[u8]) -> Option<String> {
        (payload.len() > Self::CEILING).then(|| {
            format!(
                "a payload of {} bytes, over the {} the in-memory far end holds whole",
                payload.len(),
                Self::CEILING
            )
        })
    }

    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        // Bind through the tcp carrier this transport is declared over.
        let (listener, address) = tcp::TcpTransport::new(self.authority()).bind()?;
        Ok(Box::new(Inbox {
            listener,
            address,
            host: SigningKey::from_bytes(&[0x5e; 32]),
            timeout: self.timeout,
        }))
    }

    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        let near = SftpTransport {
            endpoint: address.to_string(),
            user: self.user.clone(),
            credential: self.credential.clone(),
            timeout: self.timeout,
        };
        near.connect(address)?.put(PROBE, payload)
    }
}

/// A bound SSH server waiting for its one client, serving one directory.
struct Inbox {
    listener: TcpListener,
    address: String,
    host: SigningKey,
    timeout: Option<std::time::Duration>,
}

impl FarEnd for Inbox {
    fn address(&self) -> &str {
        &self.address
    }

    fn take_one(self: Box<Self>) -> Result<Arrived> {
        let (stream, peer) = socket::accept_tcp(&self.listener, self.timeout)?;
        let served = server::serve(stream, &self.host, crate::subsystem::Files::new())?;
        arrival(&peer.to_string(), &served)
    }
}

/// The one file the client put, as an arrival with the peer promoted onto its
/// origin URI for the identity gate.
fn arrival(peer: &str, served: &Served) -> Result<Arrived> {
    let (name, bytes) = served
        .files
        .iter()
        .next()
        .ok_or_else(|| protocol_error("a client that connected and put nothing"))?;
    let mut origin = format!("sftp://{peer}/{name}?{SSH_USER}={}", served.who.user);
    if let Some(fingerprint) = &served.who.fingerprint {
        let _ = write!(origin, "&{SSH_KEY}={fingerprint}");
    }
    if let Some(signature) = &served.who.signature {
        let _ = write!(
            origin,
            "&{SSH_SIGNATURE}={}",
            codec::base64::encode_unpadded(signature)
        );
        let _ = write!(
            origin,
            "&{SSH_SESSION}={}",
            codec::base64::encode_unpadded(&served.session_id)
        );
    }
    Ok(Arrived::new(origin, bytes.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use transport::payload::edge_payloads;

    #[test]
    fn the_loopback_returns_the_edge_payloads_whole() {
        let transport = SftpTransport::loopback();
        assert_eq!(transport.ceiling(), Some(SftpTransport::CEILING));
        for (name, bytes) in edge_payloads() {
            assert!(transport.refuses(&bytes).is_none(), "{name}");
            let arrived = transport
                .round(&bytes)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(arrived.bytes, bytes, "{name}");
        }
    }

    #[test]
    fn a_payload_over_the_ceiling_is_refused_with_its_reason() {
        let transport = SftpTransport::loopback();
        let over = vec![0u8; SftpTransport::CEILING + 1];
        let why = transport.refuses(&over).expect("refused");
        assert!(why.contains("over the"), "{why}");
        assert!(why.contains("holds whole"), "{why}");
        assert!(transport.unavailable().is_none());
    }
}
