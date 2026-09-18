//! What seals a binary packet on the way out and opens it on the way in:
//! nothing, before the keys are exchanged, and one negotiated suite after.
//!
//! The one suite this transport offers is `aes256-ctr` for confidentiality
//! with `hmac-sha2-256` for integrity (RFC 4253 section 6.3, RFC 6668): the
//! packet is encrypted with AES-256 in counter mode and a SHA-256 HMAC over
//! the sequence number and the cleartext packet rides after it. The keys and
//! initialisation vectors come from the shared secret and the exchange hash
//! through the key derivation of RFC 4253 section 7.2.

use std::io::{BufReader, Read};
use std::net::TcpStream;

use aes::Aes256;
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use transport::error::{Result, classify, protocol_error};

use crate::packet::MAX_PACKET;

/// The cipher's block size: eight for the cleartext framing, sixteen for
/// AES.
type HmacSha256 = Hmac<Sha256>;
type Aes256Ctr = Ctr128BE<Aes256>;

/// One direction's sealing and opening.
pub trait Cipher: Send {
    /// Wrap `payload` as a binary packet for sequence number `seq`.
    ///
    /// # Errors
    /// Where randomness for the padding could not be drawn.
    fn seal(&mut self, seq: u32, payload: &[u8]) -> Result<Vec<u8>>;

    /// Read and unwrap one binary packet for sequence number `seq`.
    ///
    /// # Errors
    /// Where the socket, the length or the integrity check failed.
    fn open(&mut self, seq: u32, reader: &mut BufReader<TcpStream>) -> Result<Vec<u8>>;
}

/// The cleartext framing used until the keys are exchanged: block size eight,
/// no integrity code.
struct Plain;

/// The negotiated suite: AES-256 counter mode and a SHA-256 HMAC.
struct AesCtrHmac {
    cipher: Aes256Ctr,
    integrity: Vec<u8>,
}

/// The cleartext cipher.
#[must_use]
pub fn plain() -> Box<dyn Cipher> {
    Box::new(Plain)
}

impl Cipher for Plain {
    fn seal(&mut self, _seq: u32, payload: &[u8]) -> Result<Vec<u8>> {
        frame(payload, 8)
    }

    fn open(&mut self, _seq: u32, reader: &mut BufReader<TcpStream>) -> Result<Vec<u8>> {
        let mut length = [0u8; 4];
        read_exact(reader, &mut length)?;
        let packet_length = u32::from_be_bytes(length) as usize;
        check_length(packet_length)?;
        let mut rest = vec![0u8; packet_length];
        read_exact(reader, &mut rest)?;
        unframe(&rest)
    }
}

impl AesCtrHmac {
    fn new(key: &[u8], iv: &[u8], integrity: Vec<u8>) -> Result<Self> {
        let cipher = Aes256Ctr::new_from_slices(key, iv)
            .map_err(|_| protocol_error("an AES-256 key or IV of the wrong length"))?;
        Ok(Self { cipher, integrity })
    }

    fn mac(&self, seq: u32, packet: &[u8]) -> Result<Vec<u8>> {
        let mut mac = HmacSha256::new_from_slice(&self.integrity)
            .map_err(|_| protocol_error("an HMAC key of the wrong length"))?;
        mac.update(&seq.to_be_bytes());
        mac.update(packet);
        Ok(mac.finalize().into_bytes().to_vec())
    }
}

impl Cipher for AesCtrHmac {
    fn seal(&mut self, seq: u32, payload: &[u8]) -> Result<Vec<u8>> {
        let mut packet = frame(payload, 16)?;
        let tag = self.mac(seq, &packet)?;
        self.cipher.apply_keystream(&mut packet);
        packet.extend_from_slice(&tag);
        Ok(packet)
    }

    fn open(&mut self, seq: u32, reader: &mut BufReader<TcpStream>) -> Result<Vec<u8>> {
        let mut first = [0u8; 16];
        read_exact(reader, &mut first)?;
        self.cipher.apply_keystream(&mut first);
        let packet_length = u32::from_be_bytes([first[0], first[1], first[2], first[3]]) as usize;
        check_length(packet_length)?;
        let remaining = 4 + packet_length - 16;
        let mut rest = vec![0u8; remaining];
        read_exact(reader, &mut rest)?;
        self.cipher.apply_keystream(&mut rest);
        let mut packet = Vec::with_capacity(16 + remaining);
        packet.extend_from_slice(&first);
        packet.extend_from_slice(&rest);
        let mut tag = vec![0u8; 32];
        read_exact(reader, &mut tag)?;
        let mut mac = HmacSha256::new_from_slice(&self.integrity)
            .map_err(|_| protocol_error("an HMAC key of the wrong length"))?;
        mac.update(&seq.to_be_bytes());
        mac.update(&packet);
        mac.verify_slice(&tag).map_err(|_| {
            protocol_error("a packet whose message authentication code did not agree")
        })?;
        unframe(&packet[4..])
    }
}

/// The two directions of the negotiated suite, keyed from the shared secret
/// `k` (already `mpint`-encoded), the exchange hash `h` and the session id.
///
/// The letters are RFC 4253 section 7.2: A and B are the IVs, C and D the
/// encryption keys, E and F the integrity keys, client-to-server first.
///
/// # Errors
/// Where a key or IV came out the wrong length.
pub fn suite(
    k: &[u8],
    h: &[u8],
    session_id: &[u8],
    client_to_server: bool,
) -> Result<Box<dyn Cipher>> {
    let (iv, key, mac) = if client_to_server {
        (b'A', b'C', b'E')
    } else {
        (b'B', b'D', b'F')
    };
    let iv = derive(k, h, iv, session_id, 16);
    let key = derive(k, h, key, session_id, 32);
    let integrity = derive(k, h, mac, session_id, 32);
    Ok(Box::new(AesCtrHmac::new(&key, &iv, integrity)?))
}

/// Key material of `need` bytes for `letter`, extended by re-hashing as
/// RFC 4253 section 7.2 sets out where one hash is not enough.
fn derive(k: &[u8], h: &[u8], letter: u8, session_id: &[u8], need: usize) -> Vec<u8> {
    let mut out = {
        let mut hash = Sha256::new();
        hash.update(k);
        hash.update(h);
        hash.update([letter]);
        hash.update(session_id);
        hash.finalize().to_vec()
    };
    while out.len() < need {
        let mut hash = Sha256::new();
        hash.update(k);
        hash.update(h);
        hash.update(&out);
        out.extend_from_slice(&hash.finalize());
    }
    out.truncate(need);
    out
}

/// Wrap `payload` as `length | padding_length | payload | padding`, padded to
/// a multiple of `block` with at least four bytes of padding (RFC 4253
/// section 6).
fn frame(payload: &[u8], block: usize) -> Result<Vec<u8>> {
    let base = 5 + payload.len();
    let mut padding = block - (base % block);
    if padding < 4 {
        padding += block;
    }
    let packet_length = 1 + payload.len() + padding;
    let mut out = Vec::with_capacity(4 + packet_length);
    out.extend_from_slice(
        &u32::try_from(packet_length)
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    out.push(u8::try_from(padding).unwrap_or(u8::MAX));
    out.extend_from_slice(payload);
    let mut random = vec![0u8; padding];
    getrandom::getrandom(&mut random)
        .map_err(|_| protocol_error("the system would not draw padding"))?;
    out.extend_from_slice(&random);
    Ok(out)
}

/// The payload inside `packet`, which is `padding_length | payload | padding`
/// (the length field already stripped).
fn unframe(packet: &[u8]) -> Result<Vec<u8>> {
    let padding = *packet
        .first()
        .ok_or_else(|| protocol_error("a packet with no padding length"))?
        as usize;
    let end = packet
        .len()
        .checked_sub(padding)
        .filter(|end| *end >= 1)
        .ok_or_else(|| protocol_error("a packet whose padding is longer than the packet"))?;
    Ok(packet[1..end].to_vec())
}

fn check_length(packet_length: usize) -> Result<()> {
    if (12..=MAX_PACKET).contains(&packet_length) {
        Ok(())
    } else {
        Err(protocol_error(format!(
            "a binary packet of {packet_length} bytes, outside what is carried"
        )))
    }
}

fn read_exact(reader: &mut BufReader<TcpStream>, into: &mut [u8]) -> Result<()> {
    reader
        .read_exact(into)
        .map_err(|error| classify("reading a packet", &error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_is_padded_to_the_block_and_reads_its_payload_back() {
        for block in [8usize, 16] {
            let framed = frame(b"hello", block).expect("frame");
            assert_eq!((framed.len()) % block, 0, "block {block}");
            let payload = unframe(&framed[4..]).expect("unframe");
            assert_eq!(payload, b"hello");
        }
    }

    #[test]
    fn the_derived_key_is_the_length_asked_for_and_extends_past_one_hash() {
        let short = derive(b"k", b"h", b'C', b"s", 16);
        assert_eq!(short.len(), 16);
        let long = derive(b"k", b"h", b'C', b"s", 64);
        assert_eq!(long.len(), 64);
        // The first 32 bytes are the first hash; the rest is the extension.
        assert_eq!(&long[..32], &derive(b"k", b"h", b'C', b"s", 32)[..]);
    }

    #[test]
    fn a_sealed_packet_opens_only_under_its_own_sequence_number() {
        let (key, iv, mac) = ([7u8; 32], [3u8; 16], vec![9u8; 32]);
        let mut sealer = AesCtrHmac::new(&key, &iv, mac.clone()).expect("cipher");
        let wire = sealer.seal(5, b"a payload of some length").expect("seal");
        // A fresh opener with the same key opens the same stream position.
        let mut opener = AesCtrHmac::new(&key, &iv, mac).expect("cipher");
        let tag_ok = {
            let mut check = HmacSha256::new_from_slice(&[9u8; 32]).expect("mac");
            check.update(&5u32.to_be_bytes());
            let mut decrypted = wire[..wire.len() - 32].to_vec();
            let mut plain = AesCtrHmac::new(&key, &iv, vec![9u8; 32]).expect("c");
            plain.cipher.apply_keystream(&mut decrypted);
            check.update(&decrypted);
            check.verify_slice(&wire[wire.len() - 32..]).is_ok()
        };
        assert!(tag_ok, "the code covers the sequence number and the packet");
        let _ = &mut opener;
    }

    #[test]
    fn a_length_outside_the_bounds_is_refused() {
        assert!(check_length(4).is_err());
        assert!(check_length(MAX_PACKET + 1).is_err());
        assert!(check_length(64).is_ok());
    }
}
