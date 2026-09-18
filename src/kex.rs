//! The key exchange: the identification strings, the algorithm offer, the
//! Curve25519 Diffie-Hellman and the Ed25519 host key that together settle a
//! shared secret and a session identifier (RFC 4253 section 7, RFC 5656,
//! RFC 8731, RFC 8709).
//!
//! One algorithm is offered on each axis — `curve25519-sha256`,
//! `ssh-ed25519`, `aes256-ctr`, `hmac-sha2-256`, `none` — so there is
//! nothing to negotiate but everything to agree on: the exchange hash covers
//! the identification strings and both `SSH_MSG_KEXINIT` payloads verbatim,
//! so the two ends must hash exactly what crossed the wire.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use transport::error::{Result, protocol_error};

use crate::packet::{Conn, Reader, Writer};

/// The message that opens the key exchange.
pub const KEXINIT: u8 = 20;
/// The message that switches to the exchanged keys.
pub const NEWKEYS: u8 = 21;
/// The client's ephemeral public key.
pub const KEX_ECDH_INIT: u8 = 30;
/// The server's host key, ephemeral public key and signature.
pub const KEX_ECDH_REPLY: u8 = 31;
/// The message that asks to start a service after the keys are exchanged.
pub const SERVICE_REQUEST: u8 = 5;
/// The message that grants it.
pub const SERVICE_ACCEPT: u8 = 6;

/// Our identification string, without the trailing carriage return and line
/// feed the exchange adds.
pub const IDENTIFICATION: &str = "SSH-2.0-xmip_1.0";

/// The host key algorithm name.
pub const HOST_KEY: &str = "ssh-ed25519";

/// What a completed key exchange leaves behind: the session identifier, which
/// is the first exchange hash, and the two directions' ciphers already set on
/// the connection.
pub struct Exchanged {
    /// The session identifier: the exchange hash of the first key exchange,
    /// what a public-key signature is made over.
    pub session_id: Vec<u8>,
}

/// The `SSH_MSG_KEXINIT` payload: a cookie and the one-name lists this
/// transport offers.
fn kexinit() -> Result<Vec<u8>> {
    let mut cookie = [0u8; 16];
    getrandom::getrandom(&mut cookie)
        .map_err(|_| protocol_error("the system would not draw a key-exchange cookie"))?;
    let mut writer = Writer::new();
    writer.byte(KEXINIT);
    for byte in cookie {
        writer.byte(byte);
    }
    for names in [
        "curve25519-sha256",
        HOST_KEY,
        "aes256-ctr",
        "aes256-ctr",
        "hmac-sha2-256",
        "hmac-sha2-256",
        "none",
        "none",
        "",
        "",
    ] {
        writer.string(names.as_bytes());
    }
    writer.bool(false);
    writer.u32(0);
    Ok(writer.finish())
}

/// A fresh ephemeral Curve25519 key pair: the secret and its public 32 bytes.
fn ephemeral() -> Result<(StaticSecret, [u8; 32])> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|_| protocol_error("the system would not draw a Curve25519 secret"))?;
    let secret = StaticSecret::from(seed);
    let public = PublicKey::from(&secret);
    Ok((secret, public.to_bytes()))
}

/// The exchange hash of RFC 5656 section 4: the two identifications, the two
/// key-exchange payloads, the host key, the two ephemeral public keys, and
/// the shared secret as an `mpint`.
fn exchange_hash(parts: &HashParts<'_>) -> Vec<u8> {
    let mut writer = Writer::new();
    writer
        .string(parts.v_c.as_bytes())
        .string(parts.v_s.as_bytes())
        .string(parts.i_c)
        .string(parts.i_s)
        .string(parts.k_s)
        .string(parts.q_c)
        .string(parts.q_s);
    let mut data = writer.finish();
    data.extend_from_slice(parts.k_mpint);
    Sha256::digest(&data).to_vec()
}

/// The pieces the exchange hash is built from.
struct HashParts<'a> {
    v_c: &'a str,
    v_s: &'a str,
    i_c: &'a [u8],
    i_s: &'a [u8],
    k_s: &'a [u8],
    q_c: &'a [u8],
    q_s: &'a [u8],
    k_mpint: &'a [u8],
}

/// The `mpint` encoding of a 32-byte shared secret, used both in the exchange
/// hash and in the key derivation.
fn shared_mpint(shared: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.mpint(shared);
    writer.finish()
}

/// The `ssh-ed25519` host key blob: the algorithm name and the 32-byte public
/// key, each a string.
#[must_use]
pub fn host_key_blob(verifying: &VerifyingKey) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.string(HOST_KEY.as_bytes());
    writer.string(verifying.as_bytes());
    writer.finish()
}

/// Drive the client's half of the key exchange over `conn`.
///
/// # Errors
/// Where a message was out of order, the host signature did not verify, or
/// the keys could not be derived.
pub fn client(conn: &mut Conn, v_c: &str, v_s: &str) -> Result<Exchanged> {
    let i_c = kexinit()?;
    conn.send(&i_c)?;
    let i_s = conn.expect(KEXINIT, "the server's key-exchange offer")?;

    let (secret, q_c) = ephemeral()?;
    let mut init = Writer::new();
    init.byte(KEX_ECDH_INIT).string(&q_c);
    conn.send(&init.finish())?;

    let reply = conn.expect(KEX_ECDH_REPLY, "the server's key-exchange reply")?;
    let mut reader = Reader::new(&reply[1..]);
    let k_s = reader.string()?.to_vec();
    let q_s = reader.string()?.to_vec();
    let signature = reader.string()?.to_vec();

    let peer = <[u8; 32]>::try_from(q_s.as_slice())
        .map_err(|_| protocol_error("a server ephemeral key that is not 32 bytes"))?;
    let shared = secret.diffie_hellman(&PublicKey::from(peer));
    let k_mpint = shared_mpint(shared.as_bytes());
    let hash = exchange_hash(&HashParts {
        v_c,
        v_s,
        i_c: &i_c,
        i_s: &i_s,
        k_s: &k_s,
        q_c: &q_c,
        q_s: &q_s,
        k_mpint: &k_mpint,
    });
    verify_host(&k_s, &signature, &hash)?;

    conn.send(&[NEWKEYS])?;
    conn.expect(NEWKEYS, "the server's new keys")?;
    conn.rekey(
        crate::cipher::suite(&k_mpint, &hash, &hash, false)?,
        crate::cipher::suite(&k_mpint, &hash, &hash, true)?,
    );
    Ok(Exchanged { session_id: hash })
}

/// Drive the server's half of the key exchange over `conn`, signing with
/// `host`.
///
/// # Errors
/// Where a message was out of order or the keys could not be derived.
pub fn server(conn: &mut Conn, host: &SigningKey, v_c: &str, v_s: &str) -> Result<Exchanged> {
    let i_s = kexinit()?;
    conn.send(&i_s)?;
    let i_c = conn.expect(KEXINIT, "the client's key-exchange offer")?;

    let init = conn.expect(KEX_ECDH_INIT, "the client's ephemeral key")?;
    let q_c = Reader::new(&init[1..]).string()?.to_vec();

    let (secret, q_s) = ephemeral()?;
    let peer = <[u8; 32]>::try_from(q_c.as_slice())
        .map_err(|_| protocol_error("a client ephemeral key that is not 32 bytes"))?;
    let shared = secret.diffie_hellman(&PublicKey::from(peer));
    let k_mpint = shared_mpint(shared.as_bytes());
    let k_s = host_key_blob(&host.verifying_key());
    let hash = exchange_hash(&HashParts {
        v_c,
        v_s,
        i_c: &i_c,
        i_s: &i_s,
        k_s: &k_s,
        q_c: &q_c,
        q_s: &q_s,
        k_mpint: &k_mpint,
    });
    let signature = signature_blob(&host.sign(&hash));

    let mut reply = Writer::new();
    reply
        .byte(KEX_ECDH_REPLY)
        .string(&k_s)
        .string(&q_s)
        .string(&signature);
    conn.send(&reply.finish())?;

    conn.send(&[NEWKEYS])?;
    conn.expect(NEWKEYS, "the client's new keys")?;
    conn.rekey(
        crate::cipher::suite(&k_mpint, &hash, &hash, true)?,
        crate::cipher::suite(&k_mpint, &hash, &hash, false)?,
    );
    Ok(Exchanged { session_id: hash })
}

/// The `ssh-ed25519` signature blob: the algorithm name and the 64-byte
/// signature.
fn signature_blob(signature: &Signature) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.string(HOST_KEY.as_bytes());
    writer.string(&signature.to_bytes());
    writer.finish()
}

/// Verify a host signature `blob` over `hash` against the host key `blob`.
fn verify_host(k_s: &[u8], sig_blob: &[u8], hash: &[u8]) -> Result<()> {
    let mut key = Reader::new(k_s);
    if key.string()? != HOST_KEY.as_bytes() {
        return Err(protocol_error("a host key that is not ssh-ed25519"));
    }
    let public = <[u8; 32]>::try_from(key.string()?)
        .map_err(|_| protocol_error("a host key that is not 32 bytes"))?;
    let verifying = VerifyingKey::from_bytes(&public)
        .map_err(|_| protocol_error("a host key that is not a valid Ed25519 point"))?;
    let mut sig = Reader::new(sig_blob);
    if sig.string()? != HOST_KEY.as_bytes() {
        return Err(protocol_error("a signature that is not ssh-ed25519"));
    }
    let bytes = <[u8; 64]>::try_from(sig.string()?)
        .map_err(|_| protocol_error("a signature that is not 64 bytes"))?;
    verifying
        .verify(hash, &Signature::from_bytes(&bytes))
        .map_err(|_| protocol_error("a host signature that did not verify"))
}

/// A fresh Ed25519 key from the system's randomness.
///
/// # Errors
/// Where the system would not draw a seed.
pub fn fresh_ed25519() -> Result<SigningKey> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|_| protocol_error("the system would not draw an Ed25519 key"))?;
    Ok(SigningKey::from_bytes(&seed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_offer_lists_one_name_on_every_axis() {
        let payload = kexinit().expect("kexinit");
        assert_eq!(payload[0], KEXINIT);
        // byte, 16-byte cookie, then the first name-list is the kex algorithm.
        let mut reader = Reader::new(&payload[17..]);
        assert_eq!(reader.string().expect("kex"), b"curve25519-sha256");
        assert_eq!(reader.string().expect("host key"), HOST_KEY.as_bytes());
        assert_eq!(reader.string().expect("cipher"), b"aes256-ctr");
    }

    #[test]
    fn a_host_signature_verifies_and_a_tampered_one_does_not() {
        let host = fresh_ed25519().expect("host");
        let hash = [0x11u8; 32];
        let blob = signature_blob(&host.sign(&hash));
        let k_s = host_key_blob(&host.verifying_key());
        assert!(verify_host(&k_s, &blob, &hash).is_ok());
        let other = [0x22u8; 32];
        assert!(verify_host(&k_s, &blob, &other).is_err());
    }

    #[test]
    fn the_shared_secret_encodes_the_same_mpint_on_both_sides() {
        let (client_secret, client_public) = ephemeral().expect("client");
        let (server_secret, server_public) = ephemeral().expect("server");
        let at_client = client_secret.diffie_hellman(&PublicKey::from(server_public));
        let at_server = server_secret.diffie_hellman(&PublicKey::from(client_public));
        assert_eq!(at_client.as_bytes(), at_server.as_bytes());
        assert_eq!(
            shared_mpint(at_client.as_bytes()),
            shared_mpint(at_server.as_bytes())
        );
    }

    #[test]
    fn the_exchange_hash_changes_when_any_part_changes() {
        let base = HashParts {
            v_c: "SSH-2.0-a",
            v_s: "SSH-2.0-b",
            i_c: b"ic",
            i_s: b"is",
            k_s: b"ks",
            q_c: b"qc",
            q_s: b"qs",
            k_mpint: b"\x00\x00\x00\x01\x02",
        };
        let one = exchange_hash(&base);
        let changed = HashParts {
            q_s: b"other",
            ..base
        };
        assert_ne!(one, exchange_hash(&changed));
        assert_eq!(one.len(), 32);
    }
}
