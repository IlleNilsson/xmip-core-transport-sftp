//! User authentication over the exchanged keys (RFC 4252): the client asks
//! for the `ssh-connection` service by a password or by a public key, and the
//! server admits it and remembers who it was.
//!
//! A public-key authentication signs the session identifier and the request,
//! so what the server keeps — the key's fingerprint, the signature and the
//! session identifier — is exactly what `xmip-core-identify-ssh-key` reads
//! back off the arrival to present the peer. A password authentication keeps
//! only the name, which is what `xmip-core-identify-username` reads.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use transport::error::{Result, protocol_error};

use crate::kex::{HOST_KEY, host_key_blob};
use crate::packet::{Conn, Reader, Writer};

/// The message that offers a credential.
pub const USERAUTH_REQUEST: u8 = 50;
/// The message that turns one down.
pub const USERAUTH_FAILURE: u8 = 51;
/// The message that admits one.
pub const USERAUTH_SUCCESS: u8 = 52;

const CONNECTION: &str = "ssh-connection";
const USERAUTH: &str = "ssh-userauth";

/// Who authenticated, and by what, for the arrival to carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authenticated {
    /// The user name presented.
    pub user: String,
    /// The public key's fingerprint, `SHA256:<base64>`, where a key was
    /// presented rather than a password.
    pub fingerprint: Option<String>,
    /// The signature the key made, where one was presented.
    pub signature: Option<Vec<u8>>,
}

/// Ask the server for the `ssh-userauth` service.
///
/// # Errors
/// Where the service was refused or a message was out of order.
pub fn request_service(conn: &mut Conn) -> Result<()> {
    let mut request = Writer::new();
    request
        .byte(crate::kex::SERVICE_REQUEST)
        .string(USERAUTH.as_bytes());
    conn.send(&request.finish())?;
    let accept = conn.expect(crate::kex::SERVICE_ACCEPT, "the userauth service")?;
    if Reader::new(&accept[1..]).string()? == USERAUTH.as_bytes() {
        Ok(())
    } else {
        Err(protocol_error("the server accepted another service"))
    }
}

/// Authenticate as `user` with `password`.
///
/// # Errors
/// Where the server turned the password down.
pub fn password(conn: &mut Conn, user: &str, secret: &str) -> Result<()> {
    let mut request = Writer::new();
    request
        .byte(USERAUTH_REQUEST)
        .string(user.as_bytes())
        .string(CONNECTION.as_bytes())
        .string(b"password")
        .bool(false)
        .string(secret.as_bytes());
    conn.send(&request.finish())?;
    admitted(conn)
}

/// Authenticate as `user` with `key`, signing over `session_id`.
///
/// # Errors
/// Where the server turned the key down.
pub fn public_key(conn: &mut Conn, user: &str, key: &SigningKey, session_id: &[u8]) -> Result<()> {
    let blob = host_key_blob(&key.verifying_key());
    let signed = signed_data(session_id, user, &blob);
    let signature = signature_blob(&key.sign(&signed));
    let mut request = Writer::new();
    request
        .byte(USERAUTH_REQUEST)
        .string(user.as_bytes())
        .string(CONNECTION.as_bytes())
        .string(b"publickey")
        .bool(true)
        .string(HOST_KEY.as_bytes())
        .string(&blob)
        .string(&signature);
    conn.send(&request.finish())?;
    admitted(conn)
}

fn admitted(conn: &mut Conn) -> Result<()> {
    let reply = conn.recv()?;
    match reply.first() {
        Some(&USERAUTH_SUCCESS) => Ok(()),
        Some(&USERAUTH_FAILURE) => Err(protocol_error("the server turned the credential down")),
        _ => Err(protocol_error(
            "a message where the authentication answer was due",
        )),
    }
}

/// Serve one authentication over `conn`, `session_id` already settled, and
/// report who it was. The first well-formed credential is admitted: the far
/// end is a loopback, not a gatekeeper.
///
/// # Errors
/// Where a message was out of order or a signature did not verify.
pub fn serve(conn: &mut Conn, session_id: &[u8]) -> Result<Authenticated> {
    let request = conn.expect(crate::kex::SERVICE_REQUEST, "a service request")?;
    if Reader::new(&request[1..]).string()? != USERAUTH.as_bytes() {
        return Err(protocol_error(
            "a service request that was not for userauth",
        ));
    }
    let mut accept = Writer::new();
    accept
        .byte(crate::kex::SERVICE_ACCEPT)
        .string(USERAUTH.as_bytes());
    conn.send(&accept.finish())?;

    loop {
        let message = conn.expect(USERAUTH_REQUEST, "an authentication request")?;
        if let Some(who) = admit(&message, session_id)? {
            conn.send(&[USERAUTH_SUCCESS])?;
            return Ok(who);
        }
        let mut failure = Writer::new();
        failure
            .byte(USERAUTH_FAILURE)
            .string(b"publickey,password")
            .bool(false);
        conn.send(&failure.finish())?;
    }
}

/// Whether a request is a credential this far end admits, and who it names;
/// `None` where the method is one it lets the client try again after.
fn admit(message: &[u8], session_id: &[u8]) -> Result<Option<Authenticated>> {
    let mut reader = Reader::new(&message[1..]);
    let user = utf8(reader.string()?, "a user name")?;
    let _service = reader.string()?;
    let method = reader.string()?;
    match method {
        b"password" => {
            let _has = reader.bool()?;
            let _secret = reader.string()?;
            Ok(Some(Authenticated {
                user,
                fingerprint: None,
                signature: None,
            }))
        }
        b"publickey" => {
            let signed = reader.bool()?;
            if !signed {
                return Ok(None);
            }
            let _algorithm = reader.string()?;
            let blob = reader.string()?;
            let signature = reader.string()?;
            verify_public_key(session_id, &user, blob, signature)?;
            Ok(Some(Authenticated {
                user,
                fingerprint: Some(fingerprint(blob)),
                signature: Some(signature.to_vec()),
            }))
        }
        _ => Ok(None),
    }
}

/// Verify a public-key request's signature over the session and the request.
fn verify_public_key(session_id: &[u8], user: &str, blob: &[u8], sig_blob: &[u8]) -> Result<()> {
    let mut key = Reader::new(blob);
    if key.string()? != HOST_KEY.as_bytes() {
        return Err(protocol_error("a public key that is not ssh-ed25519"));
    }
    let public = <[u8; 32]>::try_from(key.string()?)
        .map_err(|_| protocol_error("a public key that is not 32 bytes"))?;
    let verifying = VerifyingKey::from_bytes(&public)
        .map_err(|_| protocol_error("a public key that is not a valid Ed25519 point"))?;
    let mut sig = Reader::new(sig_blob);
    if sig.string()? != HOST_KEY.as_bytes() {
        return Err(protocol_error("a signature that is not ssh-ed25519"));
    }
    let bytes = <[u8; 64]>::try_from(sig.string()?)
        .map_err(|_| protocol_error("a signature that is not 64 bytes"))?;
    verifying
        .verify(
            &signed_data(session_id, user, blob),
            &Signature::from_bytes(&bytes),
        )
        .map_err(|_| protocol_error("a public-key signature that did not verify"))
}

/// The bytes a public-key authentication signs (RFC 4252 section 7): the
/// session identifier, then the request up to and including the key blob.
fn signed_data(session_id: &[u8], user: &str, blob: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer
        .string(session_id)
        .byte(USERAUTH_REQUEST)
        .string(user.as_bytes())
        .string(CONNECTION.as_bytes())
        .string(b"publickey")
        .bool(true)
        .string(HOST_KEY.as_bytes())
        .string(blob);
    writer.finish()
}

/// The `ssh-ed25519` signature blob: the algorithm name and the signature.
fn signature_blob(signature: &Signature) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.string(HOST_KEY.as_bytes());
    writer.string(&signature.to_bytes());
    writer.finish()
}

/// The OpenSSH fingerprint of a key blob: `SHA256:` and the base64 of the
/// SHA-256 digest, no padding.
#[must_use]
pub fn fingerprint(blob: &[u8]) -> String {
    format!("SHA256:{}", base64(&Sha256::digest(blob)))
}

/// Standard base64 without padding, which is what the ssh vocabulary carries.
#[must_use]
pub fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut block = [0u8; 3];
        block[..chunk.len()].copy_from_slice(chunk);
        let value = (u32::from(block[0]) << 16) | (u32::from(block[1]) << 8) | u32::from(block[2]);
        let indices = [
            (value >> 18) & 0x3f,
            (value >> 12) & 0x3f,
            (value >> 6) & 0x3f,
            value & 0x3f,
        ];
        for (kept, index) in indices.iter().enumerate() {
            if kept <= chunk.len() {
                out.push(ALPHABET[*index as usize] as char);
            }
        }
    }
    out
}

fn utf8(bytes: &[u8], what: &str) -> Result<String> {
    String::from_utf8(bytes.to_vec())
        .map_err(|_| protocol_error(format!("{what} that is not UTF-8")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_public_key_request_verifies_against_its_own_key() {
        let key = crate::kex::fresh_ed25519().expect("key");
        let blob = host_key_blob(&key.verifying_key());
        let session = [0x5au8; 32];
        let signed = signed_data(&session, "xmip", &blob);
        let signature = signature_blob(&key.sign(&signed));
        assert!(verify_public_key(&session, "xmip", &blob, &signature).is_ok());
        // Another session identifier is another signature.
        assert!(verify_public_key(&[0u8; 32], "xmip", &blob, &signature).is_err());
        // Another user is another signature.
        assert!(verify_public_key(&session, "someone", &blob, &signature).is_err());
    }

    #[test]
    fn a_fingerprint_is_sha256_and_forty_three_base64_characters() {
        let key = crate::kex::fresh_ed25519().expect("key");
        let print = fingerprint(&host_key_blob(&key.verifying_key()));
        assert!(print.starts_with("SHA256:"), "{print}");
        assert_eq!(print.len() - "SHA256:".len(), 43, "{print}");
    }

    #[test]
    fn base64_matches_a_known_vector_without_padding() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg");
        assert_eq!(base64(b"fo"), "Zm8");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn a_password_request_names_the_user_and_keeps_no_key() {
        let mut request = Writer::new();
        request
            .byte(USERAUTH_REQUEST)
            .string(b"partner")
            .string(CONNECTION.as_bytes())
            .string(b"password")
            .bool(false)
            .string(b"secret");
        let who = admit(&request.finish(), &[0u8; 32])
            .expect("read")
            .expect("admitted");
        assert_eq!(who.user, "partner");
        assert!(who.fingerprint.is_none());
    }
}
