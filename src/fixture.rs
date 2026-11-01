//! The one login the tests' far ends check and their near ends present: a
//! user, and a password minted for the test run; or a user and the key a
//! test drew.

use std::sync::LazyLock;

use ed25519_dalek::SigningKey;
use net::login::{self, Check};

use crate::{Credential, SftpTransport};

/// The user the tests log in as.
pub const USER: &str = "party";

/// The password, drawn once a run.
pub static SECRET: LazyLock<String> =
    LazyLock::new(|| codec::hex::encode(&codec::random::array::<32>()));

/// What a test's far end is handed: the one login.
pub fn check() -> Check {
    login::only(USER, SECRET.as_str())
}

/// What a test's far end is handed where its near end logs in as `user`
/// with `key`: that key enrolled for that user alone.
pub fn keyed(user: &str, key: &SigningKey) -> Check {
    Credential::PublicKey(Box::new(key.clone())).admitted_as(user)
}

/// A near end for `address` presenting the one login.
pub fn near(address: impl Into<String>) -> SftpTransport {
    SftpTransport::new(address)
        .as_user(USER)
        .with_password(SECRET.as_str())
}
