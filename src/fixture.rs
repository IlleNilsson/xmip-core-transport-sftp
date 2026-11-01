//! The one login the tests' far ends check and their near ends present: a
//! user, and a password minted for the test run.

use std::sync::LazyLock;

use net::login::{self, Check};

use crate::SftpTransport;

/// The user the tests log in as.
pub const USER: &str = "party";

/// The password, drawn once a run.
pub static SECRET: LazyLock<String> =
    LazyLock::new(|| codec::hex::encode(&codec::random::array::<32>()));

/// What a test's far end is handed: the one login.
pub fn check() -> Check {
    login::only(USER, SECRET.as_str())
}

/// A near end for `address` presenting the one login.
pub fn near(address: impl Into<String>) -> SftpTransport {
    SftpTransport::new(address)
        .as_user(USER)
        .with_password(SECRET.as_str())
}
