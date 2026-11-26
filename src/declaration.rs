//! What a Location of this technology is configured with: its declaration,
//! which `Configured` reads, built with the crate's `declaration` feature
//! alone and the code behind the default (ADR-0064, amendments 2026-10-22
//! and 2026-11-26), for the library the surfaces load to carry (open
//! problem 48).

use xcore::settings::{Applies, Settings};

/// Every setting a Location takes beyond its address, the user, server and
/// directory, `sftp://user@host:22/dir`, or `host:22` alone: where a
/// Receive Location takes files from and a Send Location puts them, as the
/// user it names, no one where it names none.
pub const SETTINGS: &Settings = &Settings {
    technology: env!("CARGO_PKG_NAME"),
    settings: &[transport::configured::timeout(
        Applies::Both,
        None,
        "How long a peer that stops mid-exchange is waited on; unbounded when \
         left out.",
    )],
};

/// `sftp://`.
pub const SCHEMES: &[&str] = &["sftp"];
