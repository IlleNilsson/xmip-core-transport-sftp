//! This technology's declaration: the transport guide's "The declaration",
//! `module/core/capability/transport/doc/adding-a-transport.md`.

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
