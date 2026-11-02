//! The module's timing program (`doc/governance/rust-style.md` section
//! 5c): this transport held to how long Xmip takes — the millisecond rule
//! (`CONTRIBUTING.md`, *Rust is here for one reason*). A plain `cargo test`
//! leaves it out; the landing runs it after every other test of the module,
//! alone, one test at a time
//! (`cargo test --test measured --all-features -- --test-threads=1`), so
//! what is measured is Xmip's work and not its neighbors':
//!
//! - a hundred puts on one connection take five milliseconds each at most;
//! - a hundred harvests on one connection take five milliseconds each at
//!   most.

use std::sync::LazyLock;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use net::login::{self, Check};
use transport::{Transport, socket};
use xmip_core_transport_sftp::{SftpTransport, server, subsystem};

/// The user the far end admits.
const USER: &str = "party";

/// The password, drawn once a run.
static SECRET: LazyLock<String> =
    LazyLock::new(|| codec::hex::encode(&codec::random::array::<32>()));

/// What the far end is handed: the one login.
fn check() -> Check {
    login::only(USER, SECRET.as_str())
}

/// A far end serving `files` on one connection until its client hangs up,
/// and its address.
fn far_end(files: subsystem::Files) -> (String, std::thread::JoinHandle<()>) {
    let (listener, address) = socket::bind_tcp("127.0.0.1:0").expect("bind");
    let serving = std::thread::spawn(move || {
        let host = SigningKey::from_bytes(&[0x5e; 32]);
        let (stream, _) =
            socket::accept_tcp(&listener, Some(Duration::from_secs(5))).expect("accept");
        server::serve_channels(stream, &host, files, (usize::MAX, &check())).expect("served");
    });
    (address, serving)
}

/// A near end for `address` presenting the one login.
fn near(address: impl Into<String>) -> SftpTransport {
    SftpTransport::new(address)
        .as_user(USER)
        .with_password(SECRET.as_str())
        .timing_out_after(Duration::from_secs(5))
}

#[test]
fn a_hundred_puts_take_five_milliseconds_each_at_most() {
    // A hundred: each put is a channel of its own, which is SFTP's.
    const SENDS: usize = 100;
    let (address, serving) = far_end(subsystem::Files::new());
    let near = near(address);
    let began = Instant::now();
    for n in 0..SENDS {
        near.send(&format!("{n}.edi"), n.to_string().as_bytes())
            .expect("put");
    }
    let took = began.elapsed();
    // Generous for a debug build under load: five milliseconds a put.
    assert!(took < Duration::from_millis(5 * SENDS as u64), "{took:?}");
    drop(near);
    serving.join().expect("far end");
}

#[test]
fn a_hundred_harvests_take_five_milliseconds_each_at_most() {
    // A hundred: each harvest is a channel of its own, which is SFTP's.
    const RECEIVES: usize = 100;
    let mut files = subsystem::Files::new();
    files.insert("1.edi".to_string(), b"harvested".to_vec());
    let (address, serving) = far_end(files);
    let near = near(address);
    let began = Instant::now();
    let mut arrived = Vec::new();
    for _ in 0..RECEIVES {
        for one in near.receive().expect("harvested") {
            arrived.push(one.taken().expect("taken"));
        }
    }
    let took = began.elapsed();
    // Generous for a debug build under load: five milliseconds a harvest.
    assert!(
        took < Duration::from_millis(5 * RECEIVES as u64),
        "{took:?}"
    );
    assert_eq!(arrived.len(), 1);
    drop(near);
    serving.join().expect("far end");
}
