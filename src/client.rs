//! Xmip as the SSH client: connect, exchange the version and the keys,
//! authenticate, and run the SFTP subsystem over one channel. A Send Location
//! puts a file into a directory; a Receive Location lists the directory,
//! takes each file and removes it.

use std::time::Duration;

use ed25519_dalek::SigningKey;

use transport::error::Result;
use transport::socket;

use crate::channel::Channel;
use crate::kex;
use crate::packet::Conn;
use crate::subsystem::Sftp;
use crate::userauth;

/// How Xmip proves who it is to the far end.
#[derive(Clone)]
pub enum Credential {
    /// A password, presented in the clear over the encrypted channel.
    Password(String),
    /// A key, which signs the session so the far end can hold the peer to it.
    PublicKey(Box<SigningKey>),
}

/// A connected, authenticated SSH client.
pub struct Client {
    conn: Conn,
}

impl Client {
    /// Connect to `address`, exchange keys, and authenticate as `user`.
    ///
    /// # Errors
    /// Where the connection, the key exchange or the authentication failed.
    pub fn connect(
        address: &str,
        user: &str,
        credential: &Credential,
        timeout: Option<Duration>,
    ) -> Result<Self> {
        let stream = socket::connect_tcp(address, timeout)?;
        socket::settle(&stream, timeout)?;
        let mut conn = Conn::new(stream)?;
        let peer = conn.banner(kex::IDENTIFICATION)?;
        let exchanged = kex::client(&mut conn, kex::IDENTIFICATION, &peer)?;
        userauth::request_service(&mut conn)?;
        match credential {
            Credential::Password(secret) => userauth::password(&mut conn, user, secret)?,
            Credential::PublicKey(key) => {
                userauth::public_key(&mut conn, user, key, &exchanged.session_id)?;
            }
        }
        Ok(Self { conn })
    }

    /// Open the subsystem over one channel, run `work`, and close the channel.
    ///
    /// # Errors
    /// Where the channel, the subsystem or `work` failed.
    pub fn with_subsystem<T>(&mut self, work: impl FnOnce(&mut Sftp) -> Result<T>) -> Result<T> {
        let mut channel = Channel::open(&mut self.conn)?;
        let outcome = {
            let mut sftp = Sftp::start(&mut channel)?;
            work(&mut sftp)?
        };
        channel.close()?;
        Ok(outcome)
    }

    /// Put `bytes` into the directory as `name`.
    ///
    /// # Errors
    /// Where the subsystem refused the put.
    pub fn put(&mut self, name: &str, bytes: &[u8]) -> Result<()> {
        self.with_subsystem(|sftp| sftp.put(name, bytes))
    }

    /// Every file in the directory, each taken and removed, as a Receive
    /// Location harvests a drop box.
    ///
    /// # Errors
    /// Where the subsystem refused a listing, a read or a remove.
    pub fn harvest(&mut self) -> Result<Vec<(String, Vec<u8>)>> {
        self.with_subsystem(|sftp| {
            let mut taken = Vec::new();
            for name in sftp.list()? {
                let bytes = sftp.get(&name)?;
                sftp.remove(&name)?;
                taken.push((name, bytes));
            }
            Ok(taken)
        })
    }
}
