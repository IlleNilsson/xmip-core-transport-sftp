//! One session channel and the `sftp` subsystem over it (RFC 4254): the
//! client opens a session, asks for the subsystem, and from then on the
//! channel is a byte stream in each direction. The SFTP layer above frames
//! its own packets over that stream, so a single SFTP packet may cross more
//! than one `SSH_MSG_CHANNEL_DATA` and the reader reassembles it.

use std::collections::VecDeque;

use codec::cursor::Cursor;
use codec::writer::ByteWriter;
use transport::error::{Result, protocol_error};

use crate::packet::{Conn, Ssh, SshWrite};

/// Open a channel.
pub const CHANNEL_OPEN: u8 = 90;
/// Confirm one.
pub const CHANNEL_OPEN_CONFIRMATION: u8 = 91;
/// Grant the peer more window.
pub const CHANNEL_WINDOW_ADJUST: u8 = 93;
/// Carry channel bytes.
pub const CHANNEL_DATA: u8 = 94;
/// The peer will send no more.
pub const CHANNEL_EOF: u8 = 96;
/// The peer is done with the channel.
pub const CHANNEL_CLOSE: u8 = 97;
/// Ask something of a channel.
pub const CHANNEL_REQUEST: u8 = 98;
/// The request was granted.
pub const CHANNEL_SUCCESS: u8 = 99;

/// The window each side offers: larger than the ceiling, so a whole file
/// crosses without a window adjustment.
const INITIAL_WINDOW: u32 = 0x0400_0000;
/// The most one channel-data message carries.
const MAX_CHANNEL_PACKET: usize = 32_768;

/// A session channel as a byte stream, with the peer's channel number and the
/// bytes it has sent that the SFTP layer has not yet read.
pub struct Channel<'conn> {
    conn: &'conn mut Conn,
    remote_id: u32,
    incoming: VecDeque<u8>,
    eof: bool,
    closed: bool,
}

impl<'conn> Channel<'conn> {
    /// Open a session channel and start the `sftp` subsystem (the client).
    ///
    /// # Errors
    /// Where the open or the subsystem request was refused.
    pub fn open(conn: &'conn mut Conn) -> Result<Self> {
        let mut open = Vec::new();
        open.byte(CHANNEL_OPEN)
            .string(b"session")
            .u32_be(0)
            .u32_be(INITIAL_WINDOW)
            .u32_be(u32::try_from(MAX_CHANNEL_PACKET).unwrap_or(u32::MAX));
        conn.send(&open)?;

        let confirmation = conn.expect(CHANNEL_OPEN_CONFIRMATION, "the channel confirmation")?;
        let mut reader = Cursor::new(&confirmation[1..]);
        let _local = reader.u32_be()?;
        let remote_id = reader.u32_be()?;

        let mut request = Vec::new();
        request
            .byte(CHANNEL_REQUEST)
            .u32_be(remote_id)
            .string(b"subsystem")
            .bool(true)
            .string(b"sftp");
        conn.send(&request)?;
        conn.expect(CHANNEL_SUCCESS, "the subsystem confirmation")?;

        Ok(Self {
            conn,
            remote_id,
            incoming: VecDeque::new(),
            eof: false,
            closed: false,
        })
    }

    /// Accept a session channel and the `sftp` subsystem request (the far
    /// end).
    ///
    /// # Errors
    /// Where the open was not a session or the request not the subsystem.
    pub fn accept(conn: &'conn mut Conn) -> Result<Self> {
        let open = conn.expect(CHANNEL_OPEN, "a channel open")?;
        let mut reader = Cursor::new(&open[1..]);
        if reader.string()? != b"session" {
            return Err(protocol_error("a channel open that was not for a session"));
        }
        let remote_id = reader.u32_be()?;

        let mut confirmation = Vec::new();
        confirmation
            .byte(CHANNEL_OPEN_CONFIRMATION)
            .u32_be(remote_id)
            .u32_be(0)
            .u32_be(INITIAL_WINDOW)
            .u32_be(u32::try_from(MAX_CHANNEL_PACKET).unwrap_or(u32::MAX));
        conn.send(&confirmation)?;

        let request = conn.expect(CHANNEL_REQUEST, "a channel request")?;
        let mut reader = Cursor::new(&request[1..]);
        let _recipient = reader.u32_be()?;
        if reader.string()? != b"subsystem" {
            return Err(protocol_error("a channel request that was not a subsystem"));
        }
        let _want_reply = reader.bool()?;
        if reader.string()? != b"sftp" {
            return Err(protocol_error("a subsystem other than sftp"));
        }
        conn.send(&{
            let mut ok = Vec::new();
            ok.byte(CHANNEL_SUCCESS).u32_be(remote_id);
            ok
        })?;

        Ok(Self {
            conn,
            remote_id,
            incoming: VecDeque::new(),
            eof: false,
            closed: false,
        })
    }

    /// Write `bytes` to the channel, split to the peer's packet size.
    ///
    /// # Errors
    /// Where the socket failed.
    pub fn write(&mut self, bytes: &[u8]) -> Result<()> {
        for chunk in bytes.chunks(MAX_CHANNEL_PACKET) {
            let mut data = Vec::new();
            data.byte(CHANNEL_DATA).u32_be(self.remote_id).string(chunk);
            self.conn.send(&data)?;
        }
        Ok(())
    }

    /// Read exactly `n` bytes from the channel stream.
    ///
    /// # Errors
    /// Where the channel closed before `n` bytes had arrived.
    pub fn read_exact(&mut self, n: usize) -> Result<Vec<u8>> {
        while self.incoming.len() < n {
            if !self.pump()? {
                return Err(protocol_error(
                    "the channel closed before the reply was complete",
                ));
            }
        }
        Ok(self.incoming.drain(..n).collect())
    }

    /// Read one more message off the connection into the channel state,
    /// returning whether more may yet come.
    fn pump(&mut self) -> Result<bool> {
        let message = self.conn.recv()?;
        match message.first().copied() {
            Some(CHANNEL_DATA) => {
                let mut reader = Cursor::new(&message[1..]);
                let _recipient = reader.u32_be()?;
                self.incoming.extend(reader.string()?.iter().copied());
                Ok(true)
            }
            Some(CHANNEL_WINDOW_ADJUST) => Ok(true),
            Some(CHANNEL_EOF) => {
                self.eof = true;
                Ok(!self.incoming.is_empty())
            }
            Some(CHANNEL_CLOSE) => {
                self.closed = true;
                Ok(!self.incoming.is_empty())
            }
            other => Err(protocol_error(format!(
                "an unexpected message {other:?} on the channel"
            ))),
        }
    }

    /// Whether the peer has said it will send no more.
    #[must_use]
    pub const fn done(&self) -> bool {
        self.eof || self.closed
    }

    /// The next length-prefixed frame off the stream, or `None` where the
    /// channel ended cleanly with nothing more to give — which is how the far
    /// end learns the client is done rather than by an error.
    ///
    /// # Errors
    /// Where the socket failed or a frame was cut short.
    pub fn read_frame(&mut self) -> Result<Option<Vec<u8>>> {
        loop {
            if self.incoming.len() >= 4 {
                break;
            }
            if self.done() && self.incoming.is_empty() {
                return Ok(None);
            }
            if !self.pump()? && self.incoming.len() < 4 {
                return Ok(None);
            }
        }
        let header: Vec<u8> = self.incoming.iter().take(4).copied().collect();
        let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let full = self.read_exact(4 + length)?;
        Ok(Some(full[4..].to_vec()))
    }

    /// Say goodbye: end of data, then close.
    ///
    /// # Errors
    /// Where the socket failed.
    pub fn close(&mut self) -> Result<()> {
        let mut eof = Vec::new();
        eof.byte(CHANNEL_EOF).u32_be(self.remote_id);
        self.conn.send(&eof)?;
        let mut close = Vec::new();
        close.byte(CHANNEL_CLOSE).u32_be(self.remote_id);
        self.conn.send(&close)
    }
}
