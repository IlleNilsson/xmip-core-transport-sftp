//! The binary packet protocol: the framing that wraps a payload for the
//! transport (RFC 4253 section 6). A message is laid out in a `Vec<u8>`
//! with codec's `ByteWriter` and `xmip-core-library-ssh`'s `SshWrite`, and
//! taken apart with codec's `Cursor` and `SshRead`; a [`Conn`] carries it
//! over a connection, in the clear before the keys are exchanged and under
//! a [`Cipher`] after.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;

use transport::error::{Result, classify, protocol_error};

use crate::cipher::Cipher;

/// The largest binary packet accepted, so a bad length cannot ask for a
/// gigabyte. Channel data is chunked well under this.
pub const MAX_PACKET: usize = 262_144;

/// A connection carrying binary packets, its two directions counted so the
/// message authentication code covers the sequence number (RFC 4253
/// section 6.4).
pub struct Conn {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    tx: Box<dyn Cipher>,
    rx: Box<dyn Cipher>,
    tx_seq: u32,
    rx_seq: u32,
}

impl Conn {
    /// A connection over `stream`, in the clear until [`Conn::rekey`].
    ///
    /// # Errors
    /// Where the stream could not be split.
    pub fn new(stream: TcpStream) -> Result<Self> {
        let writer = stream
            .try_clone()
            .map_err(|error| classify("cloning the connection", &error))?;
        Ok(Self {
            reader: BufReader::new(stream),
            writer,
            tx: crate::cipher::plain(),
            rx: crate::cipher::plain(),
            tx_seq: 0,
            rx_seq: 0,
        })
    }

    /// Send our identification string and read the peer's, skipping any
    /// lines it sends before one that opens with `SSH-` (RFC 4253
    /// section 4.2). The returned line has no trailing carriage return or
    /// line feed, which is what the exchange hash covers.
    ///
    /// # Errors
    /// Where the socket failed or the peer sent no identification.
    pub fn banner(&mut self, ours: &str) -> Result<String> {
        self.writer
            .write_all(format!("{ours}\r\n").as_bytes())
            .map_err(|error| classify("writing our identification", &error))?;
        self.writer
            .flush()
            .map_err(|error| classify("flushing our identification", &error))?;
        for _ in 0..64 {
            let mut line = Vec::new();
            let read = self
                .reader
                .read_until(b'\n', &mut line)
                .map_err(|error| classify("reading the peer's identification", &error))?;
            if read == 0 {
                break;
            }
            while matches!(line.last(), Some(b'\n' | b'\r')) {
                line.pop();
            }
            if line.starts_with(b"SSH-") {
                return String::from_utf8(line)
                    .map_err(|_| protocol_error("an identification string that is not UTF-8"));
            }
        }
        Err(protocol_error("a peer that sent no SSH identification"))
    }

    /// Send one message, sealed by the outgoing cipher.
    ///
    /// # Errors
    /// Where the cipher or the socket failed.
    pub fn send(&mut self, payload: &[u8]) -> Result<()> {
        let wire = self.tx.seal(self.tx_seq, payload)?;
        self.tx_seq = self.tx_seq.wrapping_add(1);
        self.writer
            .write_all(&wire)
            .map_err(|error| classify("writing a packet", &error))?;
        self.writer
            .flush()
            .map_err(|error| classify("flushing a packet", &error))
    }

    /// Take one message, opened by the incoming cipher.
    ///
    /// # Errors
    /// Where the socket, the cipher or the message authentication failed.
    pub fn recv(&mut self) -> Result<Vec<u8>> {
        let payload = self.rx.open(self.rx_seq, &mut self.reader)?;
        self.rx_seq = self.rx_seq.wrapping_add(1);
        Ok(payload)
    }

    /// Take one message and insist on its message number.
    ///
    /// # Errors
    /// Where the message is another than `expected`.
    pub fn expect(&mut self, expected: u8, what: &str) -> Result<Vec<u8>> {
        let payload = self.recv()?;
        match payload.first() {
            Some(&number) if number == expected => Ok(payload),
            Some(&number) => Err(protocol_error(format!(
                "expected {what} ({expected}), and the peer sent message {number}"
            ))),
            None => Err(protocol_error(format!(
                "an empty message where {what} was due"
            ))),
        }
    }

    /// Switch both directions to the exchanged keys.
    pub fn rekey(&mut self, tx: Box<dyn Cipher>, rx: Box<dyn Cipher>) {
        self.tx = tx;
        self.rx = rx;
    }
}
