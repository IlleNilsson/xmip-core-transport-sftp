//! The binary packet protocol: the SSH wire types every message is built
//! from, and the framing that wraps a payload for the transport (RFC 4253
//! section 6). A [`Writer`] lays a message out and a [`Reader`] takes one
//! apart; a [`Conn`] carries them over a connection, in the clear before the
//! keys are exchanged and under a [`Cipher`] after.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;

use transport::error::{Result, classify, protocol_error};

use crate::cipher::Cipher;

/// The largest binary packet accepted, so a bad length cannot ask for a
/// gigabyte. Channel data is chunked well under this.
pub const MAX_PACKET: usize = 262_144;

/// Lays out an SSH message: a byte, a `uint32`, a length-prefixed string, an
/// `mpint`, a name-list.
#[derive(Default)]
pub struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    /// An empty message.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// One byte, an SSH message number among the rest.
    pub fn byte(&mut self, value: u8) -> &mut Self {
        self.bytes.push(value);
        self
    }

    /// A `boolean`: one byte, zero or one.
    pub fn bool(&mut self, value: bool) -> &mut Self {
        self.bytes.push(u8::from(value));
        self
    }

    /// A `uint32`, big-endian.
    pub fn u32(&mut self, value: u32) -> &mut Self {
        self.bytes.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// A `string`: a `uint32` length and that many bytes.
    pub fn string(&mut self, value: &[u8]) -> &mut Self {
        self.u32(u32::try_from(value.len()).unwrap_or(u32::MAX));
        self.bytes.extend_from_slice(value);
        self
    }

    /// A `uint64`, big-endian.
    pub fn u64(&mut self, value: u64) -> &mut Self {
        self.bytes.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// An `mpint`: a non-negative integer, its leading zero bytes dropped and
    /// a zero byte kept in front where the top bit would read as a sign.
    pub fn mpint(&mut self, magnitude: &[u8]) -> &mut Self {
        let start = magnitude.iter().position(|byte| *byte != 0);
        match start {
            None => {
                self.u32(0);
            }
            Some(start) => {
                let trimmed = &magnitude[start..];
                if trimmed[0] & 0x80 != 0 {
                    self.u32(u32::try_from(trimmed.len() + 1).unwrap_or(u32::MAX));
                    self.bytes.push(0);
                } else {
                    self.u32(u32::try_from(trimmed.len()).unwrap_or(u32::MAX));
                }
                self.bytes.extend_from_slice(trimmed);
            }
        }
        self
    }

    /// The bytes laid out so far.
    #[must_use]
    pub fn finish(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

/// Takes an SSH message apart in the order it was laid out.
pub struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    /// Read `bytes` from the front.
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    /// One byte.
    ///
    /// # Errors
    /// Where nothing is left.
    pub fn byte(&mut self) -> Result<u8> {
        let byte = *self
            .bytes
            .get(self.at)
            .ok_or_else(|| protocol_error("a message that ended before its byte"))?;
        self.at += 1;
        Ok(byte)
    }

    /// A `boolean`.
    ///
    /// # Errors
    /// Where nothing is left.
    pub fn bool(&mut self) -> Result<bool> {
        Ok(self.byte()? != 0)
    }

    /// A `uint32`.
    ///
    /// # Errors
    /// Where fewer than four bytes are left.
    pub fn u32(&mut self) -> Result<u32> {
        let end = self.at + 4;
        let slice = self
            .bytes
            .get(self.at..end)
            .ok_or_else(|| protocol_error("a message that ended inside a uint32"))?;
        self.at = end;
        Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
    }

    /// A `string`, its bytes borrowed.
    ///
    /// # Errors
    /// Where the length runs past the end.
    pub fn string(&mut self) -> Result<&'a [u8]> {
        let length = self.u32()? as usize;
        let end = self.at + length;
        let slice = self
            .bytes
            .get(self.at..end)
            .ok_or_else(|| protocol_error("a string that runs past the end of its message"))?;
        self.at = end;
        Ok(slice)
    }

    /// A `uint64`.
    ///
    /// # Errors
    /// Where fewer than eight bytes are left.
    pub fn u64(&mut self) -> Result<u64> {
        let hi = u64::from(self.u32()?);
        let lo = u64::from(self.u32()?);
        Ok((hi << 32) | lo)
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_message_reads_back_the_types_it_was_written_with() {
        let mut writer = Writer::new();
        writer
            .byte(20)
            .bool(true)
            .u32(0x0102_0304)
            .string(b"ssh-connection")
            .u64(0x1122_3344_5566_7788)
            .mpint(&[0x00, 0x80, 0x01]);
        let bytes = writer.finish();
        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.byte().expect("byte"), 20);
        assert!(reader.bool().expect("bool"));
        assert_eq!(reader.u32().expect("u32"), 0x0102_0304);
        assert_eq!(reader.string().expect("string"), b"ssh-connection");
        assert_eq!(reader.u64().expect("u64"), 0x1122_3344_5566_7788);
        // The mpint kept its sign-guarding zero: 0x80 has the top bit set.
        assert_eq!(reader.string().expect("mpint"), &[0x00, 0x80, 0x01]);
    }

    #[test]
    fn an_mpint_drops_leading_zeros_and_zero_is_empty() {
        let mut writer = Writer::new();
        writer.mpint(&[0x00, 0x00, 0x0a, 0x0b]);
        let bytes = writer.finish();
        assert_eq!(Reader::new(&bytes).string().expect("mpint"), &[0x0a, 0x0b]);
        let mut zero = Writer::new();
        zero.mpint(&[0x00, 0x00]);
        assert_eq!(Reader::new(&zero.finish()).u32().expect("length"), 0);
    }

    #[test]
    fn a_reader_refuses_a_string_that_runs_past_the_end() {
        let bytes = [0x00, 0x00, 0x00, 0x08, 0x01, 0x02];
        let error = Reader::new(&bytes).string().expect_err("short");
        assert!(error.message.contains("runs past the end"), "{error}");
        assert!(Reader::new(&[0x00, 0x00]).u32().is_err());
    }
}
