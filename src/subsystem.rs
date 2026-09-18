//! The SFTP subsystem, version 3 (draft-ietf-secsh-filexfer-02): the client's
//! requests — INIT, OPEN, WRITE, READ, CLOSE, OPENDIR, READDIR, REMOVE — and
//! the wire vocabulary they share with the far end in [`crate::directory`].
//! The client here is Xmip putting a file into a directory and taking files
//! out of one.

use std::collections::BTreeMap;

use transport::error::{Result, protocol_error};

use crate::channel::Channel;
use crate::packet::{Reader, Writer};

pub(crate) const INIT: u8 = 1;
pub(crate) const VERSION: u8 = 2;
pub(crate) const OPEN: u8 = 3;
pub(crate) const CLOSE: u8 = 4;
pub(crate) const READ: u8 = 5;
pub(crate) const WRITE: u8 = 6;
pub(crate) const OPENDIR: u8 = 11;
pub(crate) const READDIR: u8 = 12;
pub(crate) const REMOVE: u8 = 13;
pub(crate) const STATUS: u8 = 101;
pub(crate) const HANDLE: u8 = 102;
pub(crate) const DATA: u8 = 103;
pub(crate) const NAME: u8 = 104;

const F_READ: u32 = 0x0000_0001;
pub(crate) const F_WRITE: u32 = 0x0000_0002;
const F_CREAT: u32 = 0x0000_0008;
const F_TRUNC: u32 = 0x0000_0010;

pub(crate) const OK: u32 = 0;
pub(crate) const EOF: u32 = 1;
pub(crate) const NO_SUCH_FILE: u32 = 2;
pub(crate) const FAILURE: u32 = 4;

/// The version this transport speaks.
pub const PROTOCOL: u32 = 3;
/// The most one read or write carries in a single request.
const CHUNK: usize = 32_768;

/// A directory of files, name to bytes, as the far end holds it.
pub type Files = BTreeMap<String, Vec<u8>>;

/// The client's side of the subsystem over an open channel.
pub struct Sftp<'a, 'conn> {
    channel: &'a mut Channel<'conn>,
    next_id: u32,
}

impl<'a, 'conn> Sftp<'a, 'conn> {
    /// Exchange the INIT and VERSION that open the subsystem.
    ///
    /// # Errors
    /// Where the server answered another version.
    pub fn start(channel: &'a mut Channel<'conn>) -> Result<Self> {
        let mut sftp = Self {
            channel,
            next_id: 1,
        };
        let mut init = Writer::new();
        init.u32(PROTOCOL);
        sftp.send(INIT, &init.finish())?;
        let (kind, body) = sftp.recv()?;
        if kind != VERSION || Reader::new(&body).u32()? != PROTOCOL {
            return Err(protocol_error(
                "a server that does not speak SFTP version 3",
            ));
        }
        Ok(sftp)
    }

    /// Put `bytes` into the directory as `name`.
    ///
    /// # Errors
    /// Where the open, a write or the close was refused.
    pub fn put(&mut self, name: &str, bytes: &[u8]) -> Result<()> {
        let handle = self.open(name, F_WRITE | F_CREAT | F_TRUNC)?;
        let mut offset = 0u64;
        for chunk in bytes
            .chunks(CHUNK)
            .chain(bytes.is_empty().then_some(&[][..]))
        {
            let mut write = Writer::new();
            write
                .u32(self.id())
                .string(handle.as_bytes())
                .u64(offset)
                .string(chunk);
            self.request(WRITE, &write.finish(), "the write")?;
            offset += chunk.len() as u64;
        }
        self.close(&handle)
    }

    /// Take `name`'s bytes from the directory.
    ///
    /// # Errors
    /// Where the file is not there or a read was refused.
    pub fn get(&mut self, name: &str) -> Result<Vec<u8>> {
        let handle = self.open(name, F_READ)?;
        let mut bytes = Vec::new();
        loop {
            let mut read = Writer::new();
            read.u32(self.id())
                .string(handle.as_bytes())
                .u64(bytes.len() as u64)
                .u32(u32::try_from(CHUNK).unwrap_or(u32::MAX));
            self.send(READ, &read.finish())?;
            let (kind, body) = self.recv()?;
            match kind {
                DATA => {
                    let mut reader = Reader::new(&body);
                    let _id = reader.u32()?;
                    bytes.extend_from_slice(reader.string()?);
                }
                STATUS if code(&body)? == EOF => break,
                STATUS => return Err(status_error(&body, "the read")),
                _ => return Err(protocol_error("a reply that was neither data nor status")),
            }
        }
        self.close(&handle)?;
        Ok(bytes)
    }

    /// The names in the directory, `.` and `..` left out.
    ///
    /// # Errors
    /// Where the directory could not be opened or listed.
    pub fn list(&mut self) -> Result<Vec<String>> {
        let mut opendir = Writer::new();
        opendir.u32(self.id()).string(b".");
        self.send(OPENDIR, &opendir.finish())?;
        let handle = self.expect_handle()?;
        let mut names = Vec::new();
        loop {
            let mut readdir = Writer::new();
            readdir.u32(self.id()).string(handle.as_bytes());
            self.send(READDIR, &readdir.finish())?;
            let (kind, body) = self.recv()?;
            match kind {
                NAME => names.extend(entries(&body)?),
                STATUS if code(&body)? == EOF => break,
                STATUS => return Err(status_error(&body, "the listing")),
                _ => return Err(protocol_error("a reply that was neither names nor status")),
            }
        }
        self.close(&handle)?;
        names.retain(|name| name != "." && name != "..");
        Ok(names)
    }

    /// Remove `name` from the directory.
    ///
    /// # Errors
    /// Where the server refused.
    pub fn remove(&mut self, name: &str) -> Result<()> {
        let mut remove = Writer::new();
        remove.u32(self.id()).string(name.as_bytes());
        self.request(REMOVE, &remove.finish(), "the remove")
    }

    fn open(&mut self, name: &str, flags: u32) -> Result<String> {
        let mut open = Writer::new();
        open.u32(self.id())
            .string(name.as_bytes())
            .u32(flags)
            .u32(0);
        self.send(OPEN, &open.finish())?;
        self.expect_handle()
    }

    fn close(&mut self, handle: &str) -> Result<()> {
        let mut close = Writer::new();
        close.u32(self.id()).string(handle.as_bytes());
        self.request(CLOSE, &close.finish(), "the close")
    }

    fn expect_handle(&mut self) -> Result<String> {
        let (kind, body) = self.recv()?;
        if kind == HANDLE {
            let mut reader = Reader::new(&body);
            let _id = reader.u32()?;
            String::from_utf8(reader.string()?.to_vec())
                .map_err(|_| protocol_error("a handle that is not UTF-8"))
        } else if kind == STATUS {
            Err(status_error(&body, "the open"))
        } else {
            Err(protocol_error("a reply where a handle was due"))
        }
    }

    fn request(&mut self, kind: u8, body: &[u8], what: &str) -> Result<()> {
        self.send(kind, body)?;
        let (reply, body) = self.recv()?;
        if reply == STATUS && code(&body)? == OK {
            Ok(())
        } else if reply == STATUS {
            Err(status_error(&body, what))
        } else {
            Err(protocol_error(format!(
                "a reply where a status for {what} was due"
            )))
        }
    }

    fn id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    fn send(&mut self, kind: u8, body: &[u8]) -> Result<()> {
        self.channel.write(&frame(kind, body))
    }

    fn recv(&mut self) -> Result<(u8, Vec<u8>)> {
        let length = self.channel.read_exact(4)?;
        let length = u32::from_be_bytes([length[0], length[1], length[2], length[3]]) as usize;
        let body = self.channel.read_exact(length)?;
        let (kind, rest) = body
            .split_first()
            .ok_or_else(|| protocol_error("an SFTP packet with no type"))?;
        Ok((*kind, rest.to_vec()))
    }
}

/// A framed SFTP packet: the length, the type, the body. Shared with the far
/// end, which frames the same way.
pub(crate) fn frame(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Writer::new();
    out.u32(u32::try_from(body.len() + 1).unwrap_or(u32::MAX))
        .byte(kind);
    let mut bytes = out.finish();
    bytes.extend_from_slice(body);
    bytes
}

/// The status code an SFTP STATUS body carries.
pub(crate) fn code(body: &[u8]) -> Result<u32> {
    let mut reader = Reader::new(body);
    let _id = reader.u32()?;
    reader.u32()
}

/// The names a NAME body carries.
pub(crate) fn entries(body: &[u8]) -> Result<Vec<String>> {
    let mut reader = Reader::new(body);
    let _id = reader.u32()?;
    let count = reader.u32()?;
    let mut names = Vec::new();
    for _ in 0..count {
        names.push(utf8(reader.string()?)?);
        let _longname = reader.string()?;
        let _attrs = reader.u32()?;
    }
    Ok(names)
}

fn status_error(body: &[u8], what: &str) -> transport::TransportError {
    let mut reader = Reader::new(body);
    let code = reader.u32().and_then(|_| reader.u32()).unwrap_or(FAILURE);
    protocol_error(format!("the server refused {what} with SFTP status {code}"))
}

/// An SFTP name or handle as text.
///
/// # Errors
/// Where the bytes are not UTF-8.
pub(crate) fn utf8(bytes: &[u8]) -> Result<String> {
    String::from_utf8(bytes.to_vec())
        .map_err(|_| protocol_error("an SFTP name or handle that is not UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_framed_packet_carries_its_type_and_body_length() {
        let framed = frame(OPEN, b"abcd");
        assert_eq!(&framed[..4], &5u32.to_be_bytes());
        assert_eq!(framed[4], OPEN);
        assert_eq!(&framed[5..], b"abcd");
    }

    #[test]
    fn a_status_code_and_a_name_list_read_back_off_their_bodies() {
        let mut status = Writer::new();
        status.u32(7).u32(EOF).string(b"done").string(b"");
        assert_eq!(code(&status.finish()).expect("code"), EOF);
        let mut name = Writer::new();
        name.u32(1).u32(2);
        for entry in ["one", "two"] {
            name.string(entry.as_bytes())
                .string(entry.as_bytes())
                .u32(0);
        }
        assert_eq!(entries(&name.finish()).expect("names"), vec!["one", "two"]);
    }

    #[test]
    fn a_name_that_is_not_utf8_is_refused() {
        assert!(utf8(&[0xff, 0xfe]).is_err());
        assert_eq!(utf8(b"probe.bin").expect("utf8"), "probe.bin");
    }
}
