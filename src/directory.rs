//! The far end's side of the subsystem: serving one directory held in memory
//! to whatever the client asks of it (draft-ietf-secsh-filexfer-02). Not a
//! file system — a `BTreeMap` of names to bytes, and when each was written —
//! which is all a loopback and the Playground need to be their own
//! counterparty (ADR-0051).

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use codec::cursor::Cursor;
use codec::writer::ByteWriter;
use net::MAX_BODY;
use net::ceiling;
use ssh::{SshRead, SshWrite};
use transport::error::{Result, protocol_error};

use crate::subsystem::{
    ATTR_ACMODTIME, ATTR_SIZE, CLOSE, DATA, EOF, F_WRITE, FAILURE, Files, HANDLE, INIT, NAME,
    NO_SUCH_FILE, OK, OPEN, OPENDIR, PROTOCOL, READ, READDIR, REMOVE, STATUS, VERSION, WRITE,
    frame, utf8,
};
use ssh::channel::Channel;

/// The directory the far end serves: its files, and when each was last
/// written, the modification time a listing gives beside its length.
#[derive(Default)]
pub struct Directory {
    /// The files, name to bytes.
    pub files: Files,
    written: BTreeMap<String, u32>,
    newest: u32,
}

impl Directory {
    /// A directory holding `files`, none of them written since.
    #[must_use]
    pub fn new(files: Files) -> Self {
        Self {
            files,
            ..Self::default()
        }
    }

    /// Note `name` written now: in seconds since the Unix epoch, as SFTP
    /// version 3 carries a time, and always after the write before it, so a
    /// file written again lists as changed even within one second.
    fn touch(&mut self, name: &str) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| {
                u32::try_from(since.as_secs()).unwrap_or(u32::MAX)
            });
        self.newest = now.max(self.newest.saturating_add(1));
        self.written.insert(name.to_string(), self.newest);
    }

    /// When `name` was last written; never, for a file it was given.
    fn modified(&self, name: &str) -> u32 {
        self.written.get(name).copied().unwrap_or(0)
    }
}

/// Serve the subsystem from `directory` until the client closes the
/// channel, answering every request it makes.
///
/// # Errors
/// Where a request was malformed or the socket failed.
pub fn serve(channel: &mut Channel<'_>, directory: &mut Directory) -> Result<()> {
    let mut handles: BTreeMap<String, Handle> = BTreeMap::new();
    let mut next = 0u64;
    while let Some(body) = channel.read_frame()? {
        let (kind, rest) = body
            .split_first()
            .ok_or_else(|| protocol_error("an SFTP packet with no type"))?;
        let reply = answer(*kind, rest, directory, &mut handles, &mut next)?;
        channel.write(&reply)?;
    }
    Ok(())
}

/// A handle the far end handed out: a file to write, a file to read, or a
/// directory whose entries are still to be read.
enum Handle {
    Write(String),
    Read(String),
    Dir(bool),
}

/// The reply to one request against `directory`.
fn answer(
    kind: u8,
    body: &[u8],
    directory: &mut Directory,
    handles: &mut BTreeMap<String, Handle>,
    next: &mut u64,
) -> Result<Vec<u8>> {
    let mut reader = Cursor::new(body);
    match kind {
        INIT => {
            let mut version = Vec::new();
            version.u32_be(PROTOCOL);
            Ok(frame(VERSION, &version))
        }
        OPEN => on_open(&mut reader, directory, handles, next),
        WRITE => on_write(&mut reader, directory, handles),
        READ => on_read(&mut reader, directory, handles),
        OPENDIR => {
            let id = reader.u32_be()?;
            let _path = reader.string()?;
            let handle = format!("d{next}");
            *next += 1;
            handles.insert(handle.clone(), Handle::Dir(false));
            Ok(handle_reply(id, &handle))
        }
        READDIR => on_readdir(&mut reader, directory, handles),
        CLOSE => {
            let id = reader.u32_be()?;
            let handle = utf8(reader.string()?)?;
            handles.remove(&handle);
            Ok(status(id, OK, "closed"))
        }
        REMOVE => {
            let id = reader.u32_be()?;
            let name = utf8(reader.string()?)?;
            directory.written.remove(&name);
            if directory.files.remove(&name).is_some() {
                Ok(status(id, OK, "removed"))
            } else {
                Ok(status(id, NO_SUCH_FILE, "no such file"))
            }
        }
        other => Err(protocol_error(format!("an SFTP request of type {other}"))),
    }
}

/// Open a file: for writing it is created empty, for reading it must exist.
fn on_open(
    reader: &mut Cursor<'_>,
    directory: &mut Directory,
    handles: &mut BTreeMap<String, Handle>,
    next: &mut u64,
) -> Result<Vec<u8>> {
    let id = reader.u32_be()?;
    let name = utf8(reader.string()?)?;
    let flags = reader.u32_be()?;
    let handle = format!("h{next}");
    *next += 1;
    if flags & F_WRITE != 0 {
        directory.files.insert(name.clone(), Vec::new());
        directory.touch(&name);
        handles.insert(handle.clone(), Handle::Write(name));
    } else if directory.files.contains_key(&name) {
        handles.insert(handle.clone(), Handle::Read(name));
    } else {
        return Ok(status(id, NO_SUCH_FILE, "no such file"));
    }
    Ok(handle_reply(id, &handle))
}

/// Write data at an offset into the file the handle names.
fn on_write(
    reader: &mut Cursor<'_>,
    directory: &mut Directory,
    handles: &BTreeMap<String, Handle>,
) -> Result<Vec<u8>> {
    let id = reader.u32_be()?;
    let handle = utf8(reader.string()?)?;
    let offset = usize::try_from(reader.u64_be()?).unwrap_or(usize::MAX);
    let data = reader.string()?;
    let Some(Handle::Write(name)) = handles.get(&handle) else {
        return Ok(status(
            id,
            FAILURE,
            "a write to a handle not open for writing",
        ));
    };
    let end = offset.saturating_add(data.len());
    if let Err(refused) = ceiling::within(end, MAX_BODY, "Xmip holds of one file") {
        return Ok(status(id, FAILURE, &refused.message));
    }
    let name = name.clone();
    let file = directory.files.entry(name.clone()).or_default();
    if file.len() < end {
        file.resize(end, 0);
    }
    file[offset..end].copy_from_slice(data);
    directory.touch(&name);
    Ok(status(id, OK, "written"))
}

/// Read data at an offset from the file the handle names.
fn on_read(
    reader: &mut Cursor<'_>,
    directory: &Directory,
    handles: &BTreeMap<String, Handle>,
) -> Result<Vec<u8>> {
    let id = reader.u32_be()?;
    let handle = utf8(reader.string()?)?;
    let offset = usize::try_from(reader.u64_be()?).unwrap_or(usize::MAX);
    let want = reader.u32_be()? as usize;
    let Some(Handle::Read(name)) = handles.get(&handle) else {
        return Ok(status(
            id,
            FAILURE,
            "a read from a handle not open for reading",
        ));
    };
    let file = directory
        .files
        .get(name)
        .map(Vec::as_slice)
        .unwrap_or_default();
    if offset >= file.len() {
        return Ok(status(id, EOF, "end of file"));
    }
    let end = file.len().min(offset.saturating_add(want));
    Ok(data_reply(id, &file[offset..end]))
}

/// List the directory once, then say end of directory.
fn on_readdir(
    reader: &mut Cursor<'_>,
    directory: &Directory,
    handles: &mut BTreeMap<String, Handle>,
) -> Result<Vec<u8>> {
    let id = reader.u32_be()?;
    let handle = utf8(reader.string()?)?;
    match handles.get_mut(&handle) {
        Some(Handle::Dir(read)) if !*read => {
            *read = true;
            Ok(name_reply(id, directory))
        }
        Some(Handle::Dir(_)) => Ok(status(id, EOF, "end of directory")),
        _ => Ok(status(
            id,
            FAILURE,
            "a readdir on a handle that is not a directory",
        )),
    }
}

fn handle_reply(id: u32, handle: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.u32_be(id).string(handle.as_bytes());
    frame(HANDLE, &body)
}

fn data_reply(id: u32, data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.u32_be(id).string(data);
    frame(DATA, &body)
}

/// Every file, each with its length and its modification time.
fn name_reply(id: u32, directory: &Directory) -> Vec<u8> {
    let mut body = Vec::new();
    body.u32_be(id)
        .u32_be(u32::try_from(directory.files.len()).unwrap_or(u32::MAX));
    for (name, bytes) in &directory.files {
        let modified = directory.modified(name);
        body.string(name.as_bytes())
            .string(name.as_bytes())
            .u32_be(ATTR_SIZE | ATTR_ACMODTIME)
            .u64_be(bytes.len() as u64)
            .u32_be(modified)
            .u32_be(modified);
    }
    frame(NAME, &body)
}

fn status(id: u32, code: u32, message: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.u32_be(id)
        .u32_be(code)
        .string(message.as_bytes())
        .string(b"");
    frame(STATUS, &body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subsystem::{Stamp, code, entries};

    fn open_write(files: &mut Directory, handles: &mut BTreeMap<String, Handle>) -> String {
        let mut open = Vec::new();
        open.u32_be(1)
            .string(b"probe.bin")
            .u32_be(F_WRITE)
            .u32_be(0);
        let reply = answer(OPEN, &open, files, handles, &mut 0).expect("open");
        let mut reader = Cursor::new(&reply[5..]);
        let _id = reader.u32_be().expect("id");
        utf8(reader.string().expect("handle")).expect("utf8")
    }

    #[test]
    fn a_write_then_a_read_returns_the_same_bytes_through_the_far_end() {
        let mut files = Directory::default();
        let mut handles = BTreeMap::new();
        let handle = open_write(&mut files, &mut handles);
        let mut write = Vec::new();
        write
            .u32_be(2)
            .string(handle.as_bytes())
            .u64_be(0)
            .string(b"hello world");
        answer(WRITE, &write, &mut files, &mut handles, &mut 1).expect("write");
        assert_eq!(
            files.files.get("probe.bin").expect("stored"),
            b"hello world"
        );
    }

    #[test]
    fn a_write_past_what_the_far_end_holds_is_refused_before_it_is_allocated() {
        let mut files = Directory::default();
        let mut handles = BTreeMap::new();
        let handle = open_write(&mut files, &mut handles);
        let mut write = Vec::new();
        write
            .u32_be(2)
            .string(handle.as_bytes())
            .u64_be(u64::MAX - 4)
            .string(b"hello");
        let reply = answer(WRITE, &write, &mut files, &mut handles, &mut 1).expect("answered");
        assert_eq!(reply[4], STATUS);
        assert_eq!(code(&reply[5..]).expect("code"), FAILURE);
        assert!(files.files.get("probe.bin").is_none_or(Vec::is_empty));
    }

    #[test]
    fn a_read_past_the_end_is_an_end_of_file_status() {
        let mut files = Directory::default();
        files.files.insert("a".to_string(), b"xy".to_vec());
        let mut handles = BTreeMap::new();
        handles.insert("h0".to_string(), Handle::Read("a".to_string()));
        let mut read = Vec::new();
        read.u32_be(9).string(b"h0").u64_be(2).u32_be(10);
        let reply = answer(READ, &read, &mut files, &mut handles, &mut 1).expect("read");
        assert_eq!(reply[4], STATUS);
        assert_eq!(code(&reply[5..]).expect("code"), EOF);
    }

    #[test]
    fn a_readdir_lists_once_with_stamps_then_says_end_of_directory() {
        let mut files = Directory::default();
        files.files.insert("one".to_string(), Vec::new());
        files.files.insert("two".to_string(), b"xy".to_vec());
        let mut handles = BTreeMap::new();
        handles.insert("d0".to_string(), Handle::Dir(false));
        let mut readdir = Vec::new();
        readdir.u32_be(1).string(b"d0");
        let first = answer(READDIR, &readdir, &mut files, &mut handles, &mut 1).expect("dir");
        assert_eq!(first[4], NAME);
        let listed = entries(&first[5..]).expect("names");
        let stamped = |name: &str, length| {
            let modified = 0;
            (name.to_string(), Some(Stamp { length, modified }))
        };
        assert_eq!(listed, vec![stamped("one", 0), stamped("two", 2)]);
        let mut again = Vec::new();
        again.u32_be(2).string(b"d0");
        let end = answer(READDIR, &again, &mut files, &mut handles, &mut 1).expect("end");
        assert_eq!(code(&end[5..]).expect("code"), EOF);
    }

    #[test]
    fn a_file_written_again_lists_with_another_modification_time() {
        let mut files = Directory::default();
        let mut handles = BTreeMap::new();
        open_write(&mut files, &mut handles);
        let first = files.modified("probe.bin");
        assert!(first > 0, "written now");
        open_write(&mut files, &mut handles);
        assert!(
            files.modified("probe.bin") > first,
            "within the same second too"
        );
    }

    #[test]
    fn an_unknown_request_type_is_refused() {
        let mut files = Directory::default();
        let mut handles = BTreeMap::new();
        assert!(answer(200, &[], &mut files, &mut handles, &mut 0).is_err());
    }
}
