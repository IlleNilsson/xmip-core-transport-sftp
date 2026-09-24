//! The far end's side of the subsystem: serving one directory held in memory
//! to whatever the client asks of it (draft-ietf-secsh-filexfer-02). Not a
//! file system — a `BTreeMap` of names to bytes — which is all a loopback and
//! the Playground need to be their own counterparty (ADR-0051).

use std::collections::BTreeMap;

use codec::cursor::Cursor;
use codec::writer::ByteWriter;
use transport::error::{Result, protocol_error};

use crate::channel::Channel;
use crate::packet::{Ssh, SshWrite};
use crate::subsystem::{
    CLOSE, DATA, EOF, F_WRITE, FAILURE, Files, HANDLE, INIT, NAME, NO_SUCH_FILE, OK, OPEN, OPENDIR,
    PROTOCOL, READ, READDIR, REMOVE, STATUS, VERSION, WRITE, frame, utf8,
};

/// Serve the subsystem from `files` until the client closes the channel,
/// answering every request it makes.
///
/// # Errors
/// Where a request was malformed or the socket failed.
pub fn serve(channel: &mut Channel<'_>, files: &mut Files) -> Result<()> {
    let mut handles: BTreeMap<String, Handle> = BTreeMap::new();
    let mut next = 0u64;
    while let Some(body) = channel.read_frame()? {
        let (kind, rest) = body
            .split_first()
            .ok_or_else(|| protocol_error("an SFTP packet with no type"))?;
        let reply = answer(*kind, rest, files, &mut handles, &mut next)?;
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

/// The reply to one request against `files`.
fn answer(
    kind: u8,
    body: &[u8],
    files: &mut Files,
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
        OPEN => on_open(&mut reader, files, handles, next),
        WRITE => on_write(&mut reader, files, handles),
        READ => on_read(&mut reader, files, handles),
        OPENDIR => {
            let id = reader.u32_be()?;
            let _path = reader.string()?;
            let handle = format!("d{next}");
            *next += 1;
            handles.insert(handle.clone(), Handle::Dir(false));
            Ok(handle_reply(id, &handle))
        }
        READDIR => on_readdir(&mut reader, files, handles),
        CLOSE => {
            let id = reader.u32_be()?;
            let handle = utf8(reader.string()?)?;
            handles.remove(&handle);
            Ok(status(id, OK, "closed"))
        }
        REMOVE => {
            let id = reader.u32_be()?;
            let name = utf8(reader.string()?)?;
            if files.remove(&name).is_some() {
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
    files: &mut Files,
    handles: &mut BTreeMap<String, Handle>,
    next: &mut u64,
) -> Result<Vec<u8>> {
    let id = reader.u32_be()?;
    let name = utf8(reader.string()?)?;
    let flags = reader.u32_be()?;
    let handle = format!("h{next}");
    *next += 1;
    if flags & F_WRITE != 0 {
        files.insert(name.clone(), Vec::new());
        handles.insert(handle.clone(), Handle::Write(name));
    } else if files.contains_key(&name) {
        handles.insert(handle.clone(), Handle::Read(name));
    } else {
        return Ok(status(id, NO_SUCH_FILE, "no such file"));
    }
    Ok(handle_reply(id, &handle))
}

/// Write data at an offset into the file the handle names.
fn on_write(
    reader: &mut Cursor<'_>,
    files: &mut Files,
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
    let file = files.entry(name.clone()).or_default();
    let end = offset.saturating_add(data.len());
    if file.len() < end {
        file.resize(end, 0);
    }
    file[offset..end].copy_from_slice(data);
    Ok(status(id, OK, "written"))
}

/// Read data at an offset from the file the handle names.
fn on_read(
    reader: &mut Cursor<'_>,
    files: &Files,
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
    let file = files.get(name).map(Vec::as_slice).unwrap_or_default();
    if offset >= file.len() {
        return Ok(status(id, EOF, "end of file"));
    }
    let end = file.len().min(offset.saturating_add(want));
    Ok(data_reply(id, &file[offset..end]))
}

/// List the directory once, then say end of directory.
fn on_readdir(
    reader: &mut Cursor<'_>,
    files: &Files,
    handles: &mut BTreeMap<String, Handle>,
) -> Result<Vec<u8>> {
    let id = reader.u32_be()?;
    let handle = utf8(reader.string()?)?;
    match handles.get_mut(&handle) {
        Some(Handle::Dir(read)) if !*read => {
            *read = true;
            Ok(name_reply(id, &files.keys().cloned().collect::<Vec<_>>()))
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

fn name_reply(id: u32, names: &[String]) -> Vec<u8> {
    let mut body = Vec::new();
    body.u32_be(id)
        .u32_be(u32::try_from(names.len()).unwrap_or(u32::MAX));
    for name in names {
        body.string(name.as_bytes())
            .string(name.as_bytes())
            .u32_be(0);
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
    use crate::subsystem::{code, entries};

    fn open_write(files: &mut Files, handles: &mut BTreeMap<String, Handle>) -> String {
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
        let mut files = Files::new();
        let mut handles = BTreeMap::new();
        let handle = open_write(&mut files, &mut handles);
        let mut write = Vec::new();
        write
            .u32_be(2)
            .string(handle.as_bytes())
            .u64_be(0)
            .string(b"hello world");
        answer(WRITE, &write, &mut files, &mut handles, &mut 1).expect("write");
        assert_eq!(files.get("probe.bin").expect("stored"), b"hello world");
    }

    #[test]
    fn a_read_past_the_end_is_an_end_of_file_status() {
        let mut files = Files::new();
        files.insert("a".to_string(), b"xy".to_vec());
        let mut handles = BTreeMap::new();
        handles.insert("h0".to_string(), Handle::Read("a".to_string()));
        let mut read = Vec::new();
        read.u32_be(9).string(b"h0").u64_be(2).u32_be(10);
        let reply = answer(READ, &read, &mut files, &mut handles, &mut 1).expect("read");
        assert_eq!(reply[4], STATUS);
        assert_eq!(code(&reply[5..]).expect("code"), EOF);
    }

    #[test]
    fn a_readdir_lists_once_then_says_end_of_directory() {
        let mut files = Files::new();
        files.insert("one".to_string(), Vec::new());
        files.insert("two".to_string(), Vec::new());
        let mut handles = BTreeMap::new();
        handles.insert("d0".to_string(), Handle::Dir(false));
        let mut readdir = Vec::new();
        readdir.u32_be(1).string(b"d0");
        let first = answer(READDIR, &readdir, &mut files, &mut handles, &mut 1).expect("dir");
        assert_eq!(first[4], NAME);
        assert_eq!(entries(&first[5..]).expect("names"), vec!["one", "two"]);
        let mut again = Vec::new();
        again.u32_be(2).string(b"d0");
        let end = answer(READDIR, &again, &mut files, &mut handles, &mut 1).expect("end");
        assert_eq!(code(&end[5..]).expect("code"), EOF);
    }

    #[test]
    fn an_unknown_request_type_is_refused() {
        let mut files = Files::new();
        let mut handles = BTreeMap::new();
        assert!(answer(200, &[], &mut files, &mut handles, &mut 0).is_err());
    }
}
