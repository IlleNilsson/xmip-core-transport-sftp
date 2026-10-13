//! The directory an SFTP channel reaches, as the claim sees one
//! (`transport::claim::ClaimSite`; ADR-0024, amendment 2026-10-13).
//!
//! **The claim in SFTP's words.** A turn is a file opened with `CREAT` and
//! `EXCL`, which the server refuses where one of that name exists — the one
//! exclusive step SFTP has — holding its claimant's name. The claim is
//! `RENAME`, and so is the return: version 3 refuses a rename onto a name
//! that exists (draft-ietf-secsh-filexfer-02, section 6.5), so a file dropped
//! under the dropped name since is never replaced, and the claimed one is
//! held until the name is free.

use std::cell::RefCell;

use codec::cursor::Cursor;
use codec::writer::ByteWriter;
use ssh::{SshRead, SshWrite};
use transport::claim::{ClaimSite, Listed, Restore, is_turn};
use transport::error::{Result, protocol_error};

use crate::subsystem::{
    ATTRS, F_CREAT, F_EXCL, F_WRITE, HANDLE, NO_SUCH_FILE, OK, OPEN, REMOVE, RENAME, STAT, STATUS,
    Sftp, Stamp, code, stamp, status_error,
};

impl Sftp<'_, '_> {
    /// The status the server answered the request `kind` with.
    fn status_of(&mut self, kind: u8, body: &[u8], what: &str) -> Result<u32> {
        self.send(kind, body)?;
        let (reply, body) = self.recv()?;
        if reply == STATUS {
            code(&body)
        } else {
            Err(protocol_error(format!(
                "a reply where a status for {what} was due"
            )))
        }
    }

    /// Rename `from` to `to`: the status the server answered.
    ///
    /// # Errors
    /// Where the channel broke.
    pub fn rename(&mut self, from: &str, to: &str) -> Result<u32> {
        let mut rename = Vec::new();
        rename
            .u32_be(self.id())
            .string(from.as_bytes())
            .string(to.as_bytes());
        self.status_of(RENAME, &rename, "the rename")
    }

    /// Remove `name`: the status the server answered.
    ///
    /// # Errors
    /// Where the channel broke.
    pub fn removed(&mut self, name: &str) -> Result<u32> {
        let mut remove = Vec::new();
        remove.u32_be(self.id()).string(name.as_bytes());
        self.status_of(REMOVE, &remove, "the remove")
    }

    /// The stamp of `name`; `None` where there is no such file.
    ///
    /// # Errors
    /// Where the channel broke or the server refused for another reason.
    pub fn stat(&mut self, name: &str) -> Result<Option<Stamp>> {
        let mut stat = Vec::new();
        stat.u32_be(self.id()).string(name.as_bytes());
        self.send(STAT, &stat)?;
        let (kind, body) = self.recv()?;
        match kind {
            ATTRS => {
                let mut reader = Cursor::new(&body);
                let _id = reader.u32_be()?;
                stamp(&mut reader)
            }
            STATUS if code(&body)? == NO_SUCH_FILE => Ok(None),
            STATUS => Err(status_error(&body, "the stat")),
            _ => Err(protocol_error("a reply where attributes were due")),
        }
    }

    /// `name` created holding `bytes`, only where no file of that name
    /// exists: `false` where the server refused the open.
    ///
    /// # Errors
    /// Where the channel broke, or the write or close was refused.
    pub fn create_exclusive(&mut self, name: &str, bytes: &[u8]) -> Result<bool> {
        let mut open = Vec::new();
        open.u32_be(self.id())
            .string(name.as_bytes())
            .u32_be(F_WRITE | F_CREAT | F_EXCL)
            .u32_be(0);
        self.send(OPEN, &open)?;
        let (kind, body) = self.recv()?;
        if kind == STATUS {
            return Ok(false);
        }
        if kind != HANDLE {
            return Err(protocol_error("a reply where a handle was due"));
        }
        let mut reader = Cursor::new(&body);
        let _id = reader.u32_be()?;
        let handle = String::from_utf8(reader.string()?.to_vec())
            .map_err(|_| protocol_error("a handle that is not UTF-8"))?;
        let mut write = Vec::new();
        write
            .u32_be(self.id())
            .string(handle.as_bytes())
            .u64_be(0)
            .string(bytes);
        self.request(crate::subsystem::WRITE, &write, "the write")?;
        self.close(&handle)?;
        Ok(true)
    }

    /// The whole of a small file `name`; `None` where it cannot be read.
    ///
    /// # Errors
    /// Where the channel broke.
    pub fn read_small(&mut self, name: &str) -> Result<Option<Vec<u8>>> {
        let Ok(handle) = self.open_for_reading(name) else {
            return Ok(None);
        };
        let mut whole = Vec::new();
        while let Some(chunk) = self.read_at(&handle, whole.len() as u64)? {
            whole.extend(chunk);
        }
        self.close(&handle)?;
        Ok(Some(whole))
    }
}

/// The directory one open channel reaches.
pub struct SftpSite<'s, 'a, 'c>(RefCell<&'s mut Sftp<'a, 'c>>);

impl<'s, 'a, 'c> SftpSite<'s, 'a, 'c> {
    pub fn new(sftp: &'s mut Sftp<'a, 'c>) -> Self {
        Self(RefCell::new(sftp))
    }
}

impl ClaimSite for SftpSite<'_, '_, '_> {
    type Stamp = Stamp;

    fn listed(&self) -> Result<Vec<Listed<Stamp>>> {
        self.0.borrow_mut().list()
    }

    fn turns(&self) -> Result<Vec<String>> {
        Ok(self
            .listed()?
            .into_iter()
            .map(|(name, _)| name)
            .filter(|name| is_turn(name))
            .collect())
    }

    fn stamp(&self, name: &str) -> Result<Option<Stamp>> {
        self.0.borrow_mut().stat(name)
    }

    fn take_turn(&self, turn: &str, claimant: &str) -> Result<bool> {
        self.0
            .borrow_mut()
            .create_exclusive(turn, claimant.as_bytes())
    }

    fn holder(&self, turn: &str) -> Result<Option<String>> {
        Ok(self
            .0
            .borrow_mut()
            .read_small(turn)?
            .and_then(|held| String::from_utf8(held).ok()))
    }

    fn drop_turn(&self, turn: &str, _claimant: &str) -> Result<()> {
        self.delete(turn)
    }

    fn rename(&self, from: &str, to: &str) -> Result<bool> {
        Ok(self.0.borrow_mut().rename(from, to)? == OK)
    }

    fn restore(&self, claimed: &str, dropped: &str) -> Result<Restore> {
        let mut sftp = self.0.borrow_mut();
        let status = sftp.rename(claimed, dropped)?;
        if status == OK {
            return Ok(Restore::Back);
        }
        if sftp.stat(claimed)?.is_none() {
            return Ok(Restore::Gone);
        }
        Ok(Restore::Kept(if sftp.stat(dropped)?.is_some() {
            format!("returning {dropped}: a file of that name was dropped since")
        } else {
            format!("returning {dropped}: the server answered SFTP status {status}")
        }))
    }

    fn delete(&self, name: &str) -> Result<()> {
        match self.0.borrow_mut().removed(name)? {
            OK | NO_SUCH_FILE => Ok(()),
            status => Err(protocol_error(format!(
                "the server refused the remove of {name} with SFTP status {status}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex, PoisonError};
    use std::time::Duration;

    use ed25519_dalek::SigningKey;
    use transport::concurrent::Concurrent;
    use transport::{Configured, NodeLocation, Transport};

    use crate::SftpTransport;
    use crate::directory::{Directory, Shared};

    const FILES: usize = 40;

    fn server() -> (Concurrent, Shared) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bound");
        let shared: Shared = Arc::new(Mutex::new(Directory::default()));
        let host = SigningKey::from_bytes(&[0x5e; 32]);
        let timeout = Some(Duration::from_secs(10));
        let far = crate::serving(listener, host, Arc::clone(&shared), timeout).expect("serving");
        (far, shared)
    }

    fn names(shared: &Shared) -> Vec<String> {
        let held = shared.lock().unwrap_or_else(PoisonError::into_inner);
        held.files.keys().cloned().collect()
    }

    fn receiver(address: &str, place: usize) -> SftpTransport {
        let node = NodeLocation::new(format!("process-{}/place-{place}", std::process::id()));
        SftpTransport::new(address)
            .timing_out_after(Duration::from_secs(10))
            .on_node(&node)
            .expect("built on its node")
    }

    #[test]
    fn two_nodes_over_one_server_take_each_file_once() {
        let (far, shared) = server();
        let sender = SftpTransport::new(far.address()).timing_out_after(Duration::from_secs(10));
        for file in 0..FILES {
            sender
                .send(&format!("order-{file}.edi"), file.to_string().as_bytes())
                .expect("put");
        }
        let receivers = [receiver(far.address(), 0), receiver(far.address(), 1)];
        let shared = &shared;
        let took: Vec<Vec<Vec<u8>>> = std::thread::scope(|scope| {
            let racing: Vec<_> = receivers
                .iter()
                .map(|near| {
                    scope.spawn(move || {
                        let mut took = Vec::new();
                        while !names(shared).is_empty() {
                            for arrived in near.receive().expect("receiving") {
                                took.push(arrived.taken().expect("taken").bytes);
                            }
                        }
                        took
                    })
                })
                .collect();
            racing
                .into_iter()
                .map(|one| one.join().expect("a receiver"))
                .collect()
        });
        let all: Vec<&Vec<u8>> = took.iter().flatten().collect();
        let once: BTreeSet<&Vec<u8>> = all.iter().copied().collect();
        assert_eq!(all.len(), FILES, "every file taken, none twice");
        assert_eq!(once.len(), FILES);
    }

    #[test]
    fn a_starting_node_returns_the_claims_its_name_left_on_the_server() {
        let (far, shared) = server();
        let first = receiver(far.address(), 0);
        first.send("mine.edi", b"ISA").expect("put");
        assert!(first.receive().expect("found").is_empty());
        let held = first.receive().expect("claimed");
        assert_eq!(held.len(), 1);
        // The node dies holding its claim: nothing told, nothing returned.
        std::mem::forget(held);
        std::mem::forget(first);
        assert!(
            names(&shared)
                .iter()
                .all(|name| name.contains(".xmip-claim."))
        );

        let again = receiver(far.address(), 0);
        assert!(again.receive().expect("returned").is_empty());
        assert_eq!(names(&shared), ["mine.edi"], "returned under its name");
        let taken = again
            .receive()
            .expect("taken")
            .remove(0)
            .taken()
            .expect("read");
        assert_eq!(taken.bytes, b"ISA");
        assert!(names(&shared).is_empty(), "accepted, removed");
    }
}
