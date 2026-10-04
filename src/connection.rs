//! The kept SSH connection, shared by the pool and the arrivals of the
//! receive that listed on it.
//!
//! A receive lists the directory over one channel and hands each file back
//! unread. The channel stays open until every arrival of that receive has
//! its verdict: its body reads the file a request's worth at a time (`READ`)
//! as the runtime asks, and its acknowledgement removes it (`REMOVE`) on
//! `Accepted` — the same channel, so no round trip is added to what the
//! receive did when it took and removed every file itself. A refused file is
//! left where it lies and remembered with its stamp, and the listing leaves
//! it out while it lies so (`transport::Refused`). The library's
//! channel borrows its connection, so the channel is held by one thread for
//! the receive — the harvest — and the arrivals ask it, a chunk at a time
//! through a channel of one; it ends, and the connection goes back to the
//! pool, at the last verdict (`transport::together`). A send that finds the connection
//! lent to a harvest fails, and the pool opens it one of its own.

use std::sync::mpsc::{Receiver, Sender, SyncSender, channel, sync_channel};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use transport::body::chunked;
use transport::error::{Result, TransportError, protocol_error};
use transport::pool::Pooled;
use transport::together::together;
use transport::{Acknowledgement, Arrived, Refused, Verdict};

use crate::client::Client;
use crate::subsystem::{Listed, Sftp, Stamp};

/// Where the client is.
enum Line {
    Here(Client),
    /// Lent to the harvest of a receive whose arrivals await their verdict.
    Harvesting,
    /// Gone: a harvest's connection broke.
    Broken,
}

/// A connected, authenticated client, kept by the pool and lent to one
/// receive's harvest at a time.
#[derive(Clone)]
pub struct Connection(Arc<Mutex<Line>>);

/// What an arrival asks of its harvest.
enum Request {
    /// The file's chunks, in order, `None` after the last.
    Read(String, SyncSender<Result<Option<Vec<u8>>>>),
    /// Remove the file.
    Remove(String, SyncSender<Result<()>>),
    /// Every arrival has its verdict: close the channel, give the client
    /// back, then say so.
    Finish(SyncSender<()>),
}

/// How a harvest's channel ended.
enum Ended {
    /// Nothing was listed, or nothing but what lies refused.
    Empty(Vec<Listed>),
    /// The arrivals were answered; the last asked to be told when the
    /// client is back.
    Answered(Option<SyncSender<()>>),
}

impl Connection {
    #[must_use]
    pub fn new(client: Client) -> Self {
        Self(Arc::new(Mutex::new(Line::Here(client))))
    }

    fn line(&self) -> MutexGuard<'_, Line> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Run `act` on the client while it is not lent to a harvest.
    ///
    /// # Errors
    /// Where the client is lent or broken — the pool then opens a
    /// connection of its own — or as `act`.
    pub fn with<T>(&self, act: impl FnOnce(&mut Client) -> Result<T>) -> Result<T> {
        match &mut *self.line() {
            Line::Here(client) => act(client),
            Line::Harvesting => Err(TransportError::retryable(
                "the connection is lent to a receive whose files await their verdict",
            )),
            Line::Broken => Err(protocol_error("the connection broke during a receive")),
        }
    }

    /// List the directory on a channel of its own, and hand back each file
    /// as an arrival read and removed over that channel: `origin` makes its
    /// origin from its name. A file `refused` holds as it lies is left out;
    /// one the cycle refuses is left and remembered there.
    ///
    /// # Errors
    /// Where the client is lent or broken, or the listing failed.
    pub fn harvest(
        &self,
        origin: impl Fn(&str) -> String,
        refused: &Refused<String, Stamp>,
    ) -> Result<Vec<Arrived>> {
        let lent = std::mem::replace(&mut *self.line(), Line::Harvesting);
        let client = match lent {
            Line::Here(client) => client,
            other => {
                *self.line() = other;
                return self.with(|_| Ok(Vec::new()));
            }
        };
        let (listed, names) = sync_channel(1);
        let (asking, requests) = channel();
        let line = Arc::clone(&self.0);
        let sifting = refused.clone();
        std::thread::Builder::new()
            .name("sftp-harvest".to_string())
            .spawn(move || harvesting(client, &line, &sifting, &listed, &requests))
            .map_err(|e| transport::error::classify("starting a harvest", &e))?;
        let names = names
            .recv()
            .map_err(|_| protocol_error("the harvest ended before it listed"))??;
        if names.is_empty() {
            return Ok(Vec::new());
        }
        let listed: Vec<String> = names.iter().map(|(name, _)| name.clone()).collect();
        let (removing, finishing) = (asking.clone(), asking.clone());
        // The last verdict, or the last let go without one, ends the
        // harvest and waits until the client is back, so the receive after
        // finds it (`transport::together`).
        let acknowledgements = together(
            names.len(),
            move |at, verdict| match verdict {
                Verdict::Accepted => remove(&removing, &listed[at]),
                // A refusal is not a consumption: the file is the only copy.
                Verdict::Refused(_) | Verdict::Failed => Ok(()),
            },
            move |_| {
                finish(&finishing);
                Ok(())
            },
        );
        Ok(names
            .into_iter()
            .zip(acknowledgements)
            .map(|((name, stamp), told)| {
                // Without a stamp it cannot be known unchanged: listed again.
                let told = match stamp {
                    Some(stamp) => refused.remembering(name.clone(), stamp, told),
                    None => told,
                };
                arrival(origin(&name), name, &asking, told)
            })
            .collect())
    }
}

impl Pooled for Connection {
    /// A connection lent to a harvest is kept: it comes back when the
    /// harvest's arrivals are let go.
    fn usable(&mut self) -> bool {
        match &mut *self.line() {
            Line::Here(client) => client.usable(),
            Line::Harvesting => true,
            Line::Broken => false,
        }
    }
}

/// The harvest's thread: list, leave out what lies refused, answer the
/// arrivals until the last is let go, close the channel, and give the
/// client back. An empty listing, and
/// the last arrival's finish, are answered once the client is back, so the
/// next receive finds it.
fn harvesting(
    mut client: Client,
    line: &Mutex<Line>,
    refused: &Refused<String, Stamp>,
    listed: &SyncSender<Result<Vec<Listed>>>,
    requests: &Receiver<Request>,
) {
    let harvested = client.with_subsystem(|sftp| {
        let names = refused.sift(sftp.list()?, |(name, _)| name, |(_, stamp)| *stamp);
        if names.is_empty() {
            return Ok(Ended::Empty(names));
        }
        // The receive is waiting for it; nothing else can fail this send.
        let _ = listed.send(Ok(names));
        answering(sftp, requests).map(Ended::Answered)
    });
    let mut kept = line.lock().unwrap_or_else(PoisonError::into_inner);
    match harvested {
        Ok(ended) => {
            *kept = Line::Here(client);
            drop(kept);
            match ended {
                Ended::Empty(empty) => {
                    let _ = listed.send(Ok(empty));
                }
                Ended::Answered(Some(finished)) => {
                    let _ = finished.send(());
                }
                Ended::Answered(None) => {}
            }
        }
        Err(error) => {
            *kept = Line::Broken;
            drop(kept);
            // Where the names went out already, nobody waits for this.
            let _ = listed.send(Err(error));
        }
    }
}

/// Answer what the arrivals ask, one at a time, until the last is let go:
/// what to tell once the client is back, where the last asked.
fn answering(
    sftp: &mut Sftp<'_, '_>,
    requests: &Receiver<Request>,
) -> Result<Option<SyncSender<()>>> {
    while let Ok(request) = requests.recv() {
        match request {
            Request::Read(name, chunks) => reading(sftp, &name, &chunks)?,
            Request::Remove(name, done) => {
                let _ = done.send(sftp.remove(&name));
            }
            Request::Finish(finished) => return Ok(Some(finished)),
        }
    }
    Ok(None)
}

/// Read `name` to its end into `chunks`, or until its body is let go; the
/// handle is closed either way. A refusal of the file is the body's; a
/// close that fails ends the harvest.
fn reading(
    sftp: &mut Sftp<'_, '_>,
    name: &str,
    chunks: &SyncSender<Result<Option<Vec<u8>>>>,
) -> Result<()> {
    let handle = match sftp.open_for_reading(name) {
        Ok(handle) => handle,
        Err(error) => {
            let _ = chunks.send(Err(error));
            return Ok(());
        }
    };
    let mut offset = 0u64;
    let ended = loop {
        match sftp.read_at(&handle, offset) {
            Ok(Some(chunk)) => {
                offset += chunk.len() as u64;
                if chunks.send(Ok(Some(chunk))).is_err() {
                    break None;
                }
            }
            Ok(None) => break Some(Ok(None)),
            Err(error) => break Some(Err(error)),
        }
    };
    sftp.close(&handle)?;
    if let Some(ended) = ended {
        let _ = chunks.send(ended);
    }
    Ok(())
}

/// Remove `name` through the harvest.
fn remove(asking: &Sender<Request>, name: &str) -> Result<()> {
    let (done, answer) = sync_channel(1);
    asking
        .send(Request::Remove(name.to_string(), done))
        .map_err(|_| protocol_error("the receive's channel closed before the remove"))?;
    answer
        .recv()
        .map_err(|_| protocol_error("the receive's channel closed during the remove"))?
}

/// End the harvest, and wait until the client is back.
fn finish(asking: &Sender<Request>) {
    let (done, finished) = sync_channel(1);
    if asking.send(Request::Finish(done)).is_ok() {
        // An error is a harvest already ended: nothing to wait for.
        let _ = finished.recv();
    }
}

/// One listed file: read through the harvest as the runtime asks, its
/// verdict given by `acknowledgement`.
fn arrival(
    origin: String,
    name: String,
    asking: &Sender<Request>,
    acknowledgement: Acknowledgement,
) -> Arrived {
    let mut fetch = Fetch {
        asking: asking.clone(),
        name,
        chunks: None,
    };
    Arrived::new(origin, chunked(move || fetch.next_chunk()), acknowledgement)
}

/// One file's body: asked of the harvest on the first read, a chunk at a
/// time after.
struct Fetch {
    asking: Sender<Request>,
    name: String,
    chunks: Option<Receiver<Result<Option<Vec<u8>>>>>,
}

impl Fetch {
    /// The next chunk the harvest read, `None` at the end.
    fn next_chunk(&mut self) -> Result<Option<Vec<u8>>> {
        let chunks = if let Some(chunks) = &self.chunks {
            chunks
        } else {
            let (chunks, receiving) = sync_channel(1);
            self.asking
                .send(Request::Read(self.name.clone(), chunks))
                .map_err(|_| protocol_error("the receive's channel closed"))?;
            self.chunks.insert(receiving)
        };
        chunks
            .recv()
            .map_err(|_| protocol_error("the receive's channel closed mid-read"))?
    }
}
