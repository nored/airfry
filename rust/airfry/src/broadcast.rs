//! Broadcast capture fan-out — a faithful Rust port of doubletake's
//! internal/airplay/capture_broadcast.go.
//!
//! `BroadcastCapture` reads from a single capture source and fans the raw byte
//! stream out to multiple registered sinks. Each `BroadcastSink` is a reader end
//! that exposes the same `read(&mut [u8]) -> Result<usize>` interface the mirror
//! consumes from `capture::CaptureSource`, so a single screen capture can drive
//! mirroring to several receivers at once.
//!
//! Usage:
//!
//! ```ignore
//! let bc = BroadcastCapture::new(capture);
//! let sink1 = bc.add_sink();
//! let sink2 = bc.add_sink();
//! std::thread::spawn(move || { let _ = bc.run(); }); // pumps bytes
//! // hand sink1 / sink2 to two mirror sessions; each reads like a CaptureSource.
//! ```
//!
//! Go uses an `io.Pipe` per sink: blocking reads, EOF on close, write error on a
//! closed pipe, and crucially BACK-PRESSURE — `pw.Write` blocks until the reader
//! consumes, so a slow sink throttles the pump instead of letting bytes pile up
//! in unbounded memory. We reproduce those semantics with a BOUNDED
//! `sync_channel` of byte chunks per sink plus a closed flag: `read` blocks for
//! the next chunk, returns 0 at EOF, and `write` blocks on a full channel (the
//! back-pressure) and fails once the sink is closed so `run` can drop it.

#![allow(dead_code)]

use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Condvar, Mutex};

use anyhow::{bail, Result};

use crate::capture::CaptureSource;

/// The reader end of a `BroadcastCapture`. Satisfies the same read contract as
/// `CaptureSource` (`read` fills the buffer, returning 0 at end-of-stream) and
/// can therefore be handed to the mirror in place of a live capture.
///
/// The matching writer-side `SinkHandle` holds the only `Sender`; when `run`
/// closes/removes that handle the channel drops, waking a blocked `read` with
/// EOF — the `io.Pipe` `CloseWithError(io.EOF)` analogue.
pub struct BroadcastSink {
    rx: Receiver<Vec<u8>>,
    /// Bytes left over from the previous read that did not fit the caller buf,
    /// mirroring `CaptureSource`'s leftover handling.
    leftover: Vec<u8>,
    /// Shared closed flag (also set by `run`/`remove_sink` on the writer side).
    /// Dropping the BroadcastSink marks the sink closed so the pump removes it,
    /// mirroring Go where the reader half closing breaks the pipe.
    closed: Arc<Mutex<bool>>,
}

impl Drop for BroadcastSink {
    fn drop(&mut self) {
        *self.closed.lock().unwrap() = true;
    }
}

impl BroadcastSink {
    /// Fill `buf` with the next chunk of the broadcast byte-stream. Blocks until
    /// data arrives or the broadcast ends; returns the number of bytes written,
    /// or 0 at end-of-stream. Faithful analogue of `CaptureSource::read` /
    /// Go's `BroadcastSink.Read`.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.leftover.is_empty() {
            match self.rx.recv() {
                Ok(chunk) => self.leftover = chunk,
                // Writer-side sender dropped (sink closed / broadcast ended) → EOF.
                Err(_) => return Ok(0),
            }
        }
        let n = buf.len().min(self.leftover.len());
        buf[..n].copy_from_slice(&self.leftover[..n]);
        self.leftover.drain(..n);
        Ok(n)
    }
}

/// One registered sink as seen from the `BroadcastCapture` (writer) side: its
/// BOUNDED sender (a slow reader makes `send` block — the back-pressure that
/// Go's `io.Pipe` provides) plus a shared closed flag and an identity tag for
/// `remove_sink`. Cloneable so the pump can snapshot the live set under the lock
/// and then `write` (possibly blocking) without holding the sinks lock — exactly
/// like Go copies the slice before writing.
#[derive(Clone)]
struct SinkHandle {
    id: u64,
    tx: SyncSender<Vec<u8>>,
    closed: Arc<Mutex<bool>>,
}

/// Per-sink bounded channel capacity. Go's `io.Pipe` is effectively a rendezvous
/// (capacity ~0); we use a small buffer so the pump isn't fully serialized on
/// every read but a persistently slow sink still applies back-pressure.
const SINK_CHANNEL_CAP: usize = 4;

impl SinkHandle {
    /// write — `bc.write`/`pw.Write` analogue. Returns Err once the sink is
    /// closed (Go's `io.ErrClosedPipe`) or its reader is gone. Blocks while the
    /// bounded channel is full (back-pressure).
    fn write(&self, chunk: &[u8]) -> Result<()> {
        if *self.closed.lock().unwrap() {
            bail!("broadcast sink closed");
        }
        if self.tx.send(chunk.to_vec()).is_err() {
            bail!("broadcast sink reader gone");
        }
        Ok(())
    }

    fn close(&self) {
        *self.closed.lock().unwrap() = true;
    }
}

/// Shared `run`/`done`/`err` state.
struct Shared {
    sinks: Mutex<Vec<SinkHandle>>,
    /// Set true once `run` has finished (Go's closed `done` channel). Paired
    /// with `done_cv` so callers can block until the pump finishes, matching
    /// Go's `Done() <-chan struct{}`.
    done: Mutex<bool>,
    done_cv: Condvar,
    /// The error that ended `run`, if any (Go's `err` field).
    err: Mutex<Option<String>>,
    next_id: Mutex<u64>,
}

/// Reads from a single `CaptureSource` and fans its raw byte stream out to all
/// registered sinks. Faithful port of Go's `BroadcastCapture`.
pub struct BroadcastCapture {
    src: Mutex<CaptureSource>,
    shared: Arc<Shared>,
}

impl BroadcastCapture {
    /// Wrap `src`. Call `add_sink` before `run`.
    pub fn new(src: CaptureSource) -> BroadcastCapture {
        BroadcastCapture {
            src: Mutex::new(src),
            shared: Arc::new(Shared {
                sinks: Mutex::new(Vec::new()),
                done: Mutex::new(false),
                done_cv: Condvar::new(),
                err: Mutex::new(None),
                next_id: Mutex::new(0),
            }),
        }
    }

    /// AddSink — register a new fan-out reader. Must be called before `run`
    /// (or concurrently; the sink simply starts receiving from the next chunk).
    pub fn add_sink(&self) -> BroadcastSink {
        // BOUNDED channel → a slow reader applies back-pressure to the pump,
        // like Go's blocking io.Pipe.
        let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(SINK_CHANNEL_CAP);
        let closed = Arc::new(Mutex::new(false));
        let id = {
            let mut n = self.shared.next_id.lock().unwrap();
            let id = *n;
            *n += 1;
            id
        };
        self.shared.sinks.lock().unwrap().push(SinkHandle {
            id,
            tx,
            closed: closed.clone(),
        });
        BroadcastSink {
            rx,
            leftover: Vec::new(),
            closed,
        }
    }

    /// RemoveSink — close and unregister a sink so it no longer receives data
    /// (Go's `RemoveSink`, capture_broadcast.go:59-69). Identified by the
    /// `BroadcastSink`'s id (the reader half), matching the identity the pump
    /// uses internally. Safe to call concurrently with `run`.
    pub fn remove_sink(&self, sink: &BroadcastSink) {
        // Mark the reader-side closed so a blocked `write` errors out and the
        // pump drops it; also remove its handle eagerly.
        *sink.closed.lock().unwrap() = true;
        let mut sinks = self.shared.sinks.lock().unwrap();
        if let Some(pos) = sinks
            .iter()
            .position(|s| Arc::ptr_eq(&s.closed, &sink.closed))
        {
            sinks[pos].close();
            sinks.remove(pos);
        }
    }

    /// Internal removal-by-id used by the pump when a write fails.
    fn remove_sink_id(shared: &Shared, id: u64) {
        let mut sinks = shared.sinks.lock().unwrap();
        if let Some(pos) = sinks.iter().position(|s| s.id == id) {
            sinks[pos].close();
            sinks.remove(pos);
        }
    }

    /// Run — pump data from the underlying capture to all registered sinks until
    /// the capture ends. Returns the capture's terminating error (if any). Run
    /// this on a dedicated thread. Faithful port of Go's `BroadcastCapture.Run`.
    pub fn run(&self) -> Result<()> {
        let shared = self.shared.clone();
        let result = self.pump(&shared);

        // defer: close every remaining sink, then mark done (Go's deferred block).
        {
            let mut sinks = shared.sinks.lock().unwrap();
            for s in sinks.iter() {
                s.close();
            }
            sinks.clear();
        }
        if let Err(ref e) = result {
            *shared.err.lock().unwrap() = Some(e.to_string());
        }
        *shared.done.lock().unwrap() = true;
        shared.done_cv.notify_all();
        result
    }

    fn pump(&self, shared: &Shared) -> Result<()> {
        // Go uses a 256 KiB read buffer.
        let mut buf = vec![0u8; 256 * 1024];
        let mut src = self.src.lock().unwrap();
        loop {
            let n = src.read(&mut buf)?;
            if n > 0 {
                // Snapshot the live sink HANDLES under the lock, then release it
                // and write — `write` may block (back-pressure) and must not hold
                // the sinks lock, exactly like Go copies the slice before writing.
                let snapshot: Vec<SinkHandle> = {
                    let sinks = shared.sinks.lock().unwrap();
                    sinks.clone()
                };
                if snapshot.is_empty() {
                    // No active sinks; keep draining so capture never blocks.
                    continue;
                }
                let chunk = &buf[..n];
                for s in snapshot {
                    if s.write(chunk).is_err() {
                        // Sink is closed or broken; remove it.
                        Self::remove_sink_id(shared, s.id);
                    }
                }
            }
            // `CaptureSource::read` signals end-of-stream by returning 0 (it does
            // not return a separate trailing error like Go's io.Reader), so a
            // zero-length read ends the pump cleanly.
            if n == 0 {
                return Ok(());
            }
        }
    }

    /// Done — true once `run` has finished (Go's closed `done` channel).
    pub fn done(&self) -> bool {
        *self.shared.done.lock().unwrap()
    }

    /// WaitDone — block until `run` has finished, the awaitable analogue of
    /// Go's `Done() <-chan struct{}` (`<-bc.Done()`).
    pub fn wait_done(&self) {
        let mut done = self.shared.done.lock().unwrap();
        while !*done {
            done = self.shared.done_cv.wait(done).unwrap();
        }
    }

    /// Source — the underlying `CaptureSource` (Go's `Source()`). Returns the
    /// guard since the capture lives behind a mutex here.
    pub fn source(&self) -> std::sync::MutexGuard<'_, CaptureSource> {
        self.src.lock().unwrap()
    }

    /// Err — the error that caused `run` to exit, or None if still running /
    /// finished cleanly (Go's `Err`).
    pub fn err(&self) -> Option<String> {
        if *self.shared.done.lock().unwrap() {
            self.shared.err.lock().unwrap().clone()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::{self, Receiver, Sender};

    /// A minimal in-memory source that satisfies the same `read` contract as
    /// `CaptureSource` (fills buf, 0 == EOF), used to exercise the fan-out logic
    /// without GStreamer. The fan-out semantics are identical regardless of the
    /// concrete source.
    struct MemSource {
        rx: Receiver<Vec<u8>>,
        leftover: Vec<u8>,
    }

    impl MemSource {
        fn new() -> (MemSource, Sender<Vec<u8>>) {
            let (tx, rx) = mpsc::channel();
            (
                MemSource {
                    rx,
                    leftover: Vec::new(),
                },
                tx,
            )
        }
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            if self.leftover.is_empty() {
                match self.rx.recv() {
                    Ok(chunk) if chunk.is_empty() => return Ok(0), // EOF marker
                    Ok(chunk) => self.leftover = chunk,
                    Err(_) => return Ok(0),
                }
            }
            let n = buf.len().min(self.leftover.len());
            buf[..n].copy_from_slice(&self.leftover[..n]);
            self.leftover.drain(..n);
            Ok(n)
        }
    }

    // A parallel BroadcastCapture wired to MemSource (a copy of the fan-out core
    // that proves one source reaches two sinks identically). It reuses the real
    // Shared / SinkHandle / BroadcastSink machinery; only the source type differs.
    struct MemBroadcast {
        src: Mutex<MemSource>,
        shared: Arc<Shared>,
    }

    impl MemBroadcast {
        fn new(src: MemSource) -> MemBroadcast {
            MemBroadcast {
                src: Mutex::new(src),
                shared: Arc::new(Shared {
                    sinks: Mutex::new(Vec::new()),
                    done: Mutex::new(false),
                    done_cv: Condvar::new(),
                    err: Mutex::new(None),
                    next_id: Mutex::new(0),
                }),
            }
        }
        fn add_sink(&self) -> BroadcastSink {
            let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(SINK_CHANNEL_CAP);
            let closed = Arc::new(Mutex::new(false));
            let id = {
                let mut n = self.shared.next_id.lock().unwrap();
                let id = *n;
                *n += 1;
                id
            };
            self.shared.sinks.lock().unwrap().push(SinkHandle {
                id,
                tx,
                closed: closed.clone(),
            });
            BroadcastSink {
                rx,
                leftover: Vec::new(),
                closed,
            }
        }
        fn run(&self) {
            let shared = self.shared.clone();
            let mut buf = vec![0u8; 256 * 1024];
            loop {
                let n = { self.src.lock().unwrap().read(&mut buf).unwrap() };
                if n > 0 {
                    let snapshot: Vec<SinkHandle> =
                        shared.sinks.lock().unwrap().clone();
                    let chunk = &buf[..n];
                    for s in snapshot {
                        if s.write(chunk).is_err() {
                            BroadcastCapture::remove_sink_id(&shared, s.id);
                        }
                    }
                }
                if n == 0 {
                    break;
                }
            }
            let mut sinks = shared.sinks.lock().unwrap();
            for s in sinks.iter() {
                s.close();
            }
            sinks.clear();
            *shared.done.lock().unwrap() = true;
            shared.done_cv.notify_all();
        }
    }

    /// `BroadcastSink` must be usable as a `mirror::FrameSource` so the daemon
    /// can hand one shared capture's sink to a mirror in place of a CaptureSource.
    /// Drives a real BroadcastSink through `&mut dyn FrameSource` end to end.
    #[test]
    fn broadcast_sink_is_a_frame_source() {
        use crate::mirror::FrameSource;

        let (src, feed) = MemSource::new();
        let bc = Arc::new(MemBroadcast::new(src));
        let sink = bc.add_sink();

        std::thread::spawn(move || {
            feed.send(b"frame-source bytes".to_vec()).unwrap();
            feed.send(Vec::new()).unwrap(); // EOF
        });

        let bc_run = bc.clone();
        let pump = std::thread::spawn(move || bc_run.run());

        // Consume the sink purely through the trait object.
        let mut fs: Box<dyn FrameSource> = Box::new(sink);
        let mut out = Vec::new();
        let mut buf = [0u8; 5];
        loop {
            let n = fs.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        pump.join().unwrap();
        assert_eq!(out, b"frame-source bytes");
    }

    /// 1-source → 2-mirror wiring smoke test: one BroadcastCapture fans to two
    /// `BroadcastSink`s, each consumed as an independent `Box<dyn FrameSource>`
    /// (as the daemon hands them to two `run_mirror_with_source` calls). Both
    /// trait objects must observe the identical full byte stream, then EOF.
    #[test]
    fn one_source_to_two_frame_source_mirrors() {
        use crate::mirror::FrameSource;

        let (src, feed) = MemSource::new();
        let bc = Arc::new(MemBroadcast::new(src));
        let s1: Box<dyn FrameSource> = Box::new(bc.add_sink());
        let s2: Box<dyn FrameSource> = Box::new(bc.add_sink());

        std::thread::spawn(move || {
            feed.send(b"00 00 00 01 ".to_vec()).unwrap();
            feed.send(b"SPS PPS IDR".to_vec()).unwrap();
            feed.send(Vec::new()).unwrap(); // EOF
        });

        let bc_run = bc.clone();
        let pump = std::thread::spawn(move || bc_run.run());

        fn drain_fs(mut fs: Box<dyn FrameSource>) -> Vec<u8> {
            let mut out = Vec::new();
            let mut buf = [0u8; 4];
            loop {
                let n = fs.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
            }
            out
        }

        let h1 = std::thread::spawn(move || drain_fs(s1));
        let h2 = std::thread::spawn(move || drain_fs(s2));
        let got1 = h1.join().unwrap();
        let got2 = h2.join().unwrap();
        pump.join().unwrap();

        assert_eq!(got1, b"00 00 00 01 SPS PPS IDR");
        assert_eq!(got2, b"00 00 00 01 SPS PPS IDR");
    }

    /// One source fans out to two sinks: both sinks must receive the identical
    /// full byte stream, then EOF.
    #[test]
    fn one_source_fans_to_two_sinks() {
        let (src, feed) = MemSource::new();
        let bc = Arc::new(MemBroadcast::new(src));

        let mut sink1 = bc.add_sink();
        let mut sink2 = bc.add_sink();

        // Feed three chunks then an EOF marker, on a separate thread.
        std::thread::spawn(move || {
            feed.send(b"hello ".to_vec()).unwrap();
            feed.send(b"broadcast ".to_vec()).unwrap();
            feed.send(b"world".to_vec()).unwrap();
            feed.send(Vec::new()).unwrap(); // EOF
        });

        let bc_run = bc.clone();
        let pump = std::thread::spawn(move || bc_run.run());

        // Drain a sink to EOF into a single Vec.
        fn drain(sink: &mut BroadcastSink) -> Vec<u8> {
            let mut out = Vec::new();
            let mut buf = [0u8; 4];
            loop {
                let n = sink.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
            }
            out
        }

        let h1 = std::thread::spawn(move || {
            let got = drain(&mut sink1);
            got
        });
        let h2 = std::thread::spawn(move || {
            let got = drain(&mut sink2);
            got
        });

        let got1 = h1.join().unwrap();
        let got2 = h2.join().unwrap();
        pump.join().unwrap();

        assert_eq!(got1, b"hello broadcast world");
        assert_eq!(got2, b"hello broadcast world");
        assert!(bc.shared.done.lock().unwrap().clone());
    }
}
