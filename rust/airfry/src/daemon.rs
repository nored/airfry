//! AirFry control daemon — a faithful Rust port of doubletake's
//! `internal/daemon/daemon.go`.
//!
//! A long-running service that:
//!   * listens on a Unix domain socket (default
//!     `$XDG_RUNTIME_DIR/airfry.sock`), 0700 dir + socket, stale socket removed
//!     on start and cleaned up on shutdown;
//!   * runs continuous background mDNS discovery (rolling ~5s scans, devices
//!     aged out after 30s) via `crate::discovery::discover`;
//!   * maintains a lifecycle `State` machine (idle / discovering / connecting /
//!     streaming / pin_required) and a per-target stream registry;
//!   * fans out to several Apple TVs at once, one mirror worker per target;
//!   * speaks newline/length-delimited JSON over the socket (the exact request
//!     /response shape `daemonclient` uses).
//!
//! Protocol parity with daemon.go: the `Request`/`Response`/`DeviceInfo`/
//! `StreamInfo` serde structs use the identical JSON field names, so the Rust
//! `airfry-ctl` and a Go `doubletake-ctl` are wire-compatible.
//!
//! Shared screen capture (daemon.go getOrStartBroadcastLocked): all targets are
//! fanned out from ONE screen capture. The first `connect` lazily starts a single
//! `CaptureSource`, wraps it in a `BroadcastCapture`, and spawns a pump thread.
//! Each target then gets its own `BroadcastSink` (`add_sink`) and runs through
//! `mirror::run_mirror_with_source(.., Some(sink))`, consuming that fan-out byte
//! stream instead of building its own capture. The shared capture is reference-
//! counted by the live stream set: when the LAST stream ends the capture is
//! stopped and cleared, so a later `connect` starts a fresh one. Audio stays
//! per-stream — `run_mirror_with_source` keeps each stream's own audio capture;
//! only video is shared (matching Go, which shares only the `BroadcastCapture`).

#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use crate::broadcast::BroadcastCapture;
use crate::capture::{CaptureConfig, CaptureSource, CaptureStopHandle};
use crate::discovery::{self, AirPlayDevice};
use crate::mirror::{self, MirrorControl, MirrorOpts};
use crate::rtsp::Session;

// Wire protocol + state-string constants live in `protocol.rs` (no heavy deps)
// so the lightweight `airfry-ctl` can share them. Re-export for callers that
// `use crate::daemon::{Request, Response, ...}` (daemon.go keeps these in the
// daemon package).
pub use crate::protocol::{
    default_socket_path, DeviceInfo, Request, Response, StreamInfo, STATE_CONNECTING,
    STATE_IDLE, STATE_PIN_REQUIRED, STATE_STREAMING,
};
// Re-export the discovering state too for completeness (unused internally; the
// daemon never sits in `discovering` since background discovery is continuous).
#[allow(unused_imports)]
pub use crate::protocol::STATE_DISCOVERING;

// ---------------------------------------------------------------------------
// Active stream registry (daemon.go activeStream)
// ---------------------------------------------------------------------------

/// Tracks the state of a single mirroring session to one receiver
/// (daemon.go activeStream). The `control` handle stops the worker and
/// mutes/unmutes its audio at runtime; the worker thread owns the actual
/// `Session`/capture and tears them down when `control.stop()` is observed.
struct ActiveStream {
    device: String,   // friendly name
    device_ip: String,
    device_id: String,
    state: &'static str,
    audio_muted: bool,
    has_audio: bool,
    /// Stop + mute control for the running mirror worker (daemon.go's
    /// session/client/cancelFn rolled into one handle here).
    control: MirrorControl,
    /// Sender that delivers a later `pin` command to a worker parked waiting
    /// for the on-screen PIN. `None` once pairing has progressed past the PIN
    /// prompt. This is the channel-based analogue of daemon.go's
    /// pendingTarget/pendingPort park-and-resume.
    pin_tx: Option<Sender<Option<String>>>,
    /// True once this stream has registered a fan-out sink on the shared capture
    /// (daemon.go activeStream.sink != nil). The worker thread owns the live
    /// `BroadcastSink` it reads; the daemon does not hold it. Teardown is driven
    /// by `control.stop()` (which ends `run_mirror_with_source`, dropping the
    /// sink — `BroadcastSink::Drop` marks it closed so the pump prunes it, the
    /// `entry.sink.Close()` analogue) plus `maybe_stop_broadcast_locked` to stop
    /// the shared capture once the last stream is gone. This flag exists only so
    /// the bookkeeping reads close to daemon.go.
    has_sink: bool,
}

// ---------------------------------------------------------------------------
// Daemon configuration (daemon.go Config, trimmed to what the Rust mirror uses)
// ---------------------------------------------------------------------------

/// Daemon configuration. Mirrors the subset of daemon.go Config the Rust
/// mirror/capture path actually consumes.
#[derive(Debug, Clone)]
pub struct Config {
    pub socket_path: PathBuf,
    pub fps: u32,
    pub bitrate_kbps: u32,
    pub force_software: bool,
    pub no_encrypt: bool,
    pub direct_key: bool,
    pub no_audio: bool,
    pub test_mode: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            socket_path: default_socket_path(),
            fps: 30,
            bitrate_kbps: 0,
            force_software: false,
            no_encrypt: false,
            direct_key: false,
            no_audio: false,
            test_mode: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Daemon
// ---------------------------------------------------------------------------

/// Shared, mutex-guarded daemon state (daemon.go Daemon's `mu`-guarded fields).
struct Inner {
    cfg: Config,
    devices: Vec<AirPlayDevice>,
    /// last-seen wall-clock instant keyed by IP (daemon.go deviceLastSeen).
    device_last_seen: HashMap<String, Instant>,
    /// Active/connecting streams keyed by target IP (daemon.go streams).
    streams: HashMap<String, ActiveStream>,
    /// At most one device parks waiting for a PIN at a time (daemon.go
    /// pendingTarget/pendingPort).
    pending_target: String,
    pending_port: i32,
    /// The single shared screen-capture fan-out feeding every target
    /// (daemon.go `broadcast`). Created lazily on the first stream that reaches
    /// the streaming phase and cleared when the last stream ends. The pump runs
    /// on its own thread (spawned in `get_or_start_broadcast`).
    broadcast: Option<Arc<BroadcastCapture>>,
    /// A detached stop handle for the shared capture's underlying GStreamer
    /// pipeline (daemon.go `capture` + `captureCancel`, rolled into one). Lets
    /// `maybe_stop_broadcast_locked` tear the capture down — and thereby end the
    /// pump's blocking read — without taking the pump's source mutex.
    capture_stop: Option<CaptureStopHandle>,
}

/// A long-running AirFry service. Construct with `Daemon::new`, then call
/// `run` (or use the free `run` function for the common case).
pub struct Daemon {
    inner: Mutex<Inner>,
    /// Set on shutdown; the accept loop and background discovery observe it.
    shutdown: AtomicBool,
    /// Woken when shutdown is requested so the discovery loop can exit promptly.
    shutdown_cv: Condvar,
}

impl Daemon {
    /// Create a new daemon with the given configuration (daemon.go New).
    pub fn new(cfg: Config) -> Arc<Daemon> {
        Arc::new(Daemon {
            inner: Mutex::new(Inner {
                cfg,
                devices: Vec::new(),
                device_last_seen: HashMap::new(),
                streams: HashMap::new(),
                pending_target: String::new(),
                pending_port: 0,
                broadcast: None,
                capture_stop: None,
            }),
            shutdown: AtomicBool::new(false),
            shutdown_cv: Condvar::new(),
        })
    }

    /// Start the control socket + background discovery and block serving
    /// requests until shutdown (daemon.go Run). Cleans up the socket on exit.
    pub fn run(self: &Arc<Self>) -> Result<()> {
        let socket_path = self.inner.lock().unwrap().cfg.socket_path.clone();

        // Ensure the parent directory exists and is owner-only (0700). For the
        // default $XDG_RUNTIME_DIR it already is; we only tighten it.
        if let Some(dir) = socket_path.parent() {
            std::fs::create_dir_all(dir).ok();
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).ok();
        }

        // Clean up a stale socket (daemon.go os.Remove + IsNotExist check).
        match std::fs::remove_file(&socket_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).context("remove stale socket"),
        }

        let listener = UnixListener::bind(&socket_path)
            .with_context(|| format!("listen {}", socket_path.display()))?;
        // Owner-only permissions on the socket (daemon.go chmod 0700).
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o700))
            .context("chmod socket")?;

        crate::dlog!("[daemon] listening on {}", socket_path.display());

        // Background mDNS discovery.
        {
            let me = self.clone();
            thread::spawn(move || me.background_discover());
        }

        // Accept loop. Each connection is one request/response (daemon.go's
        // per-conn goroutine).
        for conn in listener.incoming() {
            if self.shutdown.load(Ordering::Acquire) {
                break;
            }
            match conn {
                Ok(stream) => {
                    let me = self.clone();
                    thread::spawn(move || me.handle_conn(stream));
                }
                Err(e) => {
                    if self.shutdown.load(Ordering::Acquire) {
                        break;
                    }
                    crate::dlog!("[daemon] accept error: {e}");
                    continue;
                }
            }
        }

        self.cleanup(&socket_path);
        Ok(())
    }

    /// Stop active sessions, wake the discovery loop and remove the socket
    /// (daemon.go Shutdown). Calling `run` again is not supported after this.
    pub fn shutdown(self: &Arc<Self>) {
        self.shutdown.store(true, Ordering::Release);
        self.shutdown_cv.notify_all();
        let mut inner = self.inner.lock().unwrap();
        Self::stop_all_locked(&mut inner);
        let path = inner.cfg.socket_path.clone();
        drop(inner);
        // Nudge the accept loop out of `incoming()` by connecting once.
        let _ = UnixStream::connect(&path);
        let _ = std::fs::remove_file(&path);
    }

    fn cleanup(&self, socket_path: &PathBuf) {
        let mut inner = self.inner.lock().unwrap();
        Self::stop_all_locked(&mut inner);
        drop(inner);
        let _ = std::fs::remove_file(socket_path);
    }

    // -----------------------------------------------------------------------
    // Background discovery (daemon.go backgroundDiscover)
    // -----------------------------------------------------------------------

    /// Continuously browse mDNS for AirPlay receivers. Each scan runs for ~5s;
    /// devices not seen for >30s are removed (daemon.go backgroundDiscover).
    fn background_discover(self: &Arc<Self>) {
        const SCAN_DURATION: Duration = Duration::from_secs(5);
        const DEVICE_TTL: Duration = Duration::from_secs(30);

        crate::dlog!("[daemon] starting continuous mDNS discovery");
        loop {
            if self.shutdown.load(Ordering::Acquire) {
                return;
            }

            let found = discovery::discover(SCAN_DURATION);

            if self.shutdown.load(Ordering::Acquire) {
                return;
            }

            let now = Instant::now();
            let mut inner = self.inner.lock().unwrap();
            match found {
                Ok(found) => {
                    // Known devices by IP (daemon.go's `known` map).
                    let mut known: HashMap<String, AirPlayDevice> = HashMap::new();
                    for dev in &inner.devices {
                        known.insert(dev.ip.clone(), dev.clone());
                    }
                    // Update last-seen + merge.
                    for dev in found {
                        inner.device_last_seen.insert(dev.ip.clone(), now);
                        known.insert(dev.ip.clone(), dev);
                    }
                    // Rebuild, dropping anything older than the TTL.
                    let mut devices: Vec<AirPlayDevice> = Vec::with_capacity(known.len());
                    let mut drop_ips: Vec<String> = Vec::new();
                    for (ip, dev) in known {
                        let last = inner
                            .device_last_seen
                            .get(&ip)
                            .copied()
                            .unwrap_or(now);
                        if now.duration_since(last) <= DEVICE_TTL {
                            devices.push(dev);
                        } else {
                            drop_ips.push(ip);
                        }
                    }
                    for ip in drop_ips {
                        inner.device_last_seen.remove(&ip);
                    }
                    devices.sort_by(|a, b| a.ip.cmp(&b.ip));
                    inner.devices = devices;
                }
                Err(e) => {
                    crate::dlog!("[daemon] mDNS browse error: {e}");
                }
            }
            drop(inner);
            // The 5s scan IS the cadence (daemon.go: no extra wait).
        }
    }

    // -----------------------------------------------------------------------
    // Connection handling (daemon.go handleConn / handleRequest)
    // -----------------------------------------------------------------------

    fn handle_conn(self: &Arc<Self>, stream: UnixStream) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));

        let mut reader = BufReader::new(match stream.try_clone() {
            Ok(s) => s,
            Err(_) => return,
        });
        let mut writer = stream;

        // Go's json.Decoder reads exactly one JSON value off the stream; the
        // client writes one newline-terminated value (json.Encoder appends a
        // '\n'), so a line read recovers it. Fall back to reading to EOF if no
        // newline arrives but bytes are present (length-delimited single value).
        let mut line = String::new();
        let req: Request = match reader.read_line(&mut line) {
            Ok(0) => return,
            Ok(_) => match serde_json::from_str(line.trim_end()) {
                Ok(r) => r,
                Err(e) => {
                    let _ = write_response(
                        &mut writer,
                        &Response {
                            ok: false,
                            error: format!("invalid request: {e}"),
                            ..Default::default()
                        },
                    );
                    return;
                }
            },
            Err(_) => return,
        };

        let resp = self.handle_request(req);
        let _ = write_response(&mut writer, &resp);
    }

    fn handle_request(self: &Arc<Self>, req: Request) -> Response {
        match req.cmd.as_str() {
            "status" => self.handle_status(),
            "discover" => self.handle_discover(),
            "devices" => self.handle_devices(),
            "connect" => self.handle_connect(req),
            "pin" => self.handle_pin(req),
            "disconnect" => self.handle_disconnect(req),
            "mute" => self.handle_set_mute(req, true),
            "unmute" => self.handle_set_mute(req, false),
            other => Response {
                ok: false,
                error: format!("unknown command: {other}"),
                ..Default::default()
            },
        }
    }

    // -----------------------------------------------------------------------
    // State aggregation (daemon.go overallStateLocked / statusResponseLocked)
    // -----------------------------------------------------------------------

    /// Aggregate daemon state from the active streams + pending PIN
    /// (daemon.go overallStateLocked). Must be called with `inner` held.
    fn overall_state_locked(inner: &Inner) -> &'static str {
        if !inner.pending_target.is_empty() {
            return STATE_PIN_REQUIRED;
        }
        let mut has_streaming = false;
        let mut has_connecting = false;
        for s in inner.streams.values() {
            match s.state {
                STATE_STREAMING => has_streaming = true,
                STATE_CONNECTING => has_connecting = true,
                _ => {}
            }
        }
        if has_streaming {
            STATE_STREAMING
        } else if has_connecting {
            STATE_CONNECTING
        } else {
            STATE_IDLE
        }
    }

    /// Build a full status response (daemon.go statusResponseLocked). Must be
    /// called with `inner` held.
    fn status_response_locked(inner: &Inner, ok: bool, err_msg: &str) -> Response {
        let mut streams: Vec<StreamInfo> = inner
            .streams
            .values()
            .map(|s| StreamInfo {
                device: s.device.clone(),
                device_ip: s.device_ip.clone(),
                state: s.state.to_string(),
                has_audio: s.has_audio,
                audio_muted: s.audio_muted,
            })
            .collect();
        // Deterministic output (daemon.go sorts by DeviceIP).
        streams.sort_by(|a, b| a.device_ip.cmp(&b.device_ip));

        let overall = Self::overall_state_locked(inner);

        // Legacy single-stream fields: first streaming entry (daemon.go).
        let mut device = String::new();
        let mut device_ip = String::new();
        let mut has_audio = false;
        let mut audio_muted = false;
        for s in &streams {
            if s.state == STATE_STREAMING {
                device = s.device.clone();
                device_ip = s.device_ip.clone();
                has_audio = s.has_audio;
                audio_muted = s.audio_muted;
                break;
            }
        }

        Response {
            ok,
            state: overall.to_string(),
            device,
            device_ip,
            has_audio,
            audio_muted,
            needs_pin: overall == STATE_PIN_REQUIRED,
            error: err_msg.to_string(),
            devices: None,
            streams: Some(streams),
        }
    }

    fn handle_status(self: &Arc<Self>) -> Response {
        let inner = self.inner.lock().unwrap();
        Self::status_response_locked(&inner, true, "")
    }

    fn handle_discover(self: &Arc<Self>) -> Response {
        let inner = self.inner.lock().unwrap();
        Response {
            ok: true,
            state: Self::overall_state_locked(&inner).to_string(),
            devices: Some(to_device_infos(&inner.devices)),
            ..Default::default()
        }
    }

    fn handle_devices(self: &Arc<Self>) -> Response {
        let inner = self.inner.lock().unwrap();
        Response {
            ok: true,
            state: Self::overall_state_locked(&inner).to_string(),
            devices: Some(to_device_infos(&inner.devices)),
            ..Default::default()
        }
    }

    // -----------------------------------------------------------------------
    // connect (daemon.go handleConnect) + pin resume (daemon.go handleConnect
    // pending-target branch, surfaced here as the dedicated `pin` command)
    // -----------------------------------------------------------------------

    fn handle_connect(self: &Arc<Self>, req: Request) -> Response {
        let mut inner = self.inner.lock().unwrap();

        // daemon.go: a `connect` carrying a PIN while a target is parked resumes
        // that target. We honour the same shape (so a Go ctl's `pin` -> connect
        // {pin} works), and also expose it as the explicit `pin` command.
        if !inner.pending_target.is_empty() && !req.pin.is_empty() {
            return self.resume_pending_locked(inner, req.pin);
        }

        // Reject a duplicate connection to the same target (daemon.go).
        let mut target = req.target.clone();
        if !target.is_empty() {
            if let Some(existing) = inner.streams.get(&target) {
                let st = existing.state;
                return Response {
                    ok: false,
                    state: st.to_string(),
                    error: format!("already connected or connecting to {target}"),
                    ..Default::default()
                };
            }
        }

        // No target -> first cached device not already streaming (daemon.go
        // pickFreeDeviceLocked).
        let mut port = req.port;
        if target.is_empty() {
            match Self::pick_free_device_locked(&inner, port) {
                Some((t, p)) => {
                    target = t;
                    port = p;
                }
                None => {
                    return Response {
                        ok: false,
                        state: Self::overall_state_locked(&inner).to_string(),
                        error: "no available devices found".to_string(),
                        ..Default::default()
                    };
                }
            }
        }

        // Resolve the discovered port if not explicitly provided (daemon.go).
        if port == 0 {
            for dev in &inner.devices {
                if dev.ip == target {
                    port = dev.port as i32;
                    break;
                }
            }
        }
        if port == 0 {
            port = 7000;
        }

        // Register a connecting placeholder + its control handle (daemon.go).
        let control = MirrorControl::new();
        inner.streams.insert(
            target.clone(),
            ActiveStream {
                device: String::new(),
                device_ip: target.clone(),
                device_id: String::new(),
                state: STATE_CONNECTING,
                audio_muted: false,
                has_audio: false,
                control: control.clone(),
                pin_tx: None,
                has_sink: false,
            },
        );
        let overall = Self::overall_state_locked(&inner).to_string();
        drop(inner);

        self.spawn_connect_worker(target.clone(), port, req.pin);

        Response {
            ok: true,
            state: overall,
            device: target,
            ..Default::default()
        }
    }

    /// Explicit `pin` command: supply the on-screen code for the parked target
    /// (daemon.go handleConnect's pending branch). Faithful to the
    /// StatePINRequired resume flow.
    fn handle_pin(self: &Arc<Self>, req: Request) -> Response {
        let inner = self.inner.lock().unwrap();
        if inner.pending_target.is_empty() {
            return Response {
                ok: false,
                state: Self::overall_state_locked(&inner).to_string(),
                error: "no device is waiting for a PIN".to_string(),
                ..Default::default()
            };
        }
        if req.pin.is_empty() {
            return Response {
                ok: false,
                state: Self::overall_state_locked(&inner).to_string(),
                error: "pin required".to_string(),
                ..Default::default()
            };
        }
        self.resume_pending_locked(inner, req.pin)
    }

    /// Resume the parked target with the supplied PIN. Must be called holding
    /// the `inner` guard, which it consumes. Mirrors daemon.go: clears
    /// pendingTarget/pendingPort and delivers the code to the parked worker
    /// (here via the worker's pin channel) so it completes pairing in place.
    fn resume_pending_locked(
        self: &Arc<Self>,
        mut inner: std::sync::MutexGuard<'_, Inner>,
        pin: String,
    ) -> Response {
        let target = std::mem::take(&mut inner.pending_target);
        inner.pending_port = 0;

        // The parked worker registered a connecting entry holding a pin channel
        // when it hit the PIN prompt; hand it the code to resume in place.
        if let Some(entry) = inner.streams.get_mut(&target) {
            if let Some(tx) = entry.pin_tx.take() {
                let _ = tx.send(Some(pin));
                let overall = Self::overall_state_locked(&inner).to_string();
                return Response {
                    ok: true,
                    state: overall,
                    device: target,
                    ..Default::default()
                };
            }
        }

        // No parked worker channel (shouldn't happen): re-park and report.
        inner.pending_target = target.clone();
        Response {
            ok: false,
            state: STATE_PIN_REQUIRED.to_string(),
            error: format!("internal: lost the worker waiting for {target}'s PIN"),
            ..Default::default()
        }
    }

    /// First discovered device not already in `streams` (daemon.go
    /// pickFreeDeviceLocked). Must be called with `inner` held.
    fn pick_free_device_locked(inner: &Inner, preferred_port: i32) -> Option<(String, i32)> {
        for dev in &inner.devices {
            if !inner.streams.contains_key(&dev.ip) {
                let p = if preferred_port != 0 {
                    preferred_port
                } else {
                    dev.port as i32
                };
                return Some((dev.ip.clone(), p));
            }
        }
        None
    }

    // -----------------------------------------------------------------------
    // The per-target mirror worker (daemon.go connectAndStream)
    // -----------------------------------------------------------------------

    /// Spawn the worker that pairs + streams to `target` (daemon.go
    /// connectAndStream). Pairing uses `Session::connect_host_with`, whose
    /// `pin_provider` callback is invoked exactly when the receiver requires an
    /// on-screen code — that is the moment the daemon parks `pendingTarget` and
    /// blocks the worker until a later `pin` command supplies the code.
    fn spawn_connect_worker(self: &Arc<Self>, target: String, port: i32, pin: String) {
        let me = self.clone();
        thread::spawn(move || {
            me.connect_and_stream(target, port, pin);
        });
    }

    fn connect_and_stream(self: &Arc<Self>, target: String, port: i32, pin: String) {
        // Pull the control handle + config for this stream.
        let (control, cfg) = {
            let inner = self.inner.lock().unwrap();
            match inner.streams.get(&target) {
                Some(s) => (s.control.clone(), inner.cfg.clone()),
                None => return, // cancelled before we started
            }
        };

        // pin_provider: when the receiver rejects PIN-less pairing, the rtsp
        // layer calls this to obtain the displayed code. We register a pin
        // channel on the stream entry, transition the daemon into
        // pin_required (daemon.go pendingTarget), and block until the `pin`
        // command delivers the code (or aborts). This is the faithful Rust
        // shape of daemon.go's park-and-resume across the StatePINRequired
        // boundary — collapsed into a single in-place worker because the rtsp
        // cascade resumes pairing on a fresh socket internally.
        let (pin_tx, pin_rx): (Sender<Option<String>>, Receiver<Option<String>>) =
            std::sync::mpsc::channel();
        let me_for_pin = self.clone();
        let target_for_pin = target.clone();
        let mut already_parked = false;
        let mut pin_provider = move || -> Option<String> {
            if !already_parked {
                already_parked = true;
                let mut inner = me_for_pin.inner.lock().unwrap();
                inner.pending_target = target_for_pin.clone();
                inner.pending_port = port;
                if let Some(entry) = inner.streams.get_mut(&target_for_pin) {
                    entry.pin_tx = Some(pin_tx.clone());
                }
                crate::dlog!(
                    "[daemon] PIN required for {target_for_pin} — waiting for user input"
                );
            }
            // Block until `pin`/`disconnect` delivers a code (or None to abort).
            match pin_rx.recv() {
                Ok(code) => code,
                Err(_) => None,
            }
        };

        let mut report = |phase: &str, ok: bool, detail: &str| {
            let mark = if ok { "ok" } else { "FAIL" };
            crate::dlog!("[daemon] [{mark}] {phase}: {detail}");
        };

        let session = match Session::connect_host_with(
            &target,
            port as u16,
            &pin,
            &crate::rtsp::ConnectOptions::default(),
            &mut pin_provider,
            &mut report,
        ) {
            Ok(s) => s,
            Err(e) => {
                crate::dlog!("[daemon] connect to {target}:{port} failed: {e:#}");
                self.remove_stream(&target);
                return;
            }
        };

        // Obtain or lazily start the shared screen capture and register a new
        // fan-out sink for this target (daemon.go getOrStartBroadcastLocked).
        // This is the single capture shared by every receiver; the first stream
        // to get here starts it, later streams just add a sink. Must be called
        // WITHOUT the daemon lock held (it does its own locking and spawns the
        // pump thread), exactly like Go.
        let sink = match self.get_or_start_broadcast(&cfg) {
            Ok(sink) => sink,
            Err(e) => {
                crate::dlog!("[daemon] capture failed for {target}: {e:#}");
                self.remove_stream(&target);
                return;
            }
        };

        // Record device identity + flip to streaming (daemon.go: entry.device,
        // deviceID, state = StateStreaming, sink, has_audio). If the stream was
        // cancelled while we were setting up, drop the sink and possibly stop the
        // now-orphaned shared capture (daemon.go's cancelled-during-setup branch).
        let has_audio = !cfg.no_audio;
        {
            let mut inner = self.inner.lock().unwrap();
            // Clear any lingering pending-PIN state now that pairing succeeded.
            if inner.pending_target == target {
                inner.pending_target.clear();
                inner.pending_port = 0;
            }
            match inner.streams.get_mut(&target) {
                Some(entry) => {
                    entry.device = if session.info.name.is_empty() {
                        target.clone()
                    } else {
                        session.info.name.clone()
                    };
                    entry.device_id = session.info.device_id.clone();
                    entry.state = STATE_STREAMING;
                    entry.has_audio = has_audio;
                    entry.pin_tx = None;
                    entry.has_sink = true;
                }
                None => {
                    // Cancelled while we were pairing/setting up — drop the sink
                    // and tear down the shared capture if it is now orphaned
                    // (daemon.go: sink.Close(); maybeStopBroadcastLocked()).
                    drop(sink);
                    Self::maybe_stop_broadcast_locked(&mut inner);
                    return;
                }
            }
        }

        crate::dlog!("[daemon] streaming to {target}");

        // Build mirror options from config (daemon.go StreamConfig).
        let opts = MirrorOpts {
            bitrate_kbps: cfg.bitrate_kbps,
            fps: cfg.fps,
            force_software_encoder: cfg.force_software,
            no_encrypt: cfg.no_encrypt,
            no_audio: cfg.no_audio,
            direct_key: cfg.direct_key,
            test: cfg.test_mode,
            ..Default::default()
        };

        // Run the mirror against the SHARED capture's fan-out sink (daemon.go's
        // StreamFrames(sink.AsCapture())) rather than building a private capture.
        // Audio stays per-stream: run_mirror_with_source keeps this stream's own
        // audio capture; only video is shared. The control handle's stop flag
        // drives shutdown; its mute state is honoured live by mute/unmute.
        let result =
            mirror::run_mirror_with_source(session, opts, control, Some(Box::new(sink)));
        if let Err(e) = result {
            if !self
                .inner
                .lock()
                .unwrap()
                .streams
                .get(&target)
                .map(|s| s.control.stop_flag().load(Ordering::Relaxed))
                .unwrap_or(true)
            {
                crate::dlog!("[daemon] stream error for {target}: {e:#}");
            }
        }

        // Cleanup this stream (daemon.go removeStreamLocked).
        self.remove_stream(&target);
        crate::dlog!("[daemon] stream ended for {target}");
    }

    /// Remove a single stream entry, stopping its worker, and tear down the
    /// shared capture if no other streams remain (daemon.go removeStreamLocked,
    /// which calls maybeStopBroadcastLocked).
    fn remove_stream(self: &Arc<Self>, target: &str) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(entry) = inner.streams.remove(target) {
            entry.control.stop();
            // Wake a parked PIN wait so the worker unblocks and exits.
            if let Some(tx) = entry.pin_tx {
                let _ = tx.send(None);
            }
        }
        if inner.pending_target == target {
            inner.pending_target.clear();
            inner.pending_port = 0;
        }
        Self::maybe_stop_broadcast_locked(&mut inner);
    }

    // -----------------------------------------------------------------------
    // Shared screen capture lifecycle (daemon.go getOrStartBroadcastLocked /
    // maybeStopBroadcastLocked) — ONE capture fanned out to N receivers.
    // -----------------------------------------------------------------------

    /// Ensure the single shared `BroadcastCapture` is running and return a fresh
    /// fan-out sink registered with it (daemon.go getOrStartBroadcastLocked).
    /// Must NOT be called with the daemon lock held.
    ///
    /// If a capture is already running, this just adds a sink. Otherwise it
    /// starts a fresh `CaptureSource`, wraps it in a `BroadcastCapture`, spawns
    /// the pump thread, and stores both the broadcast and a detached stop handle
    /// in daemon state. A double-check after building (mirroring Go) discards a
    /// race-built capture if another worker won.
    fn get_or_start_broadcast(self: &Arc<Self>, cfg: &Config) -> Result<crate::broadcast::BroadcastSink> {
        // Fast path: a capture is already running — add a sink (daemon.go).
        {
            let inner = self.inner.lock().unwrap();
            if let Some(bc) = &inner.broadcast {
                return Ok(bc.add_sink());
            }
        }

        // Start a fresh screen capture outside the lock (daemon.go: capture is
        // built before re-acquiring d.mu).
        let cap_cfg = CaptureConfig {
            fps: cfg.fps,
            bitrate_kbps: cfg.bitrate_kbps,
            fit_pct: 0,
            live_underscan: false,
            force_software: cfg.force_software,
            test: cfg.test_mode,
            restore_token: None,
            on_restore_token: None,
        };
        let capture = CaptureSource::start(&cap_cfg).context("start shared screen capture")?;
        // Grab a detached stop handle BEFORE moving the capture into the
        // broadcast (the pump holds the source behind a mutex for its whole
        // life, so this is the only way to stop it later — see CaptureStopHandle).
        let stop_handle = capture.stop_handle();
        let new_bc = Arc::new(BroadcastCapture::new(capture));
        let sink = new_bc.add_sink();

        // Double-check: another worker may have started a capture concurrently
        // (daemon.go's re-check of d.broadcast). If so, discard ours.
        {
            let mut inner = self.inner.lock().unwrap();
            if let Some(existing) = &inner.broadcast {
                let existing_sink = existing.add_sink();
                drop(inner);
                // Tear down the capture we just built (its pump never started).
                drop(sink);
                stop_handle.stop();
                return Ok(existing_sink);
            }
            inner.broadcast = Some(new_bc.clone());
            inner.capture_stop = Some(stop_handle);
        }

        // Spawn the pump thread (daemon.go's `go newBC.Run()`). When the capture
        // ends — e.g. the portal grant is revoked or the last stream stops it —
        // stop every active stream (daemon.go's deferred stopAllLocked).
        let me = self.clone();
        let bc_run = new_bc;
        thread::spawn(move || {
            if let Err(e) = bc_run.run() {
                if e.to_string() != "EOF" {
                    crate::dlog!("[daemon] broadcast capture error: {e:#}");
                }
            }
            let mut inner = me.inner.lock().unwrap();
            Self::stop_all_locked(&mut inner);
        });

        Ok(sink)
    }

    /// Stop the shared capture if no active streams remain (daemon.go
    /// maybeStopBroadcastLocked). Must be called with `inner` held. Stopping the
    /// capture's pipeline ends the pump's blocking read, so `BroadcastCapture::run`
    /// returns and its thread finishes.
    fn maybe_stop_broadcast_locked(inner: &mut Inner) {
        if !inner.streams.is_empty() {
            return;
        }
        if let Some(stop) = inner.capture_stop.take() {
            stop.stop();
        }
        inner.broadcast = None;
    }

    // -----------------------------------------------------------------------
    // disconnect (daemon.go handleDisconnect)
    // -----------------------------------------------------------------------

    fn handle_disconnect(self: &Arc<Self>, req: Request) -> Response {
        let mut inner = self.inner.lock().unwrap();

        // Specific target.
        if !req.target.is_empty() {
            match inner.streams.remove(&req.target) {
                Some(entry) => {
                    entry.control.stop();
                    if let Some(tx) = entry.pin_tx {
                        let _ = tx.send(None);
                    }
                    if inner.pending_target == req.target {
                        inner.pending_target.clear();
                        inner.pending_port = 0;
                    }
                    // Tear down the shared capture if that was the last stream
                    // (daemon.go: maybeStopBroadcastLocked after delete).
                    Self::maybe_stop_broadcast_locked(&mut inner);
                    return Response {
                        ok: true,
                        state: Self::overall_state_locked(&inner).to_string(),
                        ..Default::default()
                    };
                }
                None => {
                    return Response {
                        ok: false,
                        state: Self::overall_state_locked(&inner).to_string(),
                        error: format!("no active stream to {}", req.target),
                        ..Default::default()
                    };
                }
            }
        }

        // Clear pending PIN + disconnect all (daemon.go).
        inner.pending_target.clear();
        inner.pending_port = 0;
        Self::stop_all_locked(&mut inner);
        Response {
            ok: true,
            state: STATE_IDLE.to_string(),
            ..Default::default()
        }
    }

    /// Stop every active stream AND tear down the shared capture (daemon.go
    /// stopAllLocked). Must be called with `inner` held.
    fn stop_all_locked(inner: &mut Inner) {
        for (_, entry) in inner.streams.drain() {
            entry.control.stop();
            if let Some(tx) = entry.pin_tx {
                let _ = tx.send(None);
            }
        }
        inner.pending_target.clear();
        inner.pending_port = 0;
        // Stop the shared screen capture + clear it (daemon.go stopAllLocked:
        // capture.Stop(); captureCancel(); broadcast = nil).
        if let Some(stop) = inner.capture_stop.take() {
            stop.stop();
        }
        inner.broadcast = None;
    }

    // -----------------------------------------------------------------------
    // mute / unmute (daemon.go handleSetMute)
    // -----------------------------------------------------------------------

    fn handle_set_mute(self: &Arc<Self>, req: Request, muted: bool) -> Response {
        // Collect the target controls under the lock, then apply the SET_PARAMETER
        // outside it (daemon.go drops mu before SetAudioMuted).
        let controls: Vec<(String, MirrorControl)> = {
            let inner = self.inner.lock().unwrap();
            if !req.target.is_empty() {
                match inner.streams.get(&req.target) {
                    Some(entry) => vec![(req.target.clone(), entry.control.clone())],
                    None => {
                        return Response {
                            ok: false,
                            state: Self::overall_state_locked(&inner).to_string(),
                            error: format!("no active stream to {}", req.target),
                            ..Default::default()
                        };
                    }
                }
            } else {
                inner
                    .streams
                    .iter()
                    .filter(|(_, s)| s.state == STATE_STREAMING)
                    .map(|(ip, s)| (ip.clone(), s.control.clone()))
                    .collect()
            }
        };

        if controls.is_empty() {
            let inner = self.inner.lock().unwrap();
            return Self::status_response_locked(&inner, false, "not currently streaming");
        }

        let mut last_err: Option<String> = None;
        for (_, c) in &controls {
            if let Err(e) = c.set_muted(muted) {
                last_err = Some(e.to_string());
            }
        }

        if let Some(e) = last_err {
            let inner = self.inner.lock().unwrap();
            return Self::status_response_locked(
                &inner,
                false,
                &format!("failed to update audio mute state: {e}"),
            );
        }

        let mut inner = self.inner.lock().unwrap();
        for (ip, _) in &controls {
            if let Some(entry) = inner.streams.get_mut(ip) {
                entry.audio_muted = muted;
            }
        }
        Self::status_response_locked(&inner, true, "")
    }
}

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

/// Write a JSON response followed by a newline (Go's json.Encoder appends '\n',
/// which the client's json.Decoder tolerates).
fn write_response(w: &mut UnixStream, resp: &Response) -> std::io::Result<()> {
    let mut buf = serde_json::to_vec(resp).unwrap_or_default();
    buf.push(b'\n');
    w.write_all(&buf)?;
    w.flush()
}

fn to_device_infos(devices: &[AirPlayDevice]) -> Vec<DeviceInfo> {
    devices
        .iter()
        .map(|d| DeviceInfo {
            name: d.name.clone(),
            model: d.model.clone(),
            ip: d.ip.clone(),
            port: d.port as i32,
            device_id: d.device_id.clone(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Public entry point used by main.rs (`--daemonize` dispatch)
// ---------------------------------------------------------------------------

/// Build and run an AirFry daemon on `socket_path` (or the default when
/// `None`), blocking until shutdown. The self-contained entry point main.rs
/// dispatches `--daemonize` to.
pub fn run(socket_path: Option<PathBuf>) -> Result<()> {
    let mut cfg = Config::default();
    if let Some(p) = socket_path {
        cfg.socket_path = p;
    }
    let daemon = Daemon::new(cfg);

    // Clean shutdown on Ctrl-C / SIGTERM.
    {
        let d = daemon.clone();
        let _ = ctrlc::set_handler(move || {
            d.shutdown();
        });
    }

    daemon.run()
}

// ---------------------------------------------------------------------------
// Tests — JSON protocol round-trips (field names must match daemon.go)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_serializes_with_go_field_names() {
        // A status request: only `cmd` is present (target/port/pin omitempty).
        let r = Request {
            cmd: "status".into(),
            ..Default::default()
        };
        let j = serde_json::to_string(&r).unwrap();
        assert_eq!(j, r#"{"cmd":"status"}"#);

        // connect {target, pin}: port stays omitted at 0.
        let r = Request {
            cmd: "connect".into(),
            target: "192.168.1.50".into(),
            pin: "1234".into(),
            ..Default::default()
        };
        let v: serde_json::Value = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(v["cmd"], "connect");
        assert_eq!(v["target"], "192.168.1.50");
        assert_eq!(v["pin"], "1234");
        assert!(v.get("port").is_none(), "zero port must be omitted");

        // explicit port is emitted.
        let r = Request {
            cmd: "connect".into(),
            target: "10.0.0.2".into(),
            port: 7000,
            ..Default::default()
        };
        let v: serde_json::Value = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(v["port"], 7000);
    }

    #[test]
    fn request_deserializes_from_go_wire() {
        // Mirrors what a Go doubletake-ctl would send for `mute <target>`.
        let req: Request =
            serde_json::from_str(r#"{"cmd":"mute","target":"192.168.1.7"}"#).unwrap();
        assert_eq!(req.cmd, "mute");
        assert_eq!(req.target, "192.168.1.7");
        assert_eq!(req.port, 0);
        assert_eq!(req.pin, "");
    }

    #[test]
    fn response_always_emits_ok_state_audio_fields() {
        // daemon.go's Response has NO omitempty on ok/state/has_audio/audio_muted.
        let resp = Response {
            ok: true,
            state: STATE_IDLE.to_string(),
            ..Default::default()
        };
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&resp).unwrap()).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["state"], "idle");
        assert_eq!(v["has_audio"], false);
        assert_eq!(v["audio_muted"], false);
        // Omitted-when-empty fields are absent.
        assert!(v.get("device").is_none());
        assert!(v.get("device_ip").is_none());
        assert!(v.get("needs_pin").is_none());
        assert!(v.get("error").is_none());
        assert!(v.get("devices").is_none());
        assert!(v.get("streams").is_none());
    }

    #[test]
    fn response_streams_and_devices_use_go_field_names() {
        let resp = Response {
            ok: true,
            state: STATE_STREAMING.to_string(),
            device: "Living Room".into(),
            device_ip: "192.168.1.50".into(),
            has_audio: true,
            audio_muted: true,
            needs_pin: false,
            error: String::new(),
            devices: Some(vec![DeviceInfo {
                name: "Living Room".into(),
                model: "AppleTV6,2".into(),
                ip: "192.168.1.50".into(),
                port: 7000,
                device_id: "AA:BB:CC:DD:EE:FF".into(),
            }]),
            streams: Some(vec![StreamInfo {
                device: "Living Room".into(),
                device_ip: "192.168.1.50".into(),
                state: STATE_STREAMING.to_string(),
                has_audio: true,
                audio_muted: true,
            }]),
        };
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&resp).unwrap()).unwrap();
        assert_eq!(v["device"], "Living Room");
        assert_eq!(v["device_ip"], "192.168.1.50");
        assert_eq!(v["devices"][0]["device_id"], "AA:BB:CC:DD:EE:FF");
        assert_eq!(v["devices"][0]["port"], 7000);
        assert_eq!(v["streams"][0]["device_ip"], "192.168.1.50");
        assert_eq!(v["streams"][0]["has_audio"], true);
        assert_eq!(v["streams"][0]["audio_muted"], true);
        assert_eq!(v["streams"][0]["state"], "streaming");
    }

    #[test]
    fn response_round_trips_through_serde() {
        let resp = Response {
            ok: false,
            state: STATE_PIN_REQUIRED.to_string(),
            needs_pin: true,
            error: "PIN required".into(),
            ..Default::default()
        };
        let s = serde_json::to_string(&resp).unwrap();
        let back: Response = serde_json::from_str(&s).unwrap();
        assert_eq!(back.ok, false);
        assert_eq!(back.state, STATE_PIN_REQUIRED);
        assert!(back.needs_pin);
        assert_eq!(back.error, "PIN required");
    }

    /// End-to-end loopback: stand up a real daemon on a temp socket, drive it
    /// with the IPC client, and assert the wire round-trips. Proves the daemon
    /// and `daemonclient` agree on the protocol over an actual UnixStream.
    #[test]
    fn client_talks_to_real_daemon_over_socket() {
        use crate::daemonclient::Client;

        let dir = std::env::temp_dir().join(format!(
            "airfry-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("airfry-test.sock");
        let _ = std::fs::remove_file(&sock);

        let mut cfg = Config::default();
        cfg.socket_path = sock.clone();
        // Avoid touching the real network during the test: nothing connects, but
        // background discovery still runs harmlessly.
        let daemon = Daemon::new(cfg);

        let d = daemon.clone();
        let handle = thread::spawn(move || {
            let _ = d.run();
        });

        // Wait for the socket to appear.
        for _ in 0..300 {
            if sock.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }

        let client = Client::new(&sock);

        // status: a freshly-started daemon is idle with an (empty) stream list.
        let resp = client.status().expect("status");
        assert!(resp.ok);
        assert_eq!(resp.state, STATE_IDLE);
        assert_eq!(resp.streams.as_ref().map(|s| s.len()), Some(0));

        // devices: ok, idle, devices list present.
        let resp = client.devices().expect("devices");
        assert!(resp.ok);
        assert!(resp.devices.is_some());

        // unknown command -> ok=false + error.
        let resp = client.pin("").expect_err_is_ok_false();
        assert!(!resp.ok);

        // disconnect on an unknown target -> ok=false + error.
        let resp = client.disconnect_target("203.0.113.1").expect("disconnect");
        assert!(!resp.ok);
        assert!(resp.error.contains("no active stream"));

        daemon.shutdown();
        let _ = handle.join();
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Small helper so the test reads cleanly: `pin("")` returns Ok(Response) with
    // ok=false (no device parked), which we want to assert on.
    trait ExpectOkFalse {
        fn expect_err_is_ok_false(self) -> Response;
    }
    impl ExpectOkFalse for Result<Response> {
        fn expect_err_is_ok_false(self) -> Response {
            self.expect("pin call should reach the daemon")
        }
    }

    /// Shared-capture lifecycle (daemon.go getOrStartBroadcastLocked /
    /// maybeStopBroadcastLocked): the FIRST stream lazily starts ONE capture;
    /// the SECOND reuses it (no second capture); removing the streams one by one
    /// keeps the capture alive until the LAST is gone, which clears it so a later
    /// connect starts fresh. Uses test-mode capture (no display/portal needed);
    /// skips if GStreamer/videotestsrc is unavailable in the environment.
    #[test]
    fn shared_capture_create_on_first_stop_on_last() {
        let mut cfg = Config::default();
        cfg.test_mode = true;
        let daemon = Daemon::new(cfg);

        // Helper: register a connecting placeholder for a target (as handle_connect
        // does) so maybe_stop_broadcast_locked counts it as an active stream.
        let register = |ip: &str| {
            let mut inner = daemon.inner.lock().unwrap();
            inner.streams.insert(
                ip.to_string(),
                ActiveStream {
                    device: String::new(),
                    device_ip: ip.to_string(),
                    device_id: String::new(),
                    state: STATE_STREAMING,
                    audio_muted: false,
                    has_audio: false,
                    control: MirrorControl::new(),
                    pin_tx: None,
                    has_sink: true,
                },
            );
        };

        register("10.0.0.1");
        let cfg = daemon.inner.lock().unwrap().cfg.clone();
        let sink1 = match daemon.get_or_start_broadcast(&cfg) {
            Ok(s) => s,
            Err(e) => {
                crate::dlog!("skip shared_capture test: capture unavailable: {e:#}");
                return;
            }
        };
        // First stream started the one shared capture.
        assert!(daemon.inner.lock().unwrap().broadcast.is_some());
        assert!(daemon.inner.lock().unwrap().capture_stop.is_some());
        let bc_ptr = Arc::as_ptr(daemon.inner.lock().unwrap().broadcast.as_ref().unwrap());

        // Second stream reuses the SAME capture (no new BroadcastCapture).
        register("10.0.0.2");
        let sink2 = daemon.get_or_start_broadcast(&cfg).expect("second sink");
        let bc_ptr2 = Arc::as_ptr(daemon.inner.lock().unwrap().broadcast.as_ref().unwrap());
        assert_eq!(bc_ptr, bc_ptr2, "second stream must reuse the shared capture");

        // Both sinks read the SAME live frames off the one capture.
        let mut s1 = sink1;
        let mut s2 = sink2;
        let mut b1 = [0u8; 1024];
        let mut b2 = [0u8; 1024];
        assert!(s1.read(&mut b1).unwrap() > 0, "sink1 receives frames");
        assert!(s2.read(&mut b2).unwrap() > 0, "sink2 receives frames");

        // Remove the first stream: capture stays up (one stream remains).
        {
            let mut inner = daemon.inner.lock().unwrap();
            inner.streams.remove("10.0.0.1");
            Daemon::maybe_stop_broadcast_locked(&mut inner);
        }
        drop(s1);
        assert!(
            daemon.inner.lock().unwrap().broadcast.is_some(),
            "capture stays up while a stream remains"
        );

        // Remove the LAST stream: capture is stopped and cleared.
        {
            let mut inner = daemon.inner.lock().unwrap();
            inner.streams.remove("10.0.0.2");
            Daemon::maybe_stop_broadcast_locked(&mut inner);
        }
        drop(s2);
        assert!(
            daemon.inner.lock().unwrap().broadcast.is_none(),
            "capture cleared after the last stream ends"
        );
        assert!(daemon.inner.lock().unwrap().capture_stop.is_none());

        // A later connect can start a fresh capture again.
        register("10.0.0.3");
        let sink3 = daemon.get_or_start_broadcast(&cfg).expect("fresh capture");
        assert!(daemon.inner.lock().unwrap().broadcast.is_some());
        drop(sink3);
        {
            let mut inner = daemon.inner.lock().unwrap();
            inner.streams.remove("10.0.0.3");
            Daemon::maybe_stop_broadcast_locked(&mut inner);
        }
        assert!(daemon.inner.lock().unwrap().broadcast.is_none());
    }

    #[test]
    fn default_socket_path_uses_xdg_runtime_dir() {
        // Save + restore the env so the test is hermetic.
        let prev = std::env::var_os("XDG_RUNTIME_DIR");
        std::env::set_var("XDG_RUNTIME_DIR", "/run/user/1000");
        assert_eq!(
            default_socket_path(),
            PathBuf::from("/run/user/1000/airfry.sock")
        );
        std::env::remove_var("XDG_RUNTIME_DIR");
        assert_eq!(default_socket_path(), PathBuf::from("/tmp/airfry.sock"));
        match prev {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
    }
}
