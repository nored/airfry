//! AirFry system tray — a **native** StatusNotifierItem (via the vendored,
//! patched `ksni`). No Qt, no C++: it renders through the same DBusMenu /
//! AppIndicator path GNOME draws in its own style.
//!
//! Behaviour is a faithful port of the Go `internal/ui/app.go` tray:
//!
//!   * **White icon, blue while mirroring** — swapped live (see `icon.rs`).
//!   * **Scan only when the menu is opened, and only while idle** — the patched
//!     `ksni::Tray::about_to_show` fires on every menu open; we debounce it and
//!     never scan while a session is live. Nothing scans in the background.
//!   * **Persistence layer for the servers** — the discovered device list is
//!     cached to `~/.config/airfry/config.json`, so the menu is populated
//!     instantly on launch before any scan (`config.rs`).
//!   * **Energy saving when nothing streams** — mirroring runs on demand on a
//!     worker thread; when it stops, every capture/encode/RTSP resource is torn
//!     down and no background work remains.
//!   * **Underscan in the tray, never a window** — scroll the tray icon to
//!     adjust 0..=15 % (like a volume tray icon), shown as a text-art bar, with
//!     a step submenu for discoverability. Persisted; applied on the next
//!     connect. The transient PIN-pairing prompt uses `zenity`.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use ksni::blocking::{Handle, TrayMethods};
use ksni::menu::StandardItem;
use ksni::{Icon, MenuItem, Status, ToolTip};

use crate::config::{Config, Device};
use crate::{discovery, icon, mirror, rtsp};

const MAX_UNDERSCAN: u8 = 15;
/// Ignore a second menu-open within this window (the host can call AboutToShow
/// more than once per open; also keeps a held-open menu from re-scanning).
const OPEN_DEBOUNCE: Duration = Duration::from_millis(1500);
const SCAN_SECS: u64 = 4;

// ---------------------------------------------------------------------------
// Shared application state (everything the worker threads and the GUI share).
// ---------------------------------------------------------------------------
struct App {
    /// Discovered / cached receivers shown in the menu.
    devices: Mutex<Vec<Device>>,
    /// The header/status line text.
    status: Mutex<String>,
    /// The device currently being (or last) mirrored to — for "Change display".
    active: Mutex<Option<Device>>,
    /// Underscan percent (0..=15), shared with the next mirror run.
    underscan: AtomicU8,
    /// True while a discovery scan is in flight (debounces about_to_show).
    scanning: AtomicBool,
    /// True while a mirror worker is running (drives the icon colour).
    mirror_active: AtomicBool,
    /// Desired audio-mute state of the current stream (for the menu label).
    muted: AtomicBool,
    /// Bumped on every new selection / stop, so a stale mirror worker that was
    /// waiting gives up instead of stealing the screen.
    mirror_gen: AtomicU64,
    /// Stop flag + control handle of the running mirror (stop / mute live).
    current_stop: Mutex<Option<Arc<AtomicBool>>>,
    current_control: Mutex<Option<mirror::MirrorControl>>,
    /// Timestamp of the last menu-open, for debounce.
    last_open: Mutex<Option<Instant>>,
    /// Handle back into the ksni service so workers can request a redraw.
    handle: OnceLock<Handle<AirfryTray>>,
}

impl App {
    fn streaming(&self) -> bool {
        self.mirror_active.load(Ordering::Acquire)
    }

    /// Ask the tray to re-render its menu + properties (icon/tooltip).
    ///
    /// `Handle::update` does a `block_on`. If it ran on the ksni service thread
    /// (e.g. inside a menu `activate`/`scroll` callback) it would DEADLOCK the
    /// whole menu — after which Stop/Change-display/etc. silently stop working.
    /// So always run it on a detached thread; it never blocks the caller.
    fn redraw(&self) {
        if let Some(h) = self.handle.get() {
            let h = h.clone();
            std::thread::spawn(move || {
                let _ = h.update(|_t: &mut AirfryTray| {});
            });
        }
    }

    fn set_status(&self, text: impl Into<String>) {
        *self.status.lock().unwrap() = text.into();
        self.redraw();
    }

    /// Persist the device cache WITHOUT clobbering each device's per-receiver
    /// underscan (the slider/scroll own that). Read-modify-write: rebuild the
    /// list from the in-memory cache but pull every device's underscan from the
    /// current config on disk.
    fn persist(&self) {
        let mut cfg = Config::load();
        let devs = self.devices.lock().unwrap();
        cfg.devices = devs
            .iter()
            .map(|d| {
                let mut d = d.clone();
                d.underscan = cfg.underscan_for(&d.addr());
                d
            })
            .collect();
        cfg.save();
    }

    /// The active/last receiver's saved underscan (per-device), or the global
    /// default when nothing is selected.
    fn active_underscan(&self) -> u8 {
        let cfg = Config::load();
        match self.active.lock().unwrap().as_ref() {
            Some(d) => cfg.underscan_for(&d.addr()),
            None => cfg.underscan.min(MAX_UNDERSCAN),
        }
    }

    /// Launch the single-instance underscan slider popup. A second click just
    /// raises the existing window (the GApplication is single-instance).
    fn open_underscan_slider(&self) {
        let mut tried = Vec::new();
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                tried.push(dir.join("airfry-underscan"));
                if let Some(up) = dir.parent() {
                    tried.push(up.join("airfry-underscan")); // debug/release sibling
                }
            }
        }
        tried.push(std::path::PathBuf::from("airfry-underscan")); // $PATH

        // Tell the slider WHICH receiver to edit (underscan is per-device). Pass
        // the active/last device's "ip:port" and name; with none selected the
        // slider edits the global default.
        let (addr, name) = match self.active.lock().unwrap().as_ref() {
            Some(d) => (d.addr(), d.name.clone()),
            None => (String::new(), String::new()),
        };
        for bin in &tried {
            let mut cmd = std::process::Command::new(bin);
            if !addr.is_empty() {
                cmd.arg(&addr).arg(&name);
            }
            if cmd.spawn().is_ok() {
                return;
            }
        }
        notify("Underscan", "slider not found (install 'airfry-underscan')");
    }

    // ---- menu open → scan (only when idle) -------------------------------
    fn on_open(self: &Arc<Self>) {
        // Reflect the ACTIVE receiver's saved underscan in the menu bar (the
        // slider popup may have written it while we were idle). Underscan is
        // per-device, so key off the active/last device; fall back to the global
        // default when nothing is selected yet.
        self.underscan
            .store(self.active_underscan(), Ordering::Release);
        {
            let mut last = self.last_open.lock().unwrap();
            if let Some(t) = *last {
                if t.elapsed() < OPEN_DEBOUNCE {
                    return;
                }
            }
            *last = Some(Instant::now());
        }
        // Never disturb a live session by scanning while mirroring.
        if self.streaming() {
            return;
        }
        self.scan();
    }

    fn scan(self: &Arc<Self>) {
        if self
            .scanning
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return; // a scan is already running
        }
        let app = self.clone();
        std::thread::spawn(move || {
            if !app.streaming() {
                app.set_status("Searching for devices…");
            }
            let found = discovery::discover(Duration::from_secs(SCAN_SECS)).unwrap_or_default();
            // Carry each receiver's SAVED per-device underscan across a rescan so
            // discovery never wipes it (underscan is per Apple TV, not global).
            let saved = Config::load();
            let mut devs: Vec<Device> = found
                .into_iter()
                .filter(|d| d.supports_screen())
                .map(|d| {
                    let addr = format!("{}:{}", d.ip, d.port);
                    Device {
                        name: if d.name.is_empty() {
                            d.ip.clone()
                        } else {
                            d.name.clone()
                        },
                        model: d.model.clone(),
                        host: d.ip.clone(),
                        port: d.port,
                        device_id: d.device_id.clone(),
                        underscan: saved.underscan_for(&addr),
                    }
                })
                .collect();
            devs.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
            devs.dedup_by(|a, b| a.host == b.host && a.port == b.port);

            let changed = {
                let mut g = app.devices.lock().unwrap();
                let changed = *g != devs;
                if !devs.is_empty() {
                    *g = devs.clone();
                }
                changed && !devs.is_empty()
            };
            if changed {
                app.persist(); // cache for an instant menu next launch
            }

            if !app.streaming() {
                let n = app.devices.lock().unwrap().len();
                app.set_status(if n == 0 {
                    "No receivers found".to_string()
                } else {
                    format!("Pick a device to mirror ({n})")
                });
            } else {
                app.redraw();
            }
            app.scanning.store(false, Ordering::Release);
        });
    }

    // ---- mirroring -------------------------------------------------------
    fn stop_current(&self) {
        if let Some(s) = self.current_stop.lock().unwrap().as_ref() {
            s.store(true, Ordering::Release);
        }
    }

    fn start_mirror(self: &Arc<Self>, dev: Device) {
        let my_gen = self.mirror_gen.fetch_add(1, Ordering::AcqRel) + 1;
        self.stop_current(); // hand the screen over to this newer selection
        *self.active.lock().unwrap() = Some(dev.clone());
        self.muted.store(false, Ordering::Release);

        let app = self.clone();
        std::thread::spawn(move || {
            // Wait (best-effort) for any prior mirror to release the capture.
            for _ in 0..400 {
                if !app.mirror_active.load(Ordering::Acquire) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            if app.mirror_gen.load(Ordering::Acquire) != my_gen {
                return; // superseded while we waited
            }
            app.mirror_active.store(true, Ordering::Release);
            app.redraw(); // icon → blue, menu → controls
            app.set_status(format!("Connecting → {}", dev.name));

            // Report every pairing/setup phase to stderr so a terminal run shows
            // exactly where a connect to a real receiver fails.
            let mut progress = |phase: &str, ok: bool, detail: &str| {
                crate::dlog!("[airfry] {} {phase}: {detail}", if ok { "OK  " } else { "FAIL" });
            };
            let pin_app = app.clone();
            let pin_name = dev.name.clone();
            let mut ask_pin = move || {
                pin_app.set_status(format!("Enter the code shown on {pin_name}…"));
                zenity_pin(
                    &format!("Pair with {pin_name}"),
                    &format!("Enter the AirPlay code shown on {pin_name}:"),
                )
            };

            let session = match rtsp::Session::connect_host_with(
                &dev.host,
                dev.port,
                "",
                &rtsp::ConnectOptions::default(),
                &mut ask_pin,
                &mut progress,
            ) {
                Ok(s) => s,
                Err(e) => {
                    crate::dlog!("[airfry] connect/pair to {} FAILED: {e:#}", dev.name);
                    app.set_status(format!("Connect failed: {e}"));
                    notify(&format!("Could not connect to {}", dev.name), &format!("{e}"));
                    finish_mirror(&app);
                    return;
                }
            };
            crate::dlog!("[airfry] session established → {}", dev.name);

            // Aborted (Stop / new selection) during connect/pairing?
            if app.mirror_gen.load(Ordering::Acquire) != my_gen {
                finish_mirror(&app);
                return;
            }

            let stop = Arc::new(AtomicBool::new(false));
            let control = mirror::MirrorControl::with_stop(stop.clone());
            *app.current_stop.lock().unwrap() = Some(stop.clone());
            *app.current_control.lock().unwrap() = Some(control.clone());

            let mut opts = mirror::MirrorOpts::default();
            // Underscan is PER DEVICE: read THIS receiver's saved value.
            let pct = Config::load().underscan_for(&dev.addr());
            opts.fit_pct = pct;
            // Keep the fit stage live so the slider/scroll retune it mid-stream.
            opts.live_underscan = true;
            app.underscan.store(pct, Ordering::Release);

            app.set_status(format!("Mirroring → {}", dev.name));
            notify("AirFry", &format!("Mirroring to {}", dev.name));

            crate::dlog!("[airfry] starting mirror stream → {}", dev.name);
            match mirror::run_mirror_with_control(session, opts, control) {
                Ok(()) => app.set_status(format!("Stopped → {}", dev.name)),
                Err(e) => {
                    // Suppress the error if WE asked it to stop.
                    if !stop.load(Ordering::Acquire) {
                        crate::dlog!("[airfry] mirror stream FAILED → {}: {e:#}", dev.name);
                        app.set_status(format!("Mirror error: {e}"));
                        notify(&format!("Mirror error → {}", dev.name), &format!("{e}"));
                    } else {
                        app.set_status(format!("Stopped → {}", dev.name));
                    }
                }
            }
            finish_mirror(&app);
        });
    }

    fn stop_mirror(&self) {
        self.mirror_gen.fetch_add(1, Ordering::AcqRel);
        self.stop_current();
    }

    /// Re-pick the screen: stop and reconnect to the active device (the portal
    /// re-prompts the native display picker on the fresh capture).
    fn change_display(self: &Arc<Self>) {
        let dev = self.active.lock().unwrap().clone();
        if let Some(d) = dev {
            notify("AirFry", "Changing display — pick a screen…");
            self.start_mirror(d);
        }
    }

    fn toggle_mute(&self) {
        let now_muted = !self.muted.load(Ordering::Acquire);
        self.muted.store(now_muted, Ordering::Release);
        // set_muted does a synchronous RTSP request — never run it on the menu
        // (service) thread or the menu freezes. Hand it to a worker thread.
        let ctrl = self.current_control.lock().unwrap().clone();
        std::thread::spawn(move || {
            if let Some(c) = ctrl {
                let _ = c.set_muted(now_muted);
            }
        });
        self.redraw();
    }

    // ---- underscan -------------------------------------------------------
    fn set_underscan(&self, pct: u8) {
        let pct = pct.min(MAX_UNDERSCAN);
        if self.underscan.swap(pct, Ordering::AcqRel) == pct {
            return;
        }
        // Save PER DEVICE (the active/last receiver); fall back to the global
        // default when nothing is selected. Read-modify-write so we don't fight
        // the slider popup writing the same file.
        let mut cfg = Config::load();
        match self.active.lock().unwrap().as_ref() {
            Some(d) => cfg.set_underscan_for(&d.addr(), pct),
            None => cfg.underscan = pct,
        }
        cfg.save();
        // Apply LIVE to the running mirror (no reconnect, no portal re-prompt).
        if let Some(c) = self.current_control.lock().unwrap().as_ref() {
            c.set_underscan(pct);
        }
        self.redraw();
    }

    /// Poll config.json for external edits (the slider popup is a separate
    /// process). While a mirror is live, push any underscan change for the active
    /// receiver straight to the running pipeline — that's what makes the slider
    /// "live". Idle changes are picked up on the next menu open / connect.
    ///
    /// Energy saving: this only touches the filesystem WHILE STREAMING. When idle
    /// it's just a slow heartbeat (a sleeping thread, no stat, no work) — nothing
    /// runs in the background when nothing is being mirrored.
    fn spawn_config_watcher(self: &Arc<Self>) {
        let app = self.clone();
        std::thread::spawn(move || {
            let path = crate::config::config_path();
            let mut last_mtime = None;
            loop {
                // While streaming, the live slider needs a quick poll; idle, sleep
                // long and do nothing (the machine can rest).
                if !app.streaming() {
                    last_mtime = None; // re-baseline on the next stream
                    std::thread::sleep(Duration::from_secs(2));
                    continue;
                }
                std::thread::sleep(Duration::from_millis(400));
                let Some(p) = path.as_ref() else { return };
                let mtime = std::fs::metadata(p).ok().and_then(|m| m.modified().ok());
                if last_mtime.is_none() {
                    last_mtime = mtime; // first tick of this stream — baseline only
                    continue;
                }
                if mtime == last_mtime {
                    continue;
                }
                last_mtime = mtime;
                let pct = app.active_underscan();
                if app.underscan.swap(pct, Ordering::AcqRel) == pct {
                    continue;
                }
                if let Some(c) = app.current_control.lock().unwrap().as_ref() {
                    c.set_underscan(pct);
                }
                app.redraw();
            }
        });
    }

    fn adjust_underscan(&self, delta: i32) {
        let cur = self.underscan.load(Ordering::Acquire) as i32;
        let next = (cur + delta.signum()).clamp(0, MAX_UNDERSCAN as i32) as u8;
        self.set_underscan(next);
    }

    fn quit(&self) {
        self.stop_current();
        // Give a live session a brief moment to TEARDOWN cleanly, then exit.
        std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(400));
            std::process::exit(0);
        });
    }
}

/// Common teardown when a mirror worker exits.
fn finish_mirror(app: &Arc<App>) {
    *app.current_control.lock().unwrap() = None;
    *app.current_stop.lock().unwrap() = None;
    app.mirror_active.store(false, Ordering::Release);
    app.redraw(); // icon → white, menu → device list
}

// ---------------------------------------------------------------------------
// The ksni tray model.
// ---------------------------------------------------------------------------
struct AirfryTray {
    app: Arc<App>,
}

impl ksni::Tray for AirfryTray {
    fn id(&self) -> String {
        "airfry".into()
    }

    fn title(&self) -> String {
        "AirFry".into()
    }

    fn status(&self) -> Status {
        Status::Active
    }

    fn icon_pixmap(&self) -> Vec<Icon> {
        if self.app.streaming() {
            icon::streaming()
        } else {
            icon::idle()
        }
    }

    fn tool_tip(&self) -> ToolTip {
        ToolTip {
            icon_name: String::new(),
            icon_pixmap: self.icon_pixmap(),
            title: "AirFry".into(),
            description: self.app.status.lock().unwrap().clone(),
        }
    }

    /// Patched hook: the menu is opening — scan if idle (never in background).
    fn about_to_show(&self) {
        self.app.on_open();
    }

    /// Left-click on the icon (where the host delivers it) — also treat as open.
    fn activate(&mut self, _x: i32, _y: i32) {
        self.app.on_open();
    }

    /// Mouse-wheel on the icon adjusts underscan, like a volume tray icon.
    fn scroll(&mut self, delta: i32, _orientation: ksni::Orientation) {
        self.app.adjust_underscan(delta);
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        let app = &self.app;
        let streaming = app.streaming();
        let muted = app.muted.load(Ordering::Acquire);
        let underscan = app.underscan.load(Ordering::Acquire);
        let status = app.status.lock().unwrap().clone();
        let devices = app.devices.lock().unwrap().clone();

        let mut items: Vec<MenuItem<Self>> = vec![
            disabled("AirFry"),
            disabled(&status),
            MenuItem::Separator,
        ];

        if streaming {
            items.push(
                StandardItem {
                    label: "Stop mirroring".into(),
                    activate: Box::new(|t: &mut AirfryTray| t.app.stop_mirror()),
                    ..Default::default()
                }
                .into(),
            );
            items.push(
                StandardItem {
                    label: if muted { "Unmute audio" } else { "Mute audio" }.into(),
                    activate: Box::new(|t: &mut AirfryTray| t.app.toggle_mute()),
                    ..Default::default()
                }
                .into(),
            );
            items.push(
                StandardItem {
                    label: "Change display…".into(),
                    activate: Box::new(|t: &mut AirfryTray| t.app.change_display()),
                    ..Default::default()
                }
                .into(),
            );
        } else {
            if devices.is_empty() {
                items.push(disabled("Open to scan for devices"));
            } else {
                for d in &devices {
                    let dev = d.clone();
                    items.push(
                        StandardItem {
                            label: format!("Mirror to {}{}", d.name, model_hint(&d.model)),
                            activate: Box::new(move |t: &mut AirfryTray| {
                                t.app.start_mirror(dev.clone())
                            }),
                            ..Default::default()
                        }
                        .into(),
                    );
                }
            }
            items.push(
                StandardItem {
                    label: "Rescan".into(),
                    activate: Box::new(|t: &mut AirfryTray| t.app.scan()),
                    ..Default::default()
                }
                .into(),
            );
        }

        items.push(MenuItem::Separator);

        // Underscan: current value (text-art bar) + a real draggable slider in a
        // single-instance popup window. Scrolling the tray icon also adjusts it.
        items.push(disabled(&underscan_bar(underscan)));
        items.push(
            StandardItem {
                label: "Underscan slider…".into(),
                activate: Box::new(|t: &mut AirfryTray| t.app.open_underscan_slider()),
                ..Default::default()
            }
            .into(),
        );

        items.push(MenuItem::Separator);
        items.push(
            StandardItem {
                label: "Quit".into(),
                activate: Box::new(|t: &mut AirfryTray| t.app.quit()),
                ..Default::default()
            }
            .into(),
        );
        items
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
fn disabled(label: &str) -> MenuItem<AirfryTray> {
    StandardItem {
        label: label.into(),
        enabled: false,
        ..Default::default()
    }
    .into()
}

fn model_hint(model: &str) -> &'static str {
    if model.starts_with("AppleTV") {
        "   (Apple TV)"
    } else if model.starts_with("Mac") {
        "   (Mac)"
    } else {
        ""
    }
}

fn underscan_bar(pct: u8) -> String {
    let total = MAX_UNDERSCAN as usize;
    let filled = (pct as usize).min(total);
    let bar: String = (0..total)
        .map(|i| if i < filled { '█' } else { '░' })
        .collect();
    format!("Underscan  {bar}  {pct}%")
}

/// Transient PIN-pairing prompt via zenity (a short-lived pairing dialog — the
/// only window AirFry ever shows; the underscan control stays in the tray).
fn zenity_pin(title: &str, text: &str) -> Option<String> {
    let out = std::process::Command::new("zenity")
        .args(["--entry", "--title", title, "--text", text])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let pin = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if pin.is_empty() {
        None
    } else {
        Some(pin)
    }
}

fn notify(title: &str, body: &str) {
    let _ = std::process::Command::new("notify-send")
        .args(["-a", "AirFry", title, body])
        .spawn();
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
pub fn run_tray() -> i32 {
    let cfg = Config::load();
    let initial_status = if cfg.devices.is_empty() {
        "Open the menu to scan".to_string()
    } else {
        format!("{} saved device(s) — open to refresh", cfg.devices.len())
    };

    let app = Arc::new(App {
        devices: Mutex::new(cfg.devices.clone()),
        status: Mutex::new(initial_status),
        active: Mutex::new(None),
        underscan: AtomicU8::new(cfg.underscan.min(MAX_UNDERSCAN)),
        scanning: AtomicBool::new(false),
        mirror_active: AtomicBool::new(false),
        muted: AtomicBool::new(false),
        mirror_gen: AtomicU64::new(0),
        current_stop: Mutex::new(None),
        current_control: Mutex::new(None),
        last_open: Mutex::new(None),
        handle: OnceLock::new(),
    });

    let tray = AirfryTray { app: app.clone() };
    let handle = match tray.spawn() {
        Ok(h) => h,
        Err(e) => {
            eprintln!(
                "airfry: could not register the system tray: {e}\n\
                 (GNOME needs the AppIndicator/StatusNotifier extension enabled.)"
            );
            return 1;
        }
    };
    let _ = app.handle.set(handle);

    // Watch config.json so the slider POPUP (a separate process) applies LIVE to
    // a running mirror: when it changes the active receiver's underscan, push it
    // to the live pipeline immediately. Cheap mtime poll; only acts while mirroring.
    app.spawn_config_watcher();

    // The ksni service runs on its own thread; mirroring/discovery run on
    // worker threads spawned on demand. Nothing runs while idle. Park here;
    // "Quit" calls std::process::exit.
    loop {
        std::thread::park();
    }
}
