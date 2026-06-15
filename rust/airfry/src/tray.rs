//! AirFry system-tray widget (default face of the app).
//!
//! The visible UI is a C++ Qt `QSystemTrayIcon` whose context `QMenu` embeds a
//! real continuous underscan `QSlider` via a `QWidgetAction` (see cpp/tray.*).
//! Qt's self-drawn menu is the only way to get a slider into a tray menu on
//! GNOME/Wayland — DBusMenu has no slider item type.
//!
//! This module is the Rust driver: it owns discovery + mirror orchestration on
//! worker threads and marshals UI updates back to the GUI thread through the
//! thread-safe `airfry_tray_set_*` C functions.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use crate::{discovery, mirror, rtsp};

// ---------------------------------------------------------------------------
// C ABI (mirrors cpp/tray.h)
// ---------------------------------------------------------------------------
#[repr(C)]
struct AirfryTrayCallbacks {
    ctx: *mut c_void,
    on_ready: extern "C" fn(*mut c_void),
    on_rescan: extern "C" fn(*mut c_void),
    on_device: extern "C" fn(*mut c_void, *const c_char),
    on_underscan: extern "C" fn(*mut c_void, c_int),
    on_quit: extern "C" fn(*mut c_void),
}

extern "C" {
    fn airfry_tray_run(cb: *const AirfryTrayCallbacks, initial_pct: c_int) -> c_int;
    fn airfry_tray_set_devices(
        names: *const *const c_char,
        addrs: *const *const c_char,
        n: c_int,
    );
    fn airfry_tray_set_status(text: *const c_char);
}

// ---------------------------------------------------------------------------
// Global state (the C callbacks have no good place to stash a Rust handle, so
// globals are simplest and the callbacks are inherently process-global anyway).
// ---------------------------------------------------------------------------
struct State {
    /// Last discovered device list (name, "ip:port").
    devices: Mutex<Vec<(String, String)>>,
    /// Current underscan percentage (0..=15), shared with the running mirror.
    underscan: AtomicU8,
    /// True while a discovery scan is in flight (debounce aboutToShow).
    scanning: AtomicBool,
    /// Generation counter bumped on every new device selection / quit. A mirror
    /// thread checks whether it is still the current generation when it returns.
    mirror_gen: AtomicU64,
    /// True while a mirror thread is running.
    mirror_active: AtomicBool,
    /// Stop flag of the currently running mirror, so a new selection or Quit
    /// can stop it live.
    current_stop: Mutex<Option<std::sync::Arc<AtomicBool>>>,
}

static STATE: OnceLock<State> = OnceLock::new();

fn state() -> &'static State {
    STATE.get_or_init(|| State {
        devices: Mutex::new(Vec::new()),
        underscan: AtomicU8::new(0),
        scanning: AtomicBool::new(false),
        mirror_gen: AtomicU64::new(0),
        mirror_active: AtomicBool::new(false),
        current_stop: Mutex::new(None),
    })
}

/// Signal the currently running mirror (if any) to stop.
fn stop_current_mirror() {
    let st = state();
    if let Ok(g) = st.current_stop.lock() {
        if let Some(s) = g.as_ref() {
            s.store(true, Ordering::Release);
        }
    }
}

// ---------------------------------------------------------------------------
// Underscan persistence: ~/.config/airfry/underscan
// ---------------------------------------------------------------------------
fn config_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("airfry").join("underscan"))
}

fn load_underscan() -> u8 {
    let Some(path) = config_path() else { return 0 };
    match std::fs::read_to_string(&path) {
        Ok(s) => s.trim().parse::<u8>().unwrap_or(0).min(15),
        Err(_) => 0,
    }
}

fn save_underscan(pct: u8) {
    let Some(path) = config_path() else { return };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(&path, pct.to_string());
}

// ---------------------------------------------------------------------------
// Helpers to call the thread-safe C setters with Rust strings.
// ---------------------------------------------------------------------------
fn set_status(text: &str) {
    if let Ok(c) = CString::new(text) {
        unsafe { airfry_tray_set_status(c.as_ptr()) };
    }
}

fn set_devices(list: &[(String, String)]) {
    // Keep the CStrings alive for the duration of the FFI call.
    let names: Vec<CString> = list
        .iter()
        .map(|(n, _)| CString::new(n.as_str()).unwrap_or_default())
        .collect();
    let addrs: Vec<CString> = list
        .iter()
        .map(|(_, a)| CString::new(a.as_str()).unwrap_or_default())
        .collect();
    let name_ptrs: Vec<*const c_char> = names.iter().map(|c| c.as_ptr()).collect();
    let addr_ptrs: Vec<*const c_char> = addrs.iter().map(|c| c.as_ptr()).collect();
    unsafe {
        airfry_tray_set_devices(
            name_ptrs.as_ptr(),
            addr_ptrs.as_ptr(),
            list.len() as c_int,
        );
    }
}

// ---------------------------------------------------------------------------
// Discovery worker
// ---------------------------------------------------------------------------
fn spawn_discovery() {
    let st = state();
    // Debounce: only one scan at a time.
    if st
        .scanning
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }

    std::thread::spawn(move || {
        let st = state();
        set_status("Scanning…");

        let found = discovery::discover(Duration::from_secs(4)).unwrap_or_default();

        // Only list receivers that advertise screen mirroring.
        let mut list: Vec<(String, String)> = found
            .into_iter()
            .filter(|d| d.supports_screen())
            .map(|d| {
                let name = if d.name.is_empty() {
                    d.ip.clone()
                } else {
                    d.name.clone()
                };
                (name, format!("{}:{}", d.ip, d.port))
            })
            .collect();
        list.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()));

        if let Ok(mut g) = st.devices.lock() {
            *g = list.clone();
        }
        set_devices(&list);

        if st.mirror_active.load(Ordering::Acquire) {
            // Don't clobber the mirroring status line.
        } else if list.is_empty() {
            set_status("No receivers found");
        } else {
            set_status(&format!("{} receiver(s)", list.len()));
        }

        st.scanning.store(false, Ordering::Release);
    });
}

// ---------------------------------------------------------------------------
// Mirror worker
// ---------------------------------------------------------------------------
fn start_mirror(addr: &str) {
    let st = state();

    // Bump generation and signal any running mirror to stop, so this newer
    // selection takes over the screen live.
    let my_gen = st.mirror_gen.fetch_add(1, Ordering::AcqRel) + 1;
    stop_current_mirror();

    let (host, port) = match addr.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(7000)),
        None => (addr.to_string(), 7000u16),
    };
    let addr_owned = addr.to_string();

    std::thread::spawn(move || {
        let st = state();

        // Wait (best-effort) for any prior mirror to release before we start.
        for _ in 0..400 {
            if !st.mirror_active.load(Ordering::Acquire) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        // Superseded by an even newer selection while we waited?
        if st.mirror_gen.load(Ordering::Acquire) != my_gen {
            return;
        }
        st.mirror_active.store(true, Ordering::Release);

        set_status(&format!("Connecting → {addr_owned}"));

        let pct = st.underscan.load(Ordering::Acquire);
        let mut opts = mirror::MirrorOpts::default();
        opts.fit_pct = pct;

        let mut report = |_phase: &str, _ok: bool, _detail: &str| {};
        // TODO: prompt for the PIN via a Qt dialog when the receiver requires a
        // code. For now the tray attempts PIN-less pairing only.
        let mut ask_pin = || None;
        let session =
            match rtsp::Session::connect_host_with(
                &host,
                port,
                "",
                &rtsp::ConnectOptions::default(),
                &mut ask_pin,
                &mut report,
            ) {
            Ok(s) => s,
            Err(e) => {
                set_status(&format!("Connect failed: {e}"));
                st.mirror_active.store(false, Ordering::Release);
                return;
            }
        };

        // Install a fresh stop flag for this session so the tray can stop it.
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        if let Ok(mut g) = st.current_stop.lock() {
            *g = Some(stop.clone());
        }
        // Aborted during connect?
        if st.mirror_gen.load(Ordering::Acquire) != my_gen {
            st.mirror_active.store(false, Ordering::Release);
            return;
        }

        set_status(&format!("Mirroring → {addr_owned}"));

        match mirror::run_mirror_with_stop(session, opts, stop) {
            Ok(()) => set_status(&format!("Stopped → {addr_owned}")),
            Err(e) => set_status(&format!("Mirror error: {e}")),
        }

        st.mirror_active.store(false, Ordering::Release);
    });
}

// ---------------------------------------------------------------------------
// extern "C" callbacks handed to the C++ tray.
// ---------------------------------------------------------------------------
extern "C" fn cb_on_ready(_ctx: *mut c_void) {
    spawn_discovery();
}

extern "C" fn cb_on_rescan(_ctx: *mut c_void) {
    spawn_discovery();
}

extern "C" fn cb_on_device(_ctx: *mut c_void, addr: *const c_char) {
    if addr.is_null() {
        return;
    }
    let addr = unsafe { CStr::from_ptr(addr) };
    if let Ok(s) = addr.to_str() {
        start_mirror(s);
    }
}

extern "C" fn cb_on_underscan(_ctx: *mut c_void, pct: c_int) {
    let pct = pct.clamp(0, 15) as u8;
    let st = state();
    st.underscan.store(pct, Ordering::Release);
    save_underscan(pct);
}

extern "C" fn cb_on_quit(_ctx: *mut c_void) {
    let st = state();
    // Bump generation so any pending/stale mirror threads give up, and stop the
    // running mirror cleanly.
    st.mirror_gen.fetch_add(1, Ordering::AcqRel);
    stop_current_mirror();
    // The C side calls QApplication::quit() right after this returns.
}

// ---------------------------------------------------------------------------
// Entry point: build + run the tray (blocks on the main thread).
// ---------------------------------------------------------------------------
pub fn run_tray() -> i32 {
    let st = state();
    let initial = load_underscan();
    st.underscan.store(initial, Ordering::Release);

    let cb = AirfryTrayCallbacks {
        ctx: ptr::null_mut(),
        on_ready: cb_on_ready,
        on_rescan: cb_on_rescan,
        on_device: cb_on_device,
        on_underscan: cb_on_underscan,
        on_quit: cb_on_quit,
    };

    unsafe { airfry_tray_run(&cb as *const AirfryTrayCallbacks, initial as c_int) }
}
