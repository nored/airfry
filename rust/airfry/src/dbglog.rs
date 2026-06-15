//! Verbose debug logging gated by `--debug` / `AIRFRY_DEBUG`, the Rust analogue
//! of doubletake's `DebugMode` + `dbg()` (debug.go). When disabled the `dlog!`
//! macro compiles to a cheap atomic load and emits nothing.

use std::sync::atomic::{AtomicBool, Ordering};

static DEBUG: AtomicBool = AtomicBool::new(false);

/// Enable/disable verbose debug logging (set from the `--debug` flag).
pub fn set_debug(on: bool) {
    DEBUG.store(on, Ordering::Relaxed);
}

/// Initialise from the `AIRFRY_DEBUG` env var (set by the CLI flag parser so the
/// setting propagates to the daemon/tray code paths too).
pub fn init_from_env() {
    if std::env::var_os("AIRFRY_DEBUG").is_some() {
        set_debug(true);
    }
}

#[inline]
pub fn enabled() -> bool {
    DEBUG.load(Ordering::Relaxed)
}

/// `dlog!("...", args)` — prints `[debug] ...` to stderr only when enabled.
#[macro_export]
macro_rules! dlog {
    ($($arg:tt)*) => {
        if $crate::dbglog::enabled() {
            eprintln!("[debug] {}", format!($($arg)*));
        }
    };
}
