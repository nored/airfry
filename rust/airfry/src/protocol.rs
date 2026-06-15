//! AirFry daemon control-socket wire protocol.
//!
//! These are the request/response types exchanged over the daemon's Unix
//! socket, factored out of `daemon.rs` so the lightweight `airfry-ctl` binary
//! can speak the protocol without pulling in the mirror/capture/rtsp stack.
//!
//! Field names + `omitempty` placement match doubletake's
//! `internal/daemon/daemon.go` Request/Response/DeviceInfo/StreamInfo EXACTLY,
//! so the Rust daemon, the Rust `airfry-ctl`, and a Go `doubletake-ctl` all
//! agree byte-for-byte on the wire.
//!
//! This module has NO heavy dependencies (serde + std only); both `daemon.rs`
//! (the service) and the standalone `airfry-ctl` binary include it.

#![allow(dead_code)]

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// State machine string constants (daemon.go State)
// ---------------------------------------------------------------------------

pub const STATE_IDLE: &str = "idle";
pub const STATE_DISCOVERING: &str = "discovering";
pub const STATE_CONNECTING: &str = "connecting";
pub const STATE_STREAMING: &str = "streaming";
pub const STATE_PIN_REQUIRED: &str = "pin_required";

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// A command sent to the daemon over the control socket (daemon.go Request).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Request {
    pub cmd: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target: String,
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub port: i32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pin: String,
}

fn is_zero_i32(v: &i32) -> bool {
    *v == 0
}

/// One active (or connecting) mirror stream (daemon.go StreamInfo).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StreamInfo {
    pub device: String,
    pub device_ip: String,
    pub state: String,
    pub has_audio: bool,
    pub audio_muted: bool,
}

/// A simplified view of a discovered AirPlay device (daemon.go DeviceInfo).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub name: String,
    pub model: String,
    pub ip: String,
    pub port: i32,
    pub device_id: String,
}

/// Returned to the caller for every request (daemon.go Response). `ok`,
/// `state`, `has_audio` and `audio_muted` are always emitted (no `omitempty`),
/// matching daemon.go; the rest are omitted when empty.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    pub state: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub device: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub device_ip: String,
    pub has_audio: bool,
    pub audio_muted: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub needs_pin: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub devices: Option<Vec<DeviceInfo>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams: Option<Vec<StreamInfo>>,
}

fn is_false(v: &bool) -> bool {
    !*v
}

// ---------------------------------------------------------------------------
// Default socket path (daemon.go DefaultSocketPath)
// ---------------------------------------------------------------------------

/// The default control-socket path: `$XDG_RUNTIME_DIR/airfry.sock`, falling
/// back to `/tmp/airfry.sock` when `XDG_RUNTIME_DIR` is unset (daemon.go
/// DefaultSocketPath, renamed doubletake.sock -> airfry.sock).
pub fn default_socket_path() -> PathBuf {
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    dir.join("airfry.sock")
}
