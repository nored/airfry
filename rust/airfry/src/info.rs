//! Receiver `/info` query — faithful port of doubletake's
//! internal/airplay/client.go `GetInfo` + `ReceiverInfo` / `DisplaySize`.
//!
//! `GetInfo` issues `GET /info` with content-type
//! `application/x-apple-binary-plist` and an empty body; the receiver replies
//! with a binary plist describing its capabilities. We parse the subset the
//! rest of the stack needs:
//!
//!   * `pk` — the receiver's ed25519 long-term public key, used by the raw
//!     (UxPlay/legacy) pair-verify to check the server signature.
//!   * `displays` — the advertised display geometry, surfaced through
//!     `DisplaySize()` so the mirror codec header can carry the real
//!     presentation size (mirror.go feeds this when nonzero).

#![allow(dead_code)]

use anyhow::{Context, Result};

use crate::rtsp::Transport;

/// A receiver display advertised in the `/info` response (`displays` array).
#[derive(Default, Clone, Debug)]
pub struct DisplayInfo {
    pub width: i64,
    pub height: i64,
    pub width_pixels: i64,
    pub height_pixels: i64,
}

/// The capabilities returned by GET /info. Mirrors the Go `ReceiverInfo`
/// (client.go:24-43) field-for-field, with the same plist keys.
#[derive(Default, Clone, Debug)]
pub struct ReceiverInfo {
    pub name: String,
    pub model: String,
    pub manufacturer: String,
    pub device_id: String,
    pub protocol_version: String,
    pub source_version: String,
    pub features: u64,
    pub status_flags: u64,
    /// Receiver ed25519 long-term public key (`pk`); empty if not advertised.
    pub pk: Vec<u8>,
    pub has_udp_mirror: bool,
    pub hdr_capability: String,
    pub volume_control_type: i64,
    pub initial_volume: f64,
    pub keep_alive_body: bool,
    pub psi: String,
    pub pi: String,
    pub mac_address: String,
    pub displays: Vec<DisplayInfo>,
}

impl ReceiverInfo {
    /// Receiver's primary display resolution in pixels, or `(0, 0)` if the
    /// receiver did not advertise a usable display size. Faithful port of the
    /// Go `DisplaySize`: prefer `widthPixels`/`heightPixels`, fall back to
    /// `width`/`height`, else `(0, 0)`.
    pub fn display_size(&self) -> (u32, u32) {
        if self.displays.is_empty() {
            return (0, 0);
        }
        let d = &self.displays[0];
        let (mut w, mut h) = (d.width_pixels, d.height_pixels);
        if w <= 0 || h <= 0 {
            w = d.width;
            h = d.height;
        }
        if w <= 0 || h <= 0 {
            return (0, 0);
        }
        (w as u32, h as u32)
    }

    /// Whether the receiver advertises FairPlay SAP (feature bit 14). Port of
    /// `(*ReceiverInfo).SupportsFairPlaySAP` (discovery.go:161-163). This gates
    /// the playout latency floor (modern Apple receivers set it; Roku/3rd-party
    /// implementations do not).
    pub fn supports_fairplay_sap(&self) -> bool {
        self.features & crate::discovery::FEATURE_FPSAP25 != 0
    }

    /// Minimum playout lead this receiver needs. Port of
    /// `(*ReceiverInfo).playoutLatencyFloor` (discovery.go:170-175): 0 when the
    /// receiver advertises FairPlay SAP (robust jitter buffers, can play at very
    /// low latency), else the conservative 500ms floor.
    pub fn playout_latency_floor(&self) -> std::time::Duration {
        if self.supports_fairplay_sap() {
            std::time::Duration::ZERO
        } else {
            crate::latency::CONSERVATIVE_PLAYOUT_LATENCY
        }
    }
}

/// Run `GET /info` against the receiver and parse the response plist.
/// Faithful port of `AirPlayClient.GetInfo`: method GET, path `/info`,
/// content-type `application/x-apple-binary-plist`, empty body.
pub fn get_info(transport: &mut Transport) -> Result<ReceiverInfo> {
    let resp = transport
        .request("GET", "/info", "application/x-apple-binary-plist", &[], &[])
        .context("GET /info")?;
    parse_info(&resp.body)
}

fn parse_info(body: &[u8]) -> Result<ReceiverInfo> {
    use plist::Value;

    let v = Value::from_reader(std::io::Cursor::new(body)).context("decode info plist")?;
    let dict = v
        .as_dictionary()
        .context("info plist is not a dictionary")?;

    let mut info = ReceiverInfo::default();

    if let Some(s) = dict.get("name").and_then(|v| v.as_string()) {
        info.name = s.to_string();
    }
    if let Some(s) = dict.get("model").and_then(|v| v.as_string()) {
        info.model = s.to_string();
    }
    if let Some(s) = dict.get("manufacturer").and_then(|v| v.as_string()) {
        info.manufacturer = s.to_string();
    }
    if let Some(s) = dict.get("deviceID").and_then(|v| v.as_string()) {
        info.device_id = s.to_string();
    }
    if let Some(s) = dict.get("protocolVersion").and_then(|v| v.as_string()) {
        info.protocol_version = s.to_string();
    }
    if let Some(s) = dict.get("sourceVersion").and_then(|v| v.as_string()) {
        info.source_version = s.to_string();
    }
    if let Some(n) = dict.get("features").and_then(as_u64) {
        info.features = n;
    }
    if let Some(n) = dict.get("statusFlags").and_then(as_u64) {
        info.status_flags = n;
    }
    if let Some(Value::Data(d)) = dict.get("pk") {
        info.pk = d.clone();
    }
    if let Some(b) = dict.get("hasUDPMirroringSupport").and_then(|v| v.as_boolean()) {
        info.has_udp_mirror = b;
    }
    if let Some(s) = dict.get("receiverHDRCapability").and_then(|v| v.as_string()) {
        info.hdr_capability = s.to_string();
    }
    if let Some(n) = dict.get("volumeControlType").and_then(as_i64) {
        info.volume_control_type = n;
    }
    if let Some(f) = dict.get("initialVolume").and_then(|v| v.as_real()) {
        info.initial_volume = f;
    }
    if let Some(b) = dict
        .get("keepAliveSendStatsAsBody")
        .and_then(|v| v.as_boolean())
    {
        info.keep_alive_body = b;
    }
    if let Some(s) = dict.get("psi").and_then(|v| v.as_string()) {
        info.psi = s.to_string();
    }
    if let Some(s) = dict.get("pi").and_then(|v| v.as_string()) {
        info.pi = s.to_string();
    }
    if let Some(s) = dict.get("macAddress").and_then(|v| v.as_string()) {
        info.mac_address = s.to_string();
    }

    if let Some(arr) = dict.get("displays").and_then(|v| v.as_array()) {
        for d in arr {
            let dd = match d.as_dictionary() {
                Some(dd) => dd,
                None => continue,
            };
            info.displays.push(DisplayInfo {
                width: dd.get("width").and_then(as_i64).unwrap_or(0),
                height: dd.get("height").and_then(as_i64).unwrap_or(0),
                width_pixels: dd.get("widthPixels").and_then(as_i64).unwrap_or(0),
                height_pixels: dd.get("heightPixels").and_then(as_i64).unwrap_or(0),
            });
        }
    }

    Ok(info)
}

fn as_i64(v: &plist::Value) -> Option<i64> {
    if let Some(i) = v.as_signed_integer() {
        Some(i)
    } else {
        v.as_unsigned_integer().map(|u| u as i64)
    }
}

fn as_u64(v: &plist::Value) -> Option<u64> {
    if let Some(u) = v.as_unsigned_integer() {
        Some(u)
    } else {
        v.as_signed_integer().map(|i| i as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_size_prefers_pixels() {
        let mut info = ReceiverInfo::default();
        info.displays.push(DisplayInfo {
            width: 1920,
            height: 1080,
            width_pixels: 3840,
            height_pixels: 2160,
        });
        assert_eq!(info.display_size(), (3840, 2160));
    }

    #[test]
    fn display_size_falls_back_to_width_height() {
        let mut info = ReceiverInfo::default();
        info.displays.push(DisplayInfo {
            width: 1280,
            height: 720,
            width_pixels: 0,
            height_pixels: 0,
        });
        assert_eq!(info.display_size(), (1280, 720));
    }

    #[test]
    fn display_size_zero_when_absent() {
        let info = ReceiverInfo::default();
        assert_eq!(info.display_size(), (0, 0));
    }
}
