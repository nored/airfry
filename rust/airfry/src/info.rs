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

/// The subset of GET /info we consume. Mirrors the Go `ReceiverInfo` fields the
/// connection path actually reads (identity key, features, display geometry).
#[derive(Default, Clone, Debug)]
pub struct ReceiverInfo {
    pub name: String,
    pub model: String,
    pub source_version: String,
    pub features: u64,
    pub status_flags: u64,
    /// Receiver ed25519 long-term public key (`pk`); empty if not advertised.
    pub pk: Vec<u8>,
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
