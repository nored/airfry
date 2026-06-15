//! mDNS discovery of AirPlay receivers — faithful port of doubletake's
//! internal/airplay/discovery.go, using the pure-Rust `mdns-sd` crate.

use std::time::Duration;

use mdns_sd::{ServiceDaemon, ServiceEvent};

/// A discovered AirPlay receiver.
#[derive(Debug, Clone, Default)]
pub struct AirPlayDevice {
    pub name: String,
    pub model: String,
    pub ip: String,
    pub port: u16,
    pub device_id: String,
    pub features: u64,
    pub pk: String, // hex Ed25519 public key
    pub flags: u64,
}

// Feature bits advertised by AirPlay receivers.
pub const FEATURE_SCREEN: u64 = 1 << 8;
pub const FEATURE_AUDIO: u64 = 1 << 10;
pub const FEATURE_FPSAP25: u64 = 1 << 14;
pub const FEATURE_HOMEKIT_PAIRING: u64 = 1 << 17;
pub const FEATURE_TRANSIENT_PAIRING: u64 = 1 << 19;
pub const FEATURE_UDP_MIRRORING: u64 = 1 << 49;

impl AirPlayDevice {
    pub fn supports_screen(&self) -> bool {
        self.features & FEATURE_SCREEN != 0
    }
    pub fn supports_transient_pairing(&self) -> bool {
        self.features & FEATURE_TRANSIENT_PAIRING != 0
    }
    pub fn supports_fairplay_sap(&self) -> bool {
        self.features & FEATURE_FPSAP25 != 0
    }
}

/// Browse `_airplay._tcp.local.` for the given duration and return receivers.
pub fn discover(timeout: Duration) -> anyhow::Result<Vec<AirPlayDevice>> {
    let daemon = ServiceDaemon::new()?;
    let receiver = daemon.browse("_airplay._tcp.local.")?;

    let deadline = std::time::Instant::now() + timeout;
    let mut devices: Vec<AirPlayDevice> = Vec::new();

    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match receiver.recv_timeout(remaining) {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                if let Some(dev) = parse_resolved(&info) {
                    if !devices.iter().any(|d| d.ip == dev.ip && d.port == dev.port) {
                        devices.push(dev);
                    }
                }
            }
            Ok(_) => {}
            Err(_) => break, // timeout
        }
    }

    let _ = daemon.shutdown();
    Ok(devices)
}

fn parse_resolved(info: &mdns_sd::ServiceInfo) -> Option<AirPlayDevice> {
    let addr = info.get_addresses().iter().next().copied()?;

    let mut dev = AirPlayDevice {
        name: unescape_dns_name(info.get_fullname().split('.').next().unwrap_or("")),
        ip: addr.to_string(),
        port: info.get_port(),
        ..Default::default()
    };

    let props = info.get_properties();
    if let Some(v) = props.get_property_val_str("model") {
        dev.model = v.to_string();
    }
    if let Some(v) = props.get_property_val_str("deviceid") {
        dev.device_id = v.to_string();
    }
    if let Some(v) = props.get_property_val_str("pk") {
        dev.pk = v.to_string();
    }
    if let Some(v) = props.get_property_val_str("features") {
        dev.features = parse_features(v);
    }
    if let Some(v) = props.get_property_val_str("flags") {
        dev.flags = parse_hex_u64(v);
    }

    Some(dev)
}

/// Parse the AirPlay features string "0xLOW,0xHIGH" into a 64-bit value.
fn parse_features(s: &str) -> u64 {
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() != 2 {
        return parse_hex_u64(s);
    }
    let lo = parse_hex_u64(parts[0]);
    let hi = parse_hex_u64(parts[1]);
    (hi << 32) | lo
}

fn parse_hex_u64(s: &str) -> u64 {
    let s = s.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u64::from_str_radix(s, 16).unwrap_or(0)
}

/// Remove DNS-SD backslash escapes from an mDNS instance name.
/// e.g. "Living\ Room\ \(2\)" -> "Living Room (2)".
fn unescape_dns_name(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'\\' && i + 1 < b.len() {
            if i + 3 < b.len()
                && b[i + 1].is_ascii_digit()
                && b[i + 2].is_ascii_digit()
                && b[i + 3].is_ascii_digit()
            {
                if let Ok(v) = std::str::from_utf8(&b[i + 1..i + 4]).unwrap_or("").parse::<u16>() {
                    if v <= 255 {
                        out.push(v as u8);
                        i += 4;
                        continue;
                    }
                }
            }
            // plain escaped char
            out.push(b[i + 1]);
            i += 2;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
