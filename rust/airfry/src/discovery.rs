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
    // Prefer an IPv4 address, falling back to IPv6 only when no IPv4 is
    // advertised — matches discovery.go:65-69, which uses entry.AddrIPv4[0]
    // and only drops to AddrIPv6[0] when no IPv4 exists. get_addresses() is an
    // unordered HashSet, so we must filter rather than take the first element.
    let addr = select_address(info.get_addresses().iter().copied())?;

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

/// Select the address to use for a resolved service, preferring IPv4 and only
/// falling back to IPv6 when no IPv4 is present. mdns-sd returns addresses as an
/// unordered set, so order is not meaningful; this filter is what makes the
/// choice deterministic and matches discovery.go:65-69 (AddrIPv4[0], else
/// AddrIPv6[0]).
fn select_address<I>(addrs: I) -> Option<std::net::IpAddr>
where
    I: IntoIterator<Item = std::net::IpAddr>,
{
    let mut first_v6: Option<std::net::IpAddr> = None;
    for a in addrs {
        if a.is_ipv4() {
            return Some(a);
        }
        if first_v6.is_none() {
            first_v6 = Some(a);
        }
    }
    first_v6
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

/// Parse a hex field with Go `fmt.Sscanf(s, "0x%x", &v)` semantics: the literal
/// `0x` prefix is required (Sscanf returns 0 if it does not match), then the
/// LEADING run of hex digits is consumed and any trailing junk is tolerated.
/// `from_str_radix` (the old impl) instead failed the whole field on any
/// non-hex char, yielding 0 where Go would parse a value — a wire divergence.
fn parse_hex_u64(s: &str) -> u64 {
    // Sscanf skips leading whitespace before matching the `0x` literal.
    let s = s.trim_start();
    // The `0x` prefix is part of the format string, so it must be present.
    // (`0X` does not match `0x` under Sscanf, so only lowercase is accepted.)
    let Some(rest) = s.strip_prefix("0x") else {
        return 0;
    };
    // Consume the leading run of hex digits; stop at the first non-hex byte.
    let mut v: u64 = 0;
    let mut any = false;
    for c in rest.chars() {
        match c.to_digit(16) {
            Some(d) => {
                v = v.wrapping_mul(16).wrapping_add(d as u64);
                any = true;
            }
            None => break,
        }
    }
    // No hex digits after `0x` -> Sscanf matches nothing, leaving v at 0.
    let _ = any;
    v
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn select_address_prefers_ipv4_over_ipv6() {
        // mdns-sd hands us an unordered set; even with the IPv6 address listed
        // first, we must pick the IPv4 one (discovery.go:65-69).
        let v6: IpAddr = "fe80::1".parse().unwrap();
        let v4: IpAddr = "192.168.1.50".parse().unwrap();
        assert_eq!(select_address([v6, v4]), Some(v4));
        assert_eq!(select_address([v4, v6]), Some(v4));
    }

    #[test]
    fn select_address_falls_back_to_ipv6() {
        let v6: IpAddr = "2001:db8::5".parse().unwrap();
        assert_eq!(select_address([v6]), Some(v6));
        assert_eq!(select_address(std::iter::empty()), None);
    }

    #[test]
    fn parse_hex_u64_sscanf_semantics() {
        // Leading hex run after 0x, trailing junk tolerated.
        assert_eq!(parse_hex_u64("0x1F"), 0x1F);
        assert_eq!(parse_hex_u64("0x1F,garbage"), 0x1F);
        assert_eq!(parse_hex_u64("0xabcdef something"), 0xabcdef);
        // Missing 0x prefix -> Sscanf matches nothing -> 0.
        assert_eq!(parse_hex_u64("1F"), 0);
        // 0X (uppercase) is not the literal 0x -> 0.
        assert_eq!(parse_hex_u64("0X1F"), 0);
        // No hex after prefix -> 0.
        assert_eq!(parse_hex_u64("0x"), 0);
    }

    #[test]
    fn parse_features_combines_lo_hi() {
        // "0xLOW,0xHIGH" -> hi<<32 | lo.
        assert_eq!(parse_features("0x1,0x2"), (2u64 << 32) | 1);
        // Wrong part count falls back to the single Sscanf-style parse.
        assert_eq!(parse_features("0xabc"), 0xabc);
    }
}
