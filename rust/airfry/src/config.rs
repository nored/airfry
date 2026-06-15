//! Persistent app configuration — the "persistence layer for the servers".
//!
//! A faithful port of the Go `internal/daemon/config.go`: a single JSON file at
//! `~/.config/airfry/config.json` holding the chosen underscan percent AND a
//! cached list of discovered receivers, so the tray menu is populated INSTANTLY
//! on launch (before any scan) and survives restarts. Discovery only refreshes
//! this cache when the user opens the menu (see `tray.rs`).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// A remembered AirPlay receiver (the persisted form of a discovered device).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub name: String,
    #[serde(default)]
    pub model: String,
    /// Receiver IP address.
    #[serde(rename = "ip")]
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub device_id: String,
    /// Per-receiver underscan percent (0..=15). Every Apple TV overscans
    /// differently, so this is saved PER DEVICE, not globally.
    #[serde(rename = "underscan_pct", default)]
    pub underscan: u8,
}

impl Device {
    /// "ip:port" address used as the menu action key.
    pub fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// The persisted app configuration (`~/.config/airfry/config.json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    /// Legacy/global default underscan (0..=15). Underscan is now stored PER
    /// DEVICE (`Device::underscan`); this remains only as the fallback for a
    /// device that has never been adjusted, and for migrating old config files.
    #[serde(rename = "underscan_pct", default)]
    pub underscan: u8,
    /// Cached device list for an instant menu next launch.
    #[serde(default)]
    pub devices: Vec<Device>,
}

/// `~/.config/airfry/config.json` under `$XDG_CONFIG_HOME` (or `~/.config`).
pub fn config_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("airfry").join("config.json"))
}

impl Config {
    /// Read the saved config (zero value if absent/unreadable), clamping the
    /// underscan to the supported 0..=15 range.
    pub fn load() -> Config {
        let Some(path) = config_path() else {
            return Config::default();
        };
        let mut cfg: Config = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        cfg.underscan = cfg.underscan.min(15);
        for d in &mut cfg.devices {
            d.underscan = d.underscan.min(15);
        }
        cfg
    }

    /// The underscan for a specific receiver (by "ip:port"), falling back to the
    /// global default for a device not yet in the cache / never adjusted.
    pub fn underscan_for(&self, addr: &str) -> u8 {
        self.devices
            .iter()
            .find(|d| d.addr() == addr)
            .map(|d| d.underscan)
            .unwrap_or(self.underscan)
            .min(15)
    }

    /// Set a receiver's underscan (by "ip:port"). If the device isn't cached
    /// yet, fall back to updating the global default so the value isn't lost.
    pub fn set_underscan_for(&mut self, addr: &str, pct: u8) {
        let pct = pct.min(15);
        if let Some(d) = self.devices.iter_mut().find(|d| d.addr() == addr) {
            d.underscan = pct;
        } else {
            self.underscan = pct;
        }
    }

    /// Write the config, creating the directory as needed (best-effort).
    pub fn save(&self) {
        let Some(path) = config_path() else { return };
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(&path, json);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(host: &str, port: u16, under: u8) -> Device {
        Device {
            name: host.into(),
            host: host.into(),
            port,
            underscan: under,
            ..Default::default()
        }
    }

    #[test]
    fn per_device_underscan_lookup_and_set() {
        let mut cfg = Config {
            underscan: 3, // global default
            devices: vec![dev("10.0.0.1", 7000, 8), dev("10.0.0.2", 7000, 0)],
        };
        // Known device → its own value; unknown → global default.
        assert_eq!(cfg.underscan_for("10.0.0.1:7000"), 8);
        assert_eq!(cfg.underscan_for("10.0.0.2:7000"), 0);
        assert_eq!(cfg.underscan_for("10.0.0.9:7000"), 3);

        // Setting a known device updates only that device, not the global/others.
        cfg.set_underscan_for("10.0.0.2:7000", 12);
        assert_eq!(cfg.underscan_for("10.0.0.2:7000"), 12);
        assert_eq!(cfg.underscan_for("10.0.0.1:7000"), 8);
        assert_eq!(cfg.underscan, 3);

        // Clamp to 15.
        cfg.set_underscan_for("10.0.0.1:7000", 99);
        assert_eq!(cfg.underscan_for("10.0.0.1:7000"), 15);
    }

    #[test]
    fn legacy_global_underscan_deserializes() {
        // Old config files only had a top-level underscan_pct; it survives as the
        // fallback for devices that have never been adjusted.
        let cfg: Config = serde_json::from_str(r#"{"underscan_pct":7,"devices":[]}"#).unwrap();
        assert_eq!(cfg.underscan, 7);
        assert_eq!(cfg.underscan_for("1.2.3.4:7000"), 7);
    }
}
