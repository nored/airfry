//! AirFry underscan slider — a tiny, SINGLE-INSTANCE GTK4 popup.
//!
//! Launched by the tray's "Underscan…" item with the active receiver's
//! `ip:port` (and name) as argv. Underscan is PER APPLE TV, so the slider edits
//! that device's `underscan_pct` inside the `devices` array of
//! `~/.config/airfry/config.json` (falling back to the top-level default when no
//! device is given / found). airfry applies it live to a running mirror and on
//! the next connect otherwise.
//!
//! Single-instance: GApplication registers a unique application-id, so a second
//! launch just `present()`s the existing window — NEVER a second window. The id
//! MUST have no hyphen in its final segment; a hyphen silently breaks the
//! single-instance registration (that was the old "infinite twin windows" bug).

use libadwaita as adw;

use adw::prelude::*;
use adw::{Application, ApplicationWindow, HeaderBar, WindowTitle};
use gtk4::{Align, Box as GtkBox, Justification, Label, Orientation, PositionType, Scale};
use std::path::PathBuf;

const MAX: f64 = 15.0;
const APP_ID: &str = "io.github.nored.AirfryUnderscan"; // no hyphen → single-instance OK

fn config_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from(".config"));
    base.join("airfry").join("config.json")
}

/// Does this `devices[]` entry match the "ip:port" addr the tray passed?
fn device_matches(d: &serde_json::Value, addr: &str) -> bool {
    let ip = d.get("ip").and_then(|x| x.as_str()).unwrap_or("");
    let port = d.get("port").and_then(|x| x.as_u64()).unwrap_or(0);
    format!("{ip}:{port}") == addr
}

/// Load the underscan for `addr`'s device entry (or the top-level default when
/// no addr / device is found).
fn load_underscan(addr: &str) -> f64 {
    if let Ok(s) = std::fs::read_to_string(config_path()) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) {
            if !addr.is_empty() {
                if let Some(d) = v
                    .get("devices")
                    .and_then(|d| d.as_array())
                    .and_then(|devs| devs.iter().find(|d| device_matches(d, addr)))
                {
                    let n = d.get("underscan_pct").and_then(|x| x.as_u64()).unwrap_or(0);
                    return (n as f64).clamp(0.0, MAX);
                }
            }
            if let Some(n) = v.get("underscan_pct").and_then(|x| x.as_u64()) {
                return (n as f64).clamp(0.0, MAX);
            }
        }
    }
    0.0
}

/// Read-modify-write the PER-DEVICE `underscan_pct` (preserving everything
/// else). Falls back to the top-level default when no device matches.
fn save_underscan(addr: &str, pct: u8) {
    let path = config_path();
    let mut v: serde_json::Value = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    if !v.is_object() {
        v = serde_json::json!({});
    }
    let mut wrote = false;
    if !addr.is_empty() {
        if let Some(devs) = v.get_mut("devices").and_then(|d| d.as_array_mut()) {
            for d in devs.iter_mut() {
                if device_matches(d, addr) {
                    d["underscan_pct"] = serde_json::json!(pct);
                    wrote = true;
                    break;
                }
            }
        }
    }
    if !wrote {
        v["underscan_pct"] = serde_json::json!(pct);
    }
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(s) = serde_json::to_string_pretty(&v) {
        let _ = std::fs::write(&path, s);
    }
}

fn main() {
    // argv: [1] = active receiver "ip:port", [2] = its display name (both optional).
    let args: Vec<String> = std::env::args().collect();
    let addr = args.get(1).cloned().unwrap_or_default();
    let name = args.get(2).cloned().unwrap_or_default();

    let app = Application::builder().application_id(APP_ID).build();
    app.connect_activate(move |a| build_ui(a, &addr, &name));
    // Pass only the program name so GApplication doesn't try to parse the device
    // argv as its own options.
    app.run_with_args(&["airfry-underscan"]);
}

fn build_ui(app: &Application, addr: &str, name: &str) {
    // Single-instance: if our window already exists, just raise it.
    if let Some(win) = app.active_window() {
        win.present();
        return;
    }

    let cur = load_underscan(addr);

    // Big current-value readout (uses the system accent colour via libadwaita).
    let value = Label::new(Some(&format!("{}%", cur as u8)));
    value.add_css_class("title-1");
    value.add_css_class("accent");
    value.set_halign(Align::Center);

    let scale = Scale::with_range(Orientation::Horizontal, 0.0, MAX, 1.0);
    scale.set_value(cur);
    scale.set_hexpand(true);
    scale.set_draw_value(false);
    scale.set_width_request(320);
    for i in 0..=(MAX as i32) {
        let label = if i % 5 == 0 {
            Some(format!("{i}"))
        } else {
            None
        };
        scale.add_mark(i as f64, PositionType::Bottom, label.as_deref());
    }

    let hint = Label::new(Some(
        "Shrinks the picture toward the centre to fit a TV that\n\
         zooms the mirror past the edges. Applies live while mirroring.",
    ));
    hint.set_halign(Align::Center);
    hint.set_justify(Justification::Center);
    hint.add_css_class("dim-label");

    let value_cb = value.clone();
    let addr_cb = addr.to_string();
    scale.connect_value_changed(move |s| {
        let pct = s.value().round() as u8;
        value_cb.set_text(&format!("{pct}%"));
        save_underscan(&addr_cb, pct);
    });

    let content = GtkBox::new(Orientation::Vertical, 14);
    content.set_margin_top(18);
    content.set_margin_bottom(24);
    content.set_margin_start(24);
    content.set_margin_end(24);
    content.append(&value);
    content.append(&scale);
    content.append(&hint);

    // Native libadwaita chrome: a header bar above the content, in a vertical box.
    let header = HeaderBar::new();
    let subtitle = if name.is_empty() {
        "AirFry".to_string()
    } else {
        format!("AirFry · {name}")
    };
    header.set_title_widget(Some(&WindowTitle::new("Underscan", &subtitle)));

    let root = GtkBox::new(Orientation::Vertical, 0);
    root.append(&header);
    root.append(&content);

    let win = ApplicationWindow::builder()
        .application(app)
        .default_width(400)
        .resizable(false)
        .content(&root)
        .build();
    win.present();
}
