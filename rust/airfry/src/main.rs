#![allow(dead_code)]
//! AirFry — a native Linux AirPlay screen-mirroring sender for Apple TV.
//!
//! Reuses the in-house Rust FairPlay core (`fpemu`). The protocol stack
//! (discovery, pairing, RTSP, mirror stream) is ported from doubletake
//! (research-only submodule; see third_party/doubletake) — credit: omarroth.

mod discovery;
mod playfair;

use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("help");

    let code = match cmd {
        "discover" | "scan" => cmd_discover(),
        "version" | "--version" | "-V" => {
            println!("airfry {}", env!("CARGO_PKG_VERSION"));
            0
        }
        _ => {
            print_help();
            0
        }
    };
    std::process::exit(code);
}

fn print_help() {
    println!(
        "airfry {} — Linux AirPlay screen-mirroring sender\n\n\
         USAGE:\n  \
           airfry discover            Scan the network for AirPlay receivers\n  \
           airfry version             Print version\n\n\
         More subcommands (pair, mirror) land as the pipeline is built.",
        env!("CARGO_PKG_VERSION")
    );
}

fn cmd_discover() -> i32 {
    eprintln!("Scanning for AirPlay receivers (5s)…");
    match discovery::discover(Duration::from_secs(5)) {
        Ok(devs) if devs.is_empty() => {
            println!("No AirPlay receivers found.");
            0
        }
        Ok(devs) => {
            for d in &devs {
                let mut tags = Vec::new();
                if d.supports_screen() {
                    tags.push("screen");
                }
                if d.supports_fairplay_sap() {
                    tags.push("fairplay-sap");
                }
                if d.supports_transient_pairing() {
                    tags.push("transient-pair");
                }
                let model = if d.model.is_empty() { "?" } else { &d.model };
                println!(
                    "• {}  [{}]  {}:{}  ({})",
                    d.name,
                    model,
                    d.ip,
                    d.port,
                    tags.join(", ")
                );
            }
            0
        }
        Err(e) => {
            eprintln!("discovery failed: {e}");
            1
        }
    }
}
