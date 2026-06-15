#![allow(dead_code)]
//! AirFry — a native Linux AirPlay screen-mirroring sender for Apple TV.
//!
//! Reuses the in-house Rust FairPlay core (`fpemu`). The protocol stack
//! (discovery, pairing, RTSP, mirror stream) is ported from doubletake
//! (research-only submodule; see third_party/doubletake) — credit: omarroth.

mod discovery;
mod fairplay;
mod pairing;
mod playfair;
mod rtsp;
mod tlv8;

use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("help");

    let code = match cmd {
        "discover" | "scan" => cmd_discover(),
        "pair" => cmd_pair(&args),
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
           airfry pair <host[:port]>  Connect + pair + fp-setup against a receiver\n  \
           airfry version             Print version\n\n\
         More subcommands (mirror) land as the pipeline is built.",
        env!("CARGO_PKG_VERSION")
    );
}

fn cmd_pair(args: &[String]) -> i32 {
    let target = match args.get(2) {
        Some(t) => t.as_str(),
        None => {
            eprintln!("usage: airfry pair <host[:port]>");
            return 2;
        }
    };
    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) => (h.to_string(), port),
            Err(_) => {
                eprintln!("invalid port in '{target}'");
                return 2;
            }
        },
        None => (target.to_string(), 7000u16),
    };
    // Optional 4th arg: PIN (empty => transient pairing).
    let pin = args.get(3).map(String::as_str).unwrap_or("");

    eprintln!("Connecting to {host}:{port} (pin={:?})…", pin);
    let mut report = |phase: &str, ok: bool, detail: &str| {
        let mark = if ok { "OK " } else { "FAIL" };
        println!("[{mark}] {phase}: {detail}");
    };

    match rtsp::Session::connect_host_with(&host, port, pin, &mut report) {
        Ok(session) => {
            println!("\nSession established.");
            println!(
                "  stream key : {}",
                hex_str(&session.stream_key)
            );
            println!("  stream iv  : {}", hex_str(&session.iv));
            println!("  ekey       : {} bytes", session.ekey.len());
            println!(
                "  shared sec : {} bytes",
                session.pair_keys.shared_secret.len()
            );
            println!("  pairing id : {}", session.pairing_id);
            println!("  session id : {}", session.session_id);
            println!(
                "  encrypted  : {}",
                session.transport.is_encrypted()
            );
            0
        }
        Err(e) => {
            eprintln!("\npairing failed: {e:#}");
            1
        }
    }
}

fn hex_str(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
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
