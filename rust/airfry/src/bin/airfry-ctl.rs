//! `airfry-ctl` — control CLI for the AirFry daemon.
//!
//! A faithful Rust port of doubletake's `cmd/doubletake-ctl/main.go`. Talks to a
//! running daemon over its Unix socket via `daemonclient::Client` and prints the
//! JSON `Response` (pretty-printed), exiting non-zero when the daemon reports
//! `ok=false` — exactly like the Go ctl.
//!
//! This binary is deliberately LIGHTWEIGHT: it only needs the wire protocol
//! (`protocol.rs`) and the IPC client (`daemonclient.rs`), neither of which pull
//! in the mirror/capture/rtsp/tray stack. We include just those two modules as
//! this binary's own crate roots via `#[path]`, so `airfry-ctl` builds without
//! the Qt/GStreamer link dependencies the main `airfry` binary carries.
//!
//! Subcommands:
//!   status                      Show daemon state and all active streams
//!   discover                    Discover AirPlay devices on the network
//!   devices                     List cached discovered devices
//!   connect [target] [pin]      Start mirroring (to target IP, or first free device)
//!   pin <PIN>                   Submit a PIN for a device parked for pairing
//!   disconnect [target]         Stop mirroring (all streams, or only the given IP)
//!   mute [target]               Mute mirrored audio (all, or only the given IP)
//!   unmute [target]             Unmute mirrored audio (all, or only the given IP)
//!
//! Flag:
//!   --socket <path>             Override the daemon socket path.

#[path = "../protocol.rs"]
mod protocol;
#[path = "../daemonclient.rs"]
mod daemonclient;

use std::process::exit;

use daemonclient::Client;
use protocol::{default_socket_path, Response};

fn main() {
    let argv: Vec<String> = std::env::args().collect();

    // Parse a leading `--socket <path>` (also accept Go-style `-socket`).
    let mut socket_path = default_socket_path();
    let mut args: Vec<String> = Vec::new();
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--socket" | "-socket" => {
                i += 1;
                match argv.get(i) {
                    Some(p) => socket_path = p.into(),
                    None => {
                        eprintln!("error: --socket requires a path");
                        exit(2);
                    }
                }
            }
            s if s.starts_with("--socket=") => {
                socket_path = s.trim_start_matches("--socket=").into();
            }
            s if s.starts_with("-socket=") => {
                socket_path = s.trim_start_matches("-socket=").into();
            }
            _ => args.push(argv[i].clone()),
        }
        i += 1;
    }

    if args.is_empty() {
        usage(&socket_path.display().to_string());
        exit(1);
    }

    let client = Client::new(&socket_path);
    let cmd = args[0].as_str();

    let result: anyhow::Result<Response> = match cmd {
        "status" => client.status(),
        "discover" => client.discover(),
        "devices" => client.devices(),
        "connect" => {
            let target = args.get(1).map(String::as_str).unwrap_or("");
            let pin = args.get(2).map(String::as_str).unwrap_or("");
            client.connect(target, 0, pin)
        }
        "pin" => {
            if args.len() < 2 {
                eprintln!("Usage: airfry-ctl pin <4-digit-PIN>");
                exit(1);
            }
            client.pin(&args[1])
        }
        "disconnect" => {
            if let Some(target) = args.get(1) {
                client.disconnect_target(target)
            } else {
                client.disconnect()
            }
        }
        "mute" => {
            if let Some(target) = args.get(1) {
                client.mute_target(target)
            } else {
                client.mute()
            }
        }
        "unmute" => {
            if let Some(target) = args.get(1) {
                client.unmute_target(target)
            } else {
                client.unmute()
            }
        }
        other => {
            eprintln!("unknown command: {other}");
            usage(&socket_path.display().to_string());
            exit(1);
        }
    };

    let resp = match result {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e:#}");
            exit(1);
        }
    };

    // Pretty-print the response (Go uses enc.SetIndent("", "  ")).
    match serde_json::to_string_pretty(&resp) {
        Ok(s) => println!("{s}"),
        Err(e) => {
            eprintln!("error: encode response: {e}");
            exit(1);
        }
    }

    if !resp.ok {
        exit(1);
    }
}

fn usage(socket: &str) {
    eprintln!(
        "Usage: airfry-ctl [--socket path] <command> [args]\n\n\
         Commands:\n  \
           status                      Show daemon state and all active streams\n  \
           discover                    Discover AirPlay devices on the network\n  \
           devices                     List cached discovered devices\n  \
           connect [target] [pin]      Start mirroring (to target IP, or first free device)\n  \
           pin <4-digit-PIN>           Submit PIN for a device waiting for pairing\n  \
           disconnect [target]         Stop mirroring (all streams, or only the given IP)\n  \
           mute [target]               Mute mirrored audio (all streams, or only the given IP)\n  \
           unmute [target]             Unmute mirrored audio (all streams, or only the given IP)\n\n\
         Flags:\n  \
           --socket path               Override daemon socket path (default: {socket})"
    );
}
