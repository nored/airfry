#![allow(dead_code)]
//! AirFry — a native Linux AirPlay screen-mirroring sender for Apple TV.
//!
//! Reuses the in-house Rust FairPlay core (`fpemu`). The protocol stack
//! (discovery, pairing, RTSP, mirror stream) is ported from doubletake
//! (research-only submodule; see third_party/doubletake) — credit: omarroth.

mod audio;
mod broadcast;
mod capture;
mod credentials;
mod daemon;
mod daemonclient;
mod discovery;
mod fairplay;
mod info;
mod latency;
mod mirror;
mod pairing;
mod playfair;
mod protocol;
mod rtsp;
mod tlv8;
mod tray;

use std::cmp::Ordering as CmpOrdering;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use mirror::MirrorControl;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // doubletake's -target-latency-ms defaults to 100ms (main.go:59); its
    // latency.init sets only 1ms, so the effective default is 100ms. Match it.
    latency::set_target_latency(Duration::from_millis(100));
    // The tray widget is the default face of the app: with no subcommand we
    // launch it. Explicit subcommands keep working for headless/CLI use.
    let cmd = args.get(1).map(String::as_str).unwrap_or("tray");

    // `--daemonize` (or the `daemon` subcommand) is a top-level mode in
    // doubletake (main.go:75-78): it runs the Unix-socket control daemon and
    // returns before any discovery/mirror flow. Accept it as the first arg or
    // anywhere via `mirror --daemonize` (handled inside cmd_mirror).
    let code = match cmd {
        "daemon" | "--daemonize" => cmd_daemon(&args),
        "tray" => tray::run_tray(),
        "discover" | "scan" => cmd_discover(&args),
        "pair" => cmd_pair(&args),
        "mirror" => cmd_mirror(&args),
        "version" | "--version" | "-V" => {
            println!("airfry {}", env!("CARGO_PKG_VERSION"));
            0
        }
        "help" | "--help" | "-h" => {
            print_help();
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
        "airfry {ver} — Linux AirPlay screen-mirroring sender\n\n\
         USAGE:\n  \
           airfry discover                Scan the network for AirPlay receivers\n  \
           airfry pair [host[:port]]      Connect + pair + fp-setup against a receiver\n  \
           airfry mirror [host[:port]]    Mirror this screen to the receiver\n  \
           airfry version                 Print version\n\n\
         When no host is given to `pair`/`mirror`/`discover`, a numbered device\n  \
         picker is shown (read a selection from stdin).\n\n\
         mirror flags:\n  \
           --fit <pct>            Underscan/fit percent (shrink + pad to counter overscan)\n  \
           --bitrate <kbps>       Video bitrate in kbps (0 = auto)\n  \
           --fps <n>              Frames per second (default 30)\n  \
           --pin <pin>            4-digit PIN shown on the Apple TV (forces full pair)\n  \
           --pair                 Force new pairing even if saved credentials exist\n  \
           --creds <path>         Path to saved pairing credentials\n  \
           --cred-backend <b>     Credential backend: file or keyring\n  \
           --target-latency-ms <n>  Target end-to-end latency in ms (default 100)\n  \
           --hwaccel <mode>       Hardware accel: auto, nvenc, vaapi, none\n  \
           --port-range <a-b>     Local UDP/TCP port range (e.g. 60000-60010; >=4 ports)\n  \
           --sw                   Force the software (x264) encoder\n  \
           --no-encrypt           Disable RTSP header encryption (debug)\n  \
           --no-audio             Disable audio streaming\n  \
           --mute                 Stream audio but start muted\n  \
           --test                 Use synthetic video (videotestsrc) for debugging\n  \
           --direct-key           Use shk/shiv directly without SHA-512 derivation\n  \
           --debug                Enable verbose debug logging\n  \
           --daemonize            Run as a background daemon with a Unix socket\n  \
           --socket <path>        Unix socket path for the daemon control interface",
        ver = env!("CARGO_PKG_VERSION")
    );
}

/// Parsed flags common to the `mirror` (and partly `pair`) subcommands, in the
/// shape doubletake's flag set defines them (main.go:51-69).
struct CliFlags {
    pin: String,
    /// Force full re-pair even when saved credentials exist (-pair).
    force_pair: bool,
    /// Custom credential file path (-creds). Threaded through where feasible.
    creds_path: Option<PathBuf>,
    /// Credential backend (-cred-backend): "file" or "keyring".
    cred_backend: String,
    target_latency_ms: u64,
    /// Hardware accel mode (-hwaccel): auto/nvenc/vaapi/none.
    hwaccel: Option<String>,
    debug: bool,
    daemonize: bool,
    socket_path: Option<PathBuf>,
    opts: mirror::MirrorOpts,
}

impl Default for CliFlags {
    fn default() -> Self {
        CliFlags {
            pin: String::new(),
            force_pair: false,
            creds_path: None,
            cred_backend: "file".to_string(),
            target_latency_ms: 100,
            hwaccel: None,
            debug: false,
            daemonize: false,
            socket_path: None,
            opts: mirror::MirrorOpts::default(),
        }
    }
}

/// Parse the flags that follow the subcommand target. `start` is the first arg
/// index to inspect. Returns Err with a usage hint on a bad flag.
fn parse_flags(args: &[String], start: usize) -> Result<CliFlags, String> {
    let mut f = CliFlags::default();
    let mut i = start;
    let next = |i: &mut usize| -> Option<String> {
        *i += 1;
        args.get(*i).cloned()
    };
    while i < args.len() {
        match args[i].as_str() {
            "--fit" => {
                f.opts.fit_pct = next(&mut i).and_then(|s| s.parse().ok()).unwrap_or(0);
            }
            "--bitrate" => {
                f.opts.bitrate_kbps = next(&mut i).and_then(|s| s.parse().ok()).unwrap_or(0);
            }
            "--fps" => {
                f.opts.fps = next(&mut i).and_then(|s| s.parse().ok()).unwrap_or(30);
            }
            "--pin" => {
                f.pin = next(&mut i).unwrap_or_default();
            }
            "--pair" => f.force_pair = true,
            "--creds" => {
                f.creds_path = next(&mut i).map(PathBuf::from);
            }
            "--cred-backend" => {
                f.cred_backend = next(&mut i).unwrap_or_else(|| "file".to_string());
            }
            "--target-latency-ms" => {
                f.target_latency_ms = next(&mut i)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(100);
            }
            "--hwaccel" => {
                f.hwaccel = next(&mut i);
            }
            "--port-range" => {
                let raw = next(&mut i).unwrap_or_default();
                match mirror::parse_port_range(&raw) {
                    Ok(r) => f.opts.port_range = r,
                    Err(e) => return Err(format!("invalid --port-range: {e}")),
                }
            }
            "--sw" => f.opts.force_software_encoder = true,
            "--no-encrypt" => f.opts.no_encrypt = true,
            "--no-audio" => f.opts.no_audio = true,
            "--mute" => f.opts.mute_audio = true,
            "--test" => {
                f.opts.test = true;
            }
            "--direct-key" => f.opts.direct_key = true,
            "--debug" => f.debug = true,
            "--daemonize" => f.daemonize = true,
            "--socket" => {
                f.socket_path = next(&mut i).map(PathBuf::from);
            }
            other => return Err(format!("unknown flag '{other}'")),
        }
        i += 1;
    }
    Ok(f)
}

/// Apply the global side effects of the parsed flags (latency, hwaccel env,
/// credential backend validation). Returns Err with a clear message when a
/// backend/option is unsupported.
fn apply_global_flags(f: &CliFlags) -> Result<(), String> {
    latency::set_target_latency(Duration::from_millis(f.target_latency_ms));
    if let Some(mode) = &f.hwaccel {
        // The capture layer reads the mode from $AIRFRY_HWACCEL (capture.rs
        // hwaccel_mode / env_var("HWACCEL")). Set it so -hwaccel takes effect.
        std::env::set_var("AIRFRY_HWACCEL", mode);
    }
    if f.debug {
        // doubletake sets airplay.DebugMode (main.go:73); airfry has no global
        // debug toggle yet, so expose it via the same env channel as the other
        // settings for any layer that opts to read it.
        std::env::set_var("AIRFRY_DEBUG", "1");
    }
    match f.cred_backend.as_str() {
        "file" => {}
        "keyring" => {
            return Err(
                "credential backend 'keyring' is not implemented; use --cred-backend file"
                    .to_string(),
            )
        }
        other => {
            return Err(format!(
                "unknown credential backend {other:?} (use \"file\" or \"keyring\")"
            ))
        }
    }
    if f.force_pair {
        // -pair forces a fresh pairing even with saved creds. The current rtsp
        // handshake always reuses the default credential store; honoring this
        // requires an rtsp-side toggle, so warn rather than silently ignore.
        eprintln!(
            "[warn] --pair: forced re-pairing is not yet wired through the handshake; \
             saved credentials (if any) will still be reused"
        );
    }
    if f.creds_path.is_some() {
        eprintln!(
            "[warn] --creds: a custom credential path is not yet threaded through the \
             handshake; using the default store"
        );
    }
    Ok(())
}

/// Parse a `host[:port]` target. Defaults to port 7000 when omitted.
fn parse_target(target: &str) -> Result<(String, u16), String> {
    match target.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) => Ok((h.to_string(), port)),
            Err(_) => Err(format!("invalid port in '{target}'")),
        },
        None => Ok((target.to_string(), 7000u16)),
    }
}

/// Read a PIN from stdin (doubletake promptForPIN). Empty -> None.
fn ask_pin() -> Option<String> {
    use std::io::Write;
    eprint!("Enter the PIN shown on the Apple TV: ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    match std::io::stdin().read_line(&mut line) {
        Ok(_) => {
            let p = line.trim().to_string();
            if p.is_empty() {
                None
            } else {
                Some(p)
            }
        }
        Err(_) => None,
    }
}

/// Numerically compare two IP-address strings (doubletake compareIPs,
/// main.go:373-396). Non-IP strings sort after IPs / lexically among themselves.
fn compare_ips(a: &str, b: &str) -> CmpOrdering {
    match (a.parse::<IpAddr>(), b.parse::<IpAddr>()) {
        (Ok(ia), Ok(ib)) => {
            let ba = ip_to_16(ia);
            let bb = ip_to_16(ib);
            ba.cmp(&bb)
        }
        (Err(_), Err(_)) => a.cmp(b),
        (Err(_), Ok(_)) => CmpOrdering::Greater,
        (Ok(_), Err(_)) => CmpOrdering::Less,
    }
}

/// Map an IP to its 16-byte representation (IPv4 -> IPv4-mapped) for ordering,
/// matching Go's `ip.To16()` byte compare.
fn ip_to_16(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// selectDevice (main.go:335-370) — run discovery, print a numbered list sorted
/// numerically by IP, and read a `[N]` selection from stdin. Returns the chosen
/// device, or an error string on failure / invalid input.
fn select_device() -> Result<discovery::AirPlayDevice, String> {
    eprintln!("searching for Apple TVs...");
    let mut devices = match discovery::discover(Duration::from_secs(5)) {
        Ok(d) => d,
        Err(e) => return Err(format!("discovery failed: {e}")),
    };
    if devices.is_empty() {
        return Err("no Apple TVs found".to_string());
    }

    devices.sort_by(|a, b| compare_ips(&a.ip, &b.ip));

    println!("\navailable devices:");
    for (i, d) in devices.iter().enumerate() {
        let model = if d.model.is_empty() { "?" } else { &d.model };
        println!("  [{}] {} ({}) - {}", i + 1, d.name, model, d.ip);
    }

    use std::io::Write;
    print!("\nselect device [1]: ");
    let _ = std::io::stdout().flush();
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return Err("read selection failed".to_string());
    }
    let input = input.trim();
    if input.is_empty() {
        return Ok(devices.into_iter().next().unwrap());
    }
    match input.parse::<usize>() {
        Ok(idx) if idx >= 1 && idx <= devices.len() => Ok(devices.swap_remove(idx - 1)),
        _ => Err("invalid selection".to_string()),
    }
}

/// Resolve the target for `pair`/`mirror`: an explicit `host[:port]` skips the
/// picker; otherwise run selectDevice. The target arg is the first non-flag arg
/// at `args[2]` (when it does not start with '-').
fn resolve_target(args: &[String]) -> Result<((String, u16), usize), String> {
    match args.get(2) {
        Some(t) if !t.starts_with('-') => {
            let hp = parse_target(t)?;
            Ok((hp, 3))
        }
        _ => {
            let dev = select_device()?;
            eprintln!("selected: {} ({}:{})", dev.name, dev.ip, dev.port);
            Ok(((dev.ip, dev.port), 2))
        }
    }
}

fn cmd_pair(args: &[String]) -> i32 {
    let ((host, port), flag_start) = match resolve_target(args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let flags = match parse_flags(args, flag_start) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    if let Err(e) = apply_global_flags(&flags) {
        eprintln!("{e}");
        return 2;
    }

    eprintln!("Connecting to {host}:{port} (pin={:?})…", flags.pin);
    let mut report = |phase: &str, ok: bool, detail: &str| {
        let mark = if ok { "OK " } else { "FAIL" };
        println!("[{mark}] {phase}: {detail}");
    };
    let mut ask = ask_pin;

    match rtsp::Session::connect_host_with(&host, port, &flags.pin, &mut ask, &mut report) {
        Ok(session) => {
            println!("\nSession established.");
            println!("  stream key : {}", hex_str(&session.stream_key));
            println!("  stream iv  : {}", hex_str(&session.iv));
            println!("  ekey       : {} bytes", session.ekey.len());
            println!(
                "  shared sec : {} bytes",
                session.pair_keys.shared_secret.len()
            );
            println!("  pairing id : {}", session.pairing_id);
            println!("  session id : {}", session.session_id);
            println!("  encrypted  : {}", session.transport.is_encrypted());
            0
        }
        Err(e) => {
            eprintln!("\npairing failed: {e:#}");
            1
        }
    }
}

fn cmd_mirror(args: &[String]) -> i32 {
    // --daemonize is dispatched before touching discovery / the target: the
    // daemon resolves its own target over the control socket (main.go:75-78).
    // Peek the raw args so `airfry mirror --daemonize` works without a target.
    if args.iter().skip(2).any(|a| a == "--daemonize") {
        return cmd_daemon(args);
    }

    let ((host, port), flag_start) = match resolve_target(args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let flags = match parse_flags(args, flag_start) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    if let Err(e) = apply_global_flags(&flags) {
        eprintln!("{e}");
        return 2;
    }

    eprintln!("Connecting to {host}:{port}…");
    let mut report = |phase: &str, ok: bool, detail: &str| {
        let mark = if ok { "OK " } else { "FAIL" };
        eprintln!("[{mark}] {phase}: {detail}");
    };
    let mut ask = ask_pin;

    let session =
        match rtsp::Session::connect_host_with(&host, port, &flags.pin, &mut ask, &mut report) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("pairing failed: {e:#}");
                return 1;
            }
        };
    eprintln!("Session established; starting mirror.");

    // ---- Graceful signal handling (main.go:83-99). First SIGINT/SIGTERM flips
    // the mirror stop flag; a ~3s watchdog force-exits if shutdown stalls; a
    // second signal force-exits immediately. We install the handler BEFORE
    // run_mirror so it owns the process-wide ctrlc slot (run_mirror's own
    // internal ctrlc handler then no-ops on the already-set slot), and share the
    // same stop flag via MirrorControl::with_stop. ----
    let stop = Arc::new(AtomicBool::new(false));
    let control = MirrorControl::with_stop(stop.clone());
    install_signal_handler(control.clone());

    match mirror::run_mirror_with_control(session, flags.opts, control) {
        Ok(()) => {
            eprintln!("mirror ended.");
            0
        }
        Err(e) => {
            eprintln!("mirror error: {e:#}");
            1
        }
    }
}

/// Install SIGINT/SIGTERM handling using the `ctrlc` crate (already a dep).
/// Faithful to doubletake main.go:83-99:
///   - first signal: graceful shutdown (flip the mirror stop) + a 3s watchdog
///     that force-exits if teardown stalls;
///   - second signal: immediate force-exit.
/// `ctrlc` delivers both SIGINT and SIGTERM (with its "termination" feature on
/// Unix); the handler runs on its own thread, so we use an atomic to detect the
/// second delivery.
fn install_signal_handler(control: MirrorControl) {
    let second = Arc::new(AtomicBool::new(false));
    let _ = ctrlc::set_handler(move || {
        if second.swap(true, Ordering::SeqCst) {
            eprintln!("forced exit");
            std::process::exit(1);
        }
        eprintln!("shutting down...");
        control.stop();
        // Watchdog: force exit if graceful shutdown does not complete in 3s.
        std::thread::spawn(|| {
            std::thread::sleep(Duration::from_secs(3));
            eprintln!("forced exit (timeout)");
            std::process::exit(1);
        });
    });
}

fn hex_str(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// `--daemonize` / `daemon` mode: dispatch to the Unix-socket control daemon
/// (main.go:75-78 runDaemon). Flags are parsed for their global side effects
/// (latency, hwaccel, cred backend) and `--socket` selects the socket path.
fn cmd_daemon(args: &[String]) -> i32 {
    // Determine where the flag list starts: `airfry --daemonize ...` puts the
    // flag at index 1; `airfry daemon ...` and `airfry mirror --daemonize ...`
    // both start their flags at index 2.
    let start = match args.get(1).map(String::as_str) {
        Some("--daemonize") => 1,
        _ => 2,
    };
    let flags = match parse_flags(args, start) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    if let Err(e) = apply_global_flags(&flags) {
        eprintln!("{e}");
        return 2;
    }
    match daemon::run(flags.socket_path) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("daemon error: {e:#}");
            1
        }
    }
}

fn cmd_discover(args: &[String]) -> i32 {
    // `discover` with NO explicit target shows the numbered picker too
    // (main.go selectDevice is the shared discovery path); when a host is given
    // we just print its scan-style line for symmetry. The plain scan listing is
    // the default when invoked bare.
    let _ = args;
    eprintln!("Scanning for AirPlay receivers (5s)…");
    match discovery::discover(Duration::from_secs(5)) {
        Ok(devs) if devs.is_empty() => {
            println!("No AirPlay receivers found.");
            0
        }
        Ok(mut devs) => {
            devs.sort_by(|a, b| compare_ips(&a.ip, &b.ip));
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
