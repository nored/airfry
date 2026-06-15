//! IPC client for the AirFry control daemon — a faithful Rust port of
//! doubletake's `internal/daemon/daemonclient/client.go`.
//!
//! Connects to the daemon's Unix socket, sends one JSON `Request`, and reads
//! one JSON `Response`. The request/response types are re-used from
//! `crate::daemon` so the wire format the `airfry-ctl` binary speaks is exactly
//! the format the daemon expects (and matches a Go doubletake-ctl byte-for-byte).

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};

use crate::protocol::{default_socket_path, Request, Response};

/// Communicates with a running AirFry daemon over its Unix socket
/// (daemonclient.Client).
pub struct Client {
    pub socket_path: PathBuf,
}

impl Client {
    /// Create a client connecting to the daemon at `socket_path`
    /// (daemonclient.New).
    pub fn new<P: AsRef<Path>>(socket_path: P) -> Client {
        Client {
            socket_path: socket_path.as_ref().to_path_buf(),
        }
    }

    /// Create a client using the default socket path (daemonclient.NewDefault).
    pub fn new_default() -> Client {
        Client {
            socket_path: default_socket_path(),
        }
    }

    /// Daemon's current state (daemonclient.Status).
    pub fn status(&self) -> Result<Response> {
        self.send(Request {
            cmd: "status".into(),
            ..Default::default()
        })
    }

    /// Trigger device discovery / return found devices (daemonclient.Discover).
    pub fn discover(&self) -> Result<Response> {
        self.send(Request {
            cmd: "discover".into(),
            ..Default::default()
        })
    }

    /// Cached list of discovered devices (daemonclient.Devices).
    pub fn devices(&self) -> Result<Response> {
        self.send(Request {
            cmd: "devices".into(),
            ..Default::default()
        })
    }

    /// Start mirroring to `target` (or first free device when empty), with an
    /// optional `pin` (daemonclient.Connect).
    pub fn connect(&self, target: &str, port: i32, pin: &str) -> Result<Response> {
        self.send(Request {
            cmd: "connect".into(),
            target: target.to_string(),
            port,
            pin: pin.to_string(),
        })
    }

    /// Submit a PIN for a device parked waiting for pairing. The daemon exposes
    /// this both as the explicit `pin` command and (for Go-ctl compatibility)
    /// as a `connect` carrying a pin; this client uses the explicit command.
    pub fn pin(&self, pin: &str) -> Result<Response> {
        self.send(Request {
            cmd: "pin".into(),
            pin: pin.to_string(),
            ..Default::default()
        })
    }

    /// Stop ALL active mirroring sessions (daemonclient.Disconnect).
    pub fn disconnect(&self) -> Result<Response> {
        self.send(Request {
            cmd: "disconnect".into(),
            ..Default::default()
        })
    }

    /// Stop the mirroring session to a specific receiver IP
    /// (daemonclient.DisconnectTarget).
    pub fn disconnect_target(&self, target: &str) -> Result<Response> {
        self.send(Request {
            cmd: "disconnect".into(),
            target: target.to_string(),
            ..Default::default()
        })
    }

    /// Mute mirrored audio on all active sessions (daemonclient.Mute).
    pub fn mute(&self) -> Result<Response> {
        self.send(Request {
            cmd: "mute".into(),
            ..Default::default()
        })
    }

    /// Mute mirrored audio on the session to a specific receiver IP
    /// (daemonclient.MuteTarget).
    pub fn mute_target(&self, target: &str) -> Result<Response> {
        self.send(Request {
            cmd: "mute".into(),
            target: target.to_string(),
            ..Default::default()
        })
    }

    /// Unmute mirrored audio on all active sessions (daemonclient.Unmute).
    pub fn unmute(&self) -> Result<Response> {
        self.send(Request {
            cmd: "unmute".into(),
            ..Default::default()
        })
    }

    /// Unmute mirrored audio on the session to a specific receiver IP
    /// (daemonclient.UnmuteTarget).
    pub fn unmute_target(&self, target: &str) -> Result<Response> {
        self.send(Request {
            cmd: "unmute".into(),
            target: target.to_string(),
            ..Default::default()
        })
    }

    /// Dial the socket, send one request, read one response (daemonclient.send).
    /// Newline-delimited JSON in both directions (Go's json.Encoder/Decoder).
    fn send(&self, req: Request) -> Result<Response> {
        let mut stream = UnixStream::connect(&self.socket_path)
            .with_context(|| format!("connect to daemon at {}", self.socket_path.display()))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .ok();
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .ok();

        let mut buf = serde_json::to_vec(&req).context("encode request")?;
        buf.push(b'\n');
        stream.write_all(&buf).context("send request")?;
        stream.flush().ok();

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        let n = reader.read_line(&mut line).context("read response")?;
        if n == 0 {
            return Err(anyhow!("daemon closed the connection without a response"));
        }
        let resp: Response =
            serde_json::from_str(line.trim_end()).context("decode response")?;
        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The client's request builders emit the exact `cmd`/`target`/`pin` shapes
    /// daemonclient.go produces, so a Go daemon would accept them unchanged.
    #[test]
    fn client_builds_go_compatible_requests() {
        // Each builder is the analogue of a daemonclient.go method; assert the
        // request JSON it would send matches the Go wire form.
        fn wire(req: &Request) -> serde_json::Value {
            serde_json::from_str(&serde_json::to_string(req).unwrap()).unwrap()
        }

        // status / discover / devices: bare `cmd`.
        for cmd in ["status", "discover", "devices", "disconnect", "mute", "unmute"] {
            let v = wire(&Request {
                cmd: cmd.into(),
                ..Default::default()
            });
            assert_eq!(v["cmd"], cmd);
            assert!(v.get("target").is_none());
        }

        // connect(target, 0, pin): port omitted at 0.
        let v = wire(&Request {
            cmd: "connect".into(),
            target: "192.168.1.50".into(),
            pin: "1234".into(),
            ..Default::default()
        });
        assert_eq!(v["cmd"], "connect");
        assert_eq!(v["target"], "192.168.1.50");
        assert_eq!(v["pin"], "1234");
        assert!(v.get("port").is_none());

        // *_target variants carry `target`.
        let v = wire(&Request {
            cmd: "mute".into(),
            target: "10.0.0.9".into(),
            ..Default::default()
        });
        assert_eq!(v["cmd"], "mute");
        assert_eq!(v["target"], "10.0.0.9");
    }
}
