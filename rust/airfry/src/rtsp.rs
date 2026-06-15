//! RTSP/1.0 transport over a plain TCP socket, with transparent HAP (HomeKit)
//! frame encryption once pair-verify has enabled it.
//!
//! Faithful port of doubletake's internal/airplay/client.go transport layer
//! (httpRequest / readHTTPResponse / encrypt / readEncryptedFrame) plus the
//! high-level `Session` orchestration that runs pair-setup, pair-verify and
//! fp-setup against a real receiver.

#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;

use crate::discovery::AirPlayDevice;
use crate::fairplay::{self, FairPlayKeys};
use crate::pairing::{self, PairKeys};

const USER_AGENT: &str = "AirPlay/935.7.1";

/// An RTSP/1.0 response (status + headers + body).
pub struct Response {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

/// RTSP transport over a TCP socket. Owns the connection, the monotonic CSeq
/// counter and — once enabled — the HAP control-channel encryption state.
pub struct Transport {
    conn: TcpStream,
    cseq: i64,

    // HAP control-channel encryption (set after pair-verify).
    encrypted: bool,
    enc_write_key: Vec<u8>,
    enc_read_key: Vec<u8>,
    enc_write_nonce: u64,
    enc_read_nonce: u64,
}

impl Transport {
    /// Dial the receiver over TCP (10s connect timeout, matching the Go client).
    pub fn connect(host: &str, port: u16) -> Result<Transport> {
        let addr = format!("{host}:{port}");
        let mut last_err: Option<anyhow::Error> = None;
        let mut sock: Option<TcpStream> = None;
        for sa in addr
            .to_socket_addrs()
            .with_context(|| format!("resolve {addr}"))?
        {
            match TcpStream::connect_timeout(&sa, Duration::from_secs(10)) {
                Ok(s) => {
                    sock = Some(s);
                    break;
                }
                Err(e) => last_err = Some(anyhow!(e)),
            }
        }
        let conn = sock.ok_or_else(|| {
            last_err.unwrap_or_else(|| anyhow!("could not resolve any address for {addr}"))
        })?;
        conn.set_nodelay(true).ok();
        Ok(Transport {
            conn,
            cseq: 0,
            encrypted: false,
            enc_write_key: Vec::new(),
            enc_read_key: Vec::new(),
            enc_write_nonce: 0,
            enc_read_nonce: 0,
        })
    }

    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    /// The receiver's (host, port) as seen on the live socket. The mirror stage
    /// uses this to build the `rtsp://host:port/<streamConnectionID>` request
    /// URIs that screen mirroring SETUP/RECORD requires.
    pub fn peer_addr(&self) -> Result<(String, u16)> {
        let pa = self.conn.peer_addr().context("socket peer addr")?;
        Ok((pa.ip().to_string(), pa.port()))
    }

    /// Enable HAP control-channel encryption with the keys derived from the
    /// pair-verify X25519 shared secret. Nonces reset to 0 (matches Go).
    pub fn enable_encryption(&mut self, write_key: Vec<u8>, read_key: Vec<u8>) {
        self.enc_write_key = write_key;
        self.enc_read_key = read_key;
        self.enc_write_nonce = 0;
        self.enc_read_nonce = 0;
        self.encrypted = true;
    }

    /// Send an RTSP/1.0 request and read the response. Mirrors Go `httpRequest`:
    /// emits `CSeq`, `User-Agent`, optional extra headers, optional
    /// `Content-Type` (only when a body is present) and `Content-Length`.
    /// Applies HAP encryption transparently once enabled.
    pub fn request(
        &mut self,
        method: &str,
        path: &str,
        content_type: &str,
        body: &[u8],
        extra_headers: &[(&str, &str)],
    ) -> Result<Response> {
        self.cseq += 1;
        let seq = self.cseq;

        let mut buf = Vec::new();
        write!(buf, "{method} {path} RTSP/1.0\r\n")?;
        write!(buf, "CSeq: {seq}\r\n")?;
        write!(buf, "User-Agent: {USER_AGENT}\r\n")?;
        for (k, v) in extra_headers {
            write!(buf, "{k}: {v}\r\n")?;
        }
        if !content_type.is_empty() && !body.is_empty() {
            write!(buf, "Content-Type: {content_type}\r\n")?;
        }
        write!(buf, "Content-Length: {}\r\n", body.len())?;
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(body);

        let data = if self.encrypted {
            self.encrypt(&buf)?
        } else {
            buf
        };

        self.conn
            .write_all(&data)
            .context("write request to socket")?;

        self.read_response()
    }

    fn read_response(&mut self) -> Result<Response> {
        self.conn
            .set_read_timeout(Some(Duration::from_secs(30)))
            .ok();
        let r = if self.encrypted {
            self.read_encrypted_response()
        } else {
            self.read_plaintext_response()
        };
        self.conn.set_read_timeout(None).ok();
        r
    }

    fn read_plaintext_response(&mut self) -> Result<Response> {
        let mut header = Vec::new();
        let mut one = [0u8; 1];
        loop {
            self.conn
                .read_exact(&mut one)
                .context("read response header byte")?;
            header.push(one[0]);
            let n = header.len();
            if n >= 4 && &header[n - 4..] == b"\r\n\r\n" {
                break;
            }
            if n > 16384 {
                bail!("response header too large");
            }
        }
        let (status, content_length, headers) = parse_http_header(&header);

        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            self.conn
                .read_exact(&mut body)
                .with_context(|| format!("read body ({content_length} bytes)"))?;
        }
        finish_response(status, headers, body)
    }

    fn read_encrypted_response(&mut self) -> Result<Response> {
        let mut decrypted: Vec<u8> = Vec::new();
        loop {
            let frame = self.read_encrypted_frame()?;
            decrypted.extend_from_slice(&frame);
            if find_subslice(&decrypted, b"\r\n\r\n").is_some() {
                break;
            }
            if decrypted.len() > 16384 {
                bail!("encrypted response header too large");
            }
        }
        let header_end = find_subslice(&decrypted, b"\r\n\r\n").unwrap() + 4;
        let (status, content_length, headers) = parse_http_header(&decrypted[..header_end]);
        let mut remaining = decrypted[header_end..].to_vec();

        while remaining.len() < content_length {
            let frame = self.read_encrypted_frame()?;
            remaining.extend_from_slice(&frame);
        }
        remaining.truncate(content_length);
        finish_response(status, headers, remaining)
    }

    /// HAP write framing: split plaintext into <=1024-byte chunks; per chunk
    /// nonce = [0;4]||LE_u64(write_nonce), AAD = LE_u16(chunk_len), output =
    /// AAD || ChaCha20Poly1305_seal(write_key, nonce, chunk, AAD).
    fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.enc_write_key)
            .map_err(|_| anyhow!("invalid write key length"))?;
        let mut result = Vec::new();
        let mut rest = data;
        while !rest.is_empty() {
            let n = rest.len().min(1024);
            let chunk = &rest[..n];
            rest = &rest[n..];

            let mut nonce = [0u8; 12];
            nonce[4..].copy_from_slice(&self.enc_write_nonce.to_le_bytes());
            let aad = (n as u16).to_le_bytes();
            self.enc_write_nonce += 1;

            let sealed = cipher
                .encrypt(
                    (&nonce).into(),
                    Payload {
                        msg: chunk,
                        aad: &aad,
                    },
                )
                .map_err(|_| anyhow!("HAP seal failed"))?;
            result.extend_from_slice(&aad);
            result.extend_from_slice(&sealed);
        }
        Ok(result)
    }

    /// Read and decrypt one HAP frame: 2-byte LE plaintext length, then
    /// plaintext_len+16 ciphertext bytes; AAD is the length prefix, nonce =
    /// [0;4]||LE_u64(read_nonce).
    fn read_encrypted_frame(&mut self) -> Result<Vec<u8>> {
        let mut len_buf = [0u8; 2];
        self.conn
            .read_exact(&mut len_buf)
            .context("read frame length")?;
        let plaintext_len = u16::from_le_bytes(len_buf) as usize;
        if plaintext_len == 0 || plaintext_len > 16384 {
            bail!("suspicious HAP frame length {plaintext_len}");
        }
        let mut ciphertext = vec![0u8; plaintext_len + 16];
        self.conn
            .read_exact(&mut ciphertext)
            .context("read frame ciphertext")?;

        let cipher = ChaCha20Poly1305::new_from_slice(&self.enc_read_key)
            .map_err(|_| anyhow!("invalid read key length"))?;
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&self.enc_read_nonce.to_le_bytes());
        self.enc_read_nonce += 1;

        cipher
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: &ciphertext,
                    aad: &len_buf,
                },
            )
            .map_err(|_| anyhow!("HAP frame decrypt failed (nonce {})", self.enc_read_nonce - 1))
    }
}

fn finish_response(
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
) -> Result<Response> {
    if !(200..300).contains(&status) {
        bail!("RTSP status {status} (body {} bytes)", body.len());
    }
    Ok(Response {
        status,
        headers,
        body,
    })
}

/// Parse an RTSP/HTTP response header block. Returns (status, content_length,
/// lowercased headers). Mirrors Go `parseHTTPHeader`.
fn parse_http_header(header: &[u8]) -> (u16, usize, HashMap<String, String>) {
    let text = String::from_utf8_lossy(header);
    let mut status = 0u16;
    let mut content_length = 0usize;
    let mut headers = HashMap::new();

    for (i, line) in text.split("\r\n").enumerate() {
        if i == 0 {
            // "RTSP/1.0 200 OK" or "HTTP/1.1 200 OK"
            for tok in line.split_whitespace() {
                if let Ok(code) = tok.parse::<u16>() {
                    status = code;
                    break;
                }
            }
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            if key.is_empty() {
                continue;
            }
            if key == "content-length" {
                content_length = val.parse().unwrap_or(0);
            }
            headers.insert(key, val);
        }
    }
    (status, content_length, headers)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

/// A fully-established AirPlay session: socket is paired (and possibly HAP
/// encrypted) and the FairPlay stream key / IV are ready for the mirror stage.
pub struct Session {
    /// RTSP transport (owns the TCP socket + HAP encryption state). The mirror
    /// stage continues to issue SETUP / RECORD etc. through this.
    pub transport: Transport,

    /// Long-term + ephemeral pairing keys (ed25519 identity, X25519 shared
    /// secret, HAP control keys). `shared_secret` is empty for the raw path.
    pub pair_keys: PairKeys,

    /// FairPlay-derived stream encryption material.
    /// `stream_key` is the final 16-byte AES key (hashed with the pair-verify
    /// shared secret when one is present); `iv` is the random 16-byte IV;
    /// `ekey` is the 72-byte wrapped key the mirror SETUP body must carry.
    pub stream_key: [u8; 16],
    pub iv: [u8; 16],
    pub ekey: Vec<u8>,

    /// Our pairing identifier (UUID), reused by later RTSP requests.
    pub pairing_id: String,
    /// Per-connection session identifier (UUID).
    pub session_id: String,
}

impl Session {
    /// Connect to a discovered device and run the full handshake:
    /// pair-setup (transient) -> pair-verify -> fp-setup. Each phase's outcome
    /// is reported through `progress`.
    pub fn connect(device: &AirPlayDevice) -> Result<Session> {
        Self::connect_host(&device.ip, device.port, "")
    }

    /// Like `connect`, but takes an explicit host/port and optional PIN.
    /// An empty `pin` selects the transient (PIN-less) flow.
    pub fn connect_host(host: &str, port: u16, pin: &str) -> Result<Session> {
        Self::connect_host_with(host, port, pin, &mut |_phase, _ok, _detail| {})
    }

    /// Full handshake with a progress callback: `progress(phase, ok, detail)`.
    pub fn connect_host_with(
        host: &str,
        port: u16,
        pin: &str,
        progress: &mut dyn FnMut(&str, bool, &str),
    ) -> Result<Session> {
        let pairing_id = pairing::generate_uuid();
        let session_id = pairing::generate_uuid();

        let mut transport = match Transport::connect(host, port) {
            Ok(t) => {
                progress("connect", true, &format!("{host}:{port}"));
                t
            }
            Err(e) => {
                progress("connect", false, &e.to_string());
                return Err(e);
            }
        };

        // pair-setup (transient SRP, or PIN-based when a PIN is given).
        let mut pair_keys = match pairing::pair_setup(&mut transport, &pairing_id, pin) {
            Ok(k) => {
                progress("pair-setup", true, "SRP exchange complete");
                k
            }
            Err(e) => {
                progress("pair-setup", false, &e.to_string());
                return Err(e.context("pair-setup"));
            }
        };

        // pair-verify (X25519); enables HAP encryption on the transport.
        match pairing::pair_verify(&mut transport, &pairing_id, &mut pair_keys) {
            Ok(()) => progress("pair-verify", true, "control channel encrypted"),
            Err(e) => {
                progress("pair-verify", false, &e.to_string());
                return Err(e.context("pair-verify"));
            }
        }

        // fp-setup (FairPlay SAP) -> stream key/iv.
        let fp: FairPlayKeys =
            match fairplay::fair_play_setup(&mut transport, &pair_keys.shared_secret) {
                Ok(fp) => {
                    progress("fp-setup", true, "FairPlay stream key derived");
                    fp
                }
                Err(e) => {
                    progress("fp-setup", false, &e.to_string());
                    return Err(e.context("fp-setup"));
                }
            };

        Ok(Session {
            transport,
            pair_keys,
            stream_key: fp.stream_key,
            iv: fp.iv,
            ekey: fp.ekey,
            pairing_id,
            session_id,
        })
    }
}
