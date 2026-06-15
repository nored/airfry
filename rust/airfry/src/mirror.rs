//! AirPlay screen-mirroring pipeline — a faithful Rust port of doubletake's
//! internal/airplay/mirror.go (video + audio paths).
//!
//! This drives an already-established `rtsp::Session` (paired + HAP-encrypted +
//! FairPlay key derived) through the mirror SETUP/RECORD handshake, opens the
//! receiver's video data TCP channel, and streams H.264 access units with the
//! 128-byte mirror frame header and per-frame encryption that the receiver
//! expects byte-for-byte.
//!
//! Wire-format / crypto invariants ported verbatim from mirror.go + client.go:
//!
//!   * Video SETUP carries shk/shiv (raw stream key/IV) inside the video stream
//!     descriptor (type=110) plus root-level ekey/eiv (the 72-byte FairPlay
//!     wrapped key). Audio SETUP (type=96) creates the session first.
//!   * Cipher selection (mirror.go setupMirrorSession):
//!       - encrypted pair-verify with a shared secret  -> ChaCha20-Poly1305
//!         with an HKDF-SHA512 key (deriveChaChaKey): salt =
//!         "DataStream-Salt"+dec(streamConnectionID), info =
//!         "DataStream-Output-Encryption-Key", IKM = pair-verify shared secret.
//!         Per-frame nonce = [0;4] || LE64(counter); AAD = the 128-byte header.
//!       - otherwise (UxPlay, plaintext) -> AES-128-CTR with SHA-512-derived
//!         key/IV (deriveVideoKeys) and the block-alignment scheme in
//!         MirrorCipher (matches mirror_buffer_decrypt on the receiver).
//!   * Frame header (128 bytes, little-endian): see `mirror_header`.
//!   * NTP frame timestamps: boot-relative, no epoch, with a forward bias.
//!
//! Audio IS streamed (RTP / ALAC). The audio SETUP is sent first because
//! current Apple receivers require the audio session to exist before they accept
//! the video stream and RECORD (mirror.go comment).

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aes::cipher::{KeyIvInit, StreamCipher};
use anyhow::{anyhow, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::{Digest, Sha512};

use crate::audio::{self, AudioSecurityMode};
use crate::capture::{CaptureConfig, CaptureSource};
use crate::latency;
use crate::rtsp::{Session, Transport};

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

/// Options for a mirror run.
#[derive(Clone, Debug)]
pub struct MirrorOpts {
    pub fit_pct: u8,
    pub bitrate_kbps: u32,
    pub fps: u32,
    pub force_software_encoder: bool,
    /// Disable per-frame video encryption (matches cfg.NoEncrypt). For debug.
    pub no_encrypt: bool,
    /// Skip audio capture/streaming entirely (video-only mirror).
    pub no_audio: bool,
    /// Stream audio but tell the receiver to mute it (SET_PARAMETER volume
    /// -144 dB). Audio frames are still sent.
    pub mute_audio: bool,
}

impl Default for MirrorOpts {
    fn default() -> Self {
        MirrorOpts {
            fit_pct: 0,
            bitrate_kbps: 0,
            fps: 30,
            force_software_encoder: false,
            no_encrypt: false,
            no_audio: false,
            mute_audio: false,
        }
    }
}

// Boot-relative timestamp reference (mirror.go: appStartTime = time.Now()).
fn boot_origin() -> Instant {
    use std::sync::OnceLock;
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    *ORIGIN.get_or_init(Instant::now)
}

const SECONDS_FROM_1900_TO_1970: u64 = 2208988800;

/// videoTimestampBias — TargetLatency, floored at 5ms. Centralized in
/// latency.rs (the single source of truth); with the default 1ms target this
/// still yields 5ms, unchanged.
fn video_timestamp_bias() -> Duration {
    latency::video_timestamp_bias()
}

/// ntpTimeWithBias — 64-bit NTP fixed-point, boot-relative, no epoch, with bias.
fn ntp_time_with_bias(bias: Duration) -> u64 {
    let bias = if bias < Duration::from_millis(5) {
        Duration::from_millis(5)
    } else {
        bias
    };
    let d = boot_origin().elapsed() + bias;
    let sec = d.as_secs();
    let nsec_frac = d.subsec_nanos() as u64;
    let frac = (nsec_frac << 32) / 1_000_000_000u64;
    (sec << 32) | frac
}

/// ntpBootTimestamp — boot-relative time with the NTP epoch added, used in the
/// NTP timing responder replies.
fn ntp_boot_timestamp() -> u64 {
    let d = boot_origin().elapsed();
    let sec = d.as_secs() + SECONDS_FROM_1900_TO_1970;
    let nsec_frac = d.subsec_nanos() as u64;
    let frac = (nsec_frac << 32) / 1_000_000_000u64;
    (sec << 32) | frac
}

// ---------------------------------------------------------------------------
// Key derivation (mirror.go deriveVideoKeys / deriveChaChaKey)
// ---------------------------------------------------------------------------

/// deriveVideoKeys — AES-128-CTR key/IV: SHA-512("AirPlayStreamKey<id>" + shk)[:16]
/// and SHA-512("AirPlayStreamIV<id>" + shk)[:16]. `id` is the stream
/// connection id formatted as an unsigned decimal (Go uses uint64).
fn derive_video_keys(shk: &[u8], stream_connection_id: i64) -> ([u8; 16], [u8; 16]) {
    let id = stream_connection_id as u64;

    let mut h = Sha512::new();
    h.update(format!("AirPlayStreamKey{id}").as_bytes());
    h.update(shk);
    let key_full = h.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&key_full[..16]);

    let mut h = Sha512::new();
    h.update(format!("AirPlayStreamIV{id}").as_bytes());
    h.update(shk);
    let iv_full = h.finalize();
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&iv_full[..16]);

    (key, iv)
}

/// deriveChaChaKey — HKDF-SHA512, IKM = pair-verify shared secret,
/// salt = "DataStream-Salt"+dec(id), info = "DataStream-Output-Encryption-Key".
fn derive_chacha_key(ikm: &[u8], stream_connection_id: i64) -> Result<[u8; 32]> {
    let id = stream_connection_id as u64;
    let salt = format!("DataStream-Salt{id}");
    let info = b"DataStream-Output-Encryption-Key";

    let hk = Hkdf::<Sha512>::new(Some(salt.as_bytes()), ikm);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .map_err(|_| anyhow!("hkdf expand"))?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// AES-CTR mirror cipher (client.go mirrorCipher / EncryptFrame)
// ---------------------------------------------------------------------------

/// The receiver's mirror_buffer_decrypt block-alignment scheme. The sender must
/// produce ciphertext that decrypts correctly under it. Faithful port of
/// client.go's mirrorCipher.EncryptFrame.
struct MirrorCipher {
    stream: Aes128Ctr,
    block_offset: usize,
    og: [u8; 16],
    next_crypt_count: usize,
}

impl MirrorCipher {
    fn new(key: &[u8; 16], iv: &[u8; 16]) -> MirrorCipher {
        MirrorCipher {
            stream: Aes128Ctr::new(key.into(), iv.into()),
            block_offset: 0,
            og: [0u8; 16],
            next_crypt_count: 0,
        }
    }

    fn encrypt_frame(&mut self, payload: &[u8]) -> Vec<u8> {
        let input_len = payload.len();
        let mut out = vec![0u8; input_len];
        let mut pos = 0usize;

        // Step 1: XOR prefix bytes using cached keystream from previous frame's
        // trailing partial block.
        if self.next_crypt_count > 0 {
            let mut n = self.next_crypt_count;
            if n > input_len {
                n = input_len;
            }
            let og_start = 16 - self.next_crypt_count;
            for i in 0..n {
                out[i] = payload[i] ^ self.og[og_start + i];
            }
            pos = n;
        }

        // Step 2: Advance CTR to next 16-byte boundary.
        if self.block_offset > 0 {
            let mut waste = vec![0u8; 16 - self.block_offset];
            self.stream.apply_keystream(&mut waste);
            self.block_offset = 0;
        }

        let remaining = input_len - pos;

        // Step 3: Encrypt full 16-byte blocks.
        let full_blocks = (remaining / 16) * 16;
        if full_blocks > 0 {
            out[pos..pos + full_blocks].copy_from_slice(&payload[pos..pos + full_blocks]);
            self.stream.apply_keystream(&mut out[pos..pos + full_blocks]);
            self.block_offset = 0;
            pos += full_blocks;
        }

        // Step 4: Handle trailing partial block.
        let rest_len = remaining % 16;
        self.next_crypt_count = 0;
        if rest_len > 0 {
            let mut padded = [0u8; 16];
            padded[..rest_len].copy_from_slice(&payload[pos..pos + rest_len]);
            self.stream.apply_keystream(&mut padded);
            out[pos..pos + rest_len].copy_from_slice(&padded[..rest_len]);
            // Cache the full block for next frame's step 1.
            self.og = padded;
            self.next_crypt_count = 16 - rest_len;
            self.block_offset = 0;
        }

        out
    }
}

/// The selected per-frame video cipher.
enum VideoCipher {
    None,
    AesCtr(MirrorCipher),
    /// ChaCha20-Poly1305 with a monotonic 64-bit nonce counter; header is AAD.
    ChaCha { aead: ChaCha20Poly1305, nonce: u64 },
}

impl VideoCipher {
    /// Poly1305 tag overhead for the ChaCha path (mirror.go adds this to the
    /// header's payload-size field). 0 for AES-CTR / none.
    fn overhead(&self) -> usize {
        match self {
            VideoCipher::ChaCha { .. } => 16,
            _ => 0,
        }
    }
}

// ---------------------------------------------------------------------------
// H.264 NAL parser (mirror.go h264Parser) + AU helpers
// ---------------------------------------------------------------------------

struct H264Parser {
    buf: Vec<u8>,
}

impl H264Parser {
    fn new() -> H264Parser {
        H264Parser {
            buf: Vec::with_capacity(512 * 1024),
        }
    }

    /// Push raw bytes, return any complete NAL units. Each returned NAL begins
    /// with a 4-byte start code (00 00 00 01 for Annex-B; a synthetic
    /// 00 00 00 01 for AVCC, matching pushAVCC which rewrites the length to 1).
    fn push(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        self.buf.extend_from_slice(data);
        if has_start_code(&self.buf) {
            self.push_annex_b()
        } else {
            self.push_avcc()
        }
    }

    fn push_annex_b(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let start = match find_start_code(&self.buf, 0) {
                Some(s) => s,
                None => {
                    if self.buf.len() > 1024 * 1024 {
                        let keep = self.buf.len() - 128 * 1024;
                        self.buf.drain(..keep);
                    }
                    break;
                }
            };
            let next = match find_start_code(&self.buf, start + 3) {
                Some(n) => n,
                None => {
                    if start > 0 {
                        self.buf.drain(..start);
                    }
                    break;
                }
            };
            out.push(self.buf[start..next].to_vec());
            self.buf.drain(..next);
        }
        out
    }

    fn push_avcc(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            if self.buf.len() < 4 {
                break;
            }
            let nal_len = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]])
                as usize;
            if nal_len == 0 || nal_len > 16 * 1024 * 1024 {
                self.buf.clear();
                break;
            }
            if self.buf.len() < 4 + nal_len {
                break;
            }
            let mut nal = Vec::with_capacity(4 + nal_len);
            nal.extend_from_slice(&1u32.to_be_bytes());
            nal.extend_from_slice(&self.buf[4..4 + nal_len]);
            out.push(nal);
            self.buf.drain(..4 + nal_len);
        }
        out
    }
}

fn has_start_code(b: &[u8]) -> bool {
    find_start_code(b, 0).is_some()
}

fn find_start_code(b: &[u8], from: usize) -> Option<usize> {
    let from = from.min(b.len());
    let mut i = from;
    while i + 3 < b.len() {
        if b[i] == 0x00 && b[i + 1] == 0x00 {
            if b[i + 2] == 0x01 {
                return Some(i);
            }
            if i + 3 < b.len() && b[i + 2] == 0x00 && b[i + 3] == 0x01 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// stripStartCode — drop the Annex-B start code (00 00 01 or 00 00 00 01).
fn strip_start_code(nal: &[u8]) -> &[u8] {
    if nal.len() > 4 && nal[0] == 0 && nal[1] == 0 && nal[2] == 0 && nal[3] == 1 {
        &nal[4..]
    } else if nal.len() > 3 && nal[0] == 0 && nal[1] == 0 && nal[2] == 1 {
        &nal[3..]
    } else {
        nal
    }
}

/// avccWrap — prepend a 4-byte big-endian length.
fn avcc_wrap(raw: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(4 + raw.len());
    b.extend_from_slice(&(raw.len() as u32).to_be_bytes());
    b.extend_from_slice(raw);
    b
}

/// nalType — H.264 NAL unit type from a NAL that may begin with a start code.
fn nal_type(nal: &[u8]) -> u8 {
    let mut i = 0usize;
    while i + 1 < nal.len() {
        if nal[i] == 0x01 && i >= 2 && nal[i - 1] == 0x00 && nal[i - 2] == 0x00 {
            if i + 1 < nal.len() {
                return nal[i + 1] & 0x1f;
            }
        }
        i += 1;
    }
    0
}

/// isFirstSlice — true if the first bit of the slice header is 1
/// (first_mb_in_slice == 0 → new access unit).
fn is_first_slice(raw: &[u8]) -> bool {
    if raw.len() < 2 {
        return false;
    }
    raw[1] & 0x80 != 0
}

/// buildAVCCConfig — AVCDecoderConfigurationRecord from raw SPS/PPS, with the
/// 4-byte (02 00 00 00) trailer observed in iPhone captures.
fn build_avcc_config(sps: &[u8], pps: &[u8]) -> Vec<u8> {
    let avcc_len = 6 + 2 + sps.len() + 1 + 2 + pps.len();
    let mut payload = vec![0u8; avcc_len + 4]; // +4 trailer
    payload[0] = 0x01; // configurationVersion
    payload[1] = sps[1]; // AVCProfileIndication
    payload[2] = sps[2]; // profile_compatibility
    payload[3] = sps[3]; // AVCLevelIndication
    payload[4] = 0xff; // lengthSizeMinusOne = 3
    payload[5] = 0xe1; // numSequenceParameterSets = 1
    payload[6..8].copy_from_slice(&(sps.len() as u16).to_be_bytes());
    payload[8..8 + sps.len()].copy_from_slice(sps);
    let off = 8 + sps.len();
    payload[off] = 0x01; // numPictureParameterSets = 1
    payload[off + 1..off + 3].copy_from_slice(&(pps.len() as u16).to_be_bytes());
    payload[off + 3..off + 3 + pps.len()].copy_from_slice(pps);
    payload[avcc_len] = 0x02; // trailer
    payload
}

// ---------------------------------------------------------------------------
// SPS dimension parsing (mirror.go spsDimensions + h264BitReader)
// ---------------------------------------------------------------------------

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    err: bool,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> BitReader<'a> {
        BitReader {
            data,
            pos: 0,
            err: false,
        }
    }
    fn read_bit(&mut self) -> u32 {
        if self.pos >= self.data.len() * 8 {
            self.err = true;
            return 0;
        }
        let b = self.data[self.pos >> 3];
        let bit = (b >> (7 - (self.pos & 7))) & 1;
        self.pos += 1;
        bit as u32
    }
    fn read_bits(&mut self, n: usize) -> u32 {
        let mut v = 0u32;
        for _ in 0..n {
            v = (v << 1) | self.read_bit();
        }
        v
    }
    fn read_ue(&mut self) -> u32 {
        let mut zeros = 0;
        while self.read_bit() == 0 {
            if self.err || zeros > 31 {
                self.err = true;
                return 0;
            }
            zeros += 1;
        }
        if zeros == 0 {
            return 0;
        }
        (1u32 << zeros) - 1 + self.read_bits(zeros)
    }
    fn read_se(&mut self) -> i32 {
        let k = self.read_ue();
        if k & 1 != 0 {
            ((k + 1) / 2) as i32
        } else {
            -((k / 2) as i32)
        }
    }
}

fn strip_emulation_prevention(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    let mut zeros = 0;
    let mut i = 0;
    while i < b.len() {
        if zeros >= 2 && b[i] == 0x03 && i + 1 < b.len() && b[i + 1] <= 0x03 {
            zeros = 0;
            i += 1;
            continue;
        }
        if b[i] == 0 {
            zeros += 1;
        } else {
            zeros = 0;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// spsDimensions — coded picture width/height from a raw SPS (with NAL header,
/// no start code). Returns None on parse failure.
fn sps_dimensions(sps: &[u8]) -> Option<(i32, i32)> {
    if sps.len() < 4 || sps[0] & 0x1f != 7 {
        return None;
    }
    let rbsp = strip_emulation_prevention(&sps[1..]);
    let mut r = BitReader::new(&rbsp);

    let profile_idc = r.read_bits(8);
    r.read_bits(8); // constraint flags + reserved
    r.read_bits(8); // level_idc
    r.read_ue(); // seq_parameter_set_id

    if matches!(
        profile_idc,
        100 | 110 | 122 | 244 | 44 | 83 | 86 | 118 | 128 | 138 | 139 | 134 | 135
    ) {
        let chroma_format_idc = r.read_ue();
        if chroma_format_idc == 3 {
            r.read_bit(); // separate_colour_plane_flag
        }
        r.read_ue(); // bit_depth_luma_minus8
        r.read_ue(); // bit_depth_chroma_minus8
        r.read_bit(); // qpprime_y_zero_transform_bypass_flag
        if r.read_bit() == 1 {
            let n = if chroma_format_idc == 3 { 12 } else { 8 };
            for i in 0..n {
                if r.read_bit() == 1 {
                    let size = if i >= 6 { 64 } else { 16 };
                    let mut last_scale = 8i32;
                    let mut next_scale = 8i32;
                    for _ in 0..size {
                        if next_scale != 0 {
                            next_scale = (last_scale + r.read_se() + 256) % 256;
                        }
                        if next_scale != 0 {
                            last_scale = next_scale;
                        }
                    }
                }
            }
        }
    }

    r.read_ue(); // log2_max_frame_num_minus4
    let pic_order_cnt_type = r.read_ue();
    if pic_order_cnt_type == 0 {
        r.read_ue();
    } else if pic_order_cnt_type == 1 {
        r.read_bit();
        r.read_se();
        r.read_se();
        let mut n = r.read_ue();
        while n > 0 {
            r.read_se();
            n -= 1;
        }
    }
    r.read_ue(); // max_num_ref_frames
    r.read_bit(); // gaps_in_frame_num_value_allowed_flag

    let pic_width_in_mbs_minus1 = r.read_ue();
    let pic_height_in_map_units_minus1 = r.read_ue();
    let frame_mbs_only_flag = r.read_bit();
    if frame_mbs_only_flag == 0 {
        r.read_bit();
    }
    r.read_bit(); // direct_8x8_inference_flag

    let (mut crop_l, mut crop_r, mut crop_t, mut crop_b) = (0u32, 0u32, 0u32, 0u32);
    if r.read_bit() == 1 {
        crop_l = r.read_ue();
        crop_r = r.read_ue();
        crop_t = r.read_ue();
        crop_b = r.read_ue();
    }
    if r.err {
        return None;
    }

    let mut w = (pic_width_in_mbs_minus1 as i32 + 1) * 16;
    let mut h = (2 - frame_mbs_only_flag as i32) * (pic_height_in_map_units_minus1 as i32 + 1) * 16;
    let crop_unit_x = 2;
    let crop_unit_y = 2 * (2 - frame_mbs_only_flag as i32);
    w -= (crop_l + crop_r) as i32 * crop_unit_x;
    h -= (crop_t + crop_b) as i32 * crop_unit_y;
    if w <= 0 || h <= 0 {
        return None;
    }
    Some((w, h))
}

// ---------------------------------------------------------------------------
// Mirror frame header (mirror.go sendFrame / sendCodecFrame)
// ---------------------------------------------------------------------------

fn put_f32_le(dst: &mut [u8], v: f32) {
    dst[..4].copy_from_slice(&v.to_bits().to_le_bytes());
}

// ---------------------------------------------------------------------------
// Data channel + the mirror driver
// ---------------------------------------------------------------------------

/// The receiver's video data TCP connection plus the cipher and frame counters.
/// Shared between the send loop and the data-heartbeat thread (dataMu).
struct DataChannel {
    conn: TcpStream,
    cipher: VideoCipher,
    /// Per-session forward NTP bias for frame timestamps (mirror.go
    /// session.timestampBias = sessionLatency). Falls back to
    /// videoTimestampBias() when <= 0 (mirror.go MirrorSession.ntpTimeNow).
    timestamp_bias: Duration,
    frame_seq: u32,
    // Presentation (display) size advertised in the codec header (offsets 56/60).
    display_w: i32,
    display_h: i32,
    // Encoded content size (read back from SPS), used at offsets 16/20 + 40/44.
    video_w: i32,
    video_h: i32,
}

impl DataChannel {
    /// ntpTimeNow — per-session NTP frame timestamp using the session
    /// timestampBias, falling back to videoTimestampBias() when unset
    /// (mirror.go MirrorSession.ntpTimeNow).
    fn ntp_time_now(&self) -> u64 {
        let bias = if self.timestamp_bias > Duration::ZERO {
            self.timestamp_bias
        } else {
            video_timestamp_bias()
        };
        ntp_time_with_bias(bias)
    }

    /// sendCodecFrame — unencrypted SPS+PPS avcC packet (header type 0x01).
    fn send_codec_frame(&mut self, payload: &[u8], ntp: u64) -> Result<()> {
        self.frame_seq += 1;
        let mut header = [0u8; 128];
        header[0..4].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        header[4] = 0x01; // SPS+PPS codec packet (unencrypted)
        header[5] = 0x00;
        header[6] = 0x16; // h264 SPS+PPS option
        header[7] = 0x01;
        header[8..16].copy_from_slice(&ntp.to_le_bytes());

        let (mut disp_w, mut disp_h) = (self.display_w, self.display_h);
        if disp_w <= 0 || disp_h <= 0 {
            disp_w = self.video_w;
            disp_h = self.video_h;
        }
        put_f32_le(&mut header[16..20], self.video_w as f32);
        put_f32_le(&mut header[20..24], self.video_h as f32);
        put_f32_le(&mut header[40..44], self.video_w as f32);
        put_f32_le(&mut header[44..48], self.video_h as f32);
        put_f32_le(&mut header[56..60], disp_w as f32);
        put_f32_le(&mut header[60..64], disp_h as f32);

        self.conn
            .set_write_timeout(Some(Duration::from_secs(1)))
            .ok();
        self.conn.write_all(&header).context("write codec header")?;
        self.conn.write_all(payload).context("write codec payload")?;
        Ok(())
    }

    /// sendFrame — one encrypted VCL access unit with the 128-byte header.
    /// `au_data` is AVCC-encoded (4-byte BE length per NALU, no start codes).
    fn send_frame(&mut self, au_data: &[u8], is_keyframe: bool, ntp: u64) -> Result<()> {
        self.frame_seq += 1;

        let payload_size = au_data.len() + self.cipher.overhead();

        let mut header = [0u8; 128];
        header[0..4].copy_from_slice(&(payload_size as u32).to_le_bytes());
        header[4] = 0x00; // encrypted video data
        header[5] = if is_keyframe { 0x10 } else { 0x00 };
        // header[6..8] = 0x00 0x00 for encrypted packets (already zero)
        header[8..16].copy_from_slice(&ntp.to_le_bytes());

        let frame_payload: Vec<u8> = match &mut self.cipher {
            VideoCipher::None => au_data.to_vec(),
            VideoCipher::AesCtr(mc) => mc.encrypt_frame(au_data),
            VideoCipher::ChaCha { aead, nonce } => {
                // IETF state matched to the receiver's 64x64: nonce = [0;4]||LE64(N).
                let mut n = [0u8; 12];
                n[4..].copy_from_slice(&nonce.to_le_bytes());
                let sealed = aead
                    .encrypt(
                        (&n).into(),
                        Payload {
                            msg: au_data,
                            aad: &header,
                        },
                    )
                    .map_err(|_| anyhow!("chacha seal failed"))?;
                *nonce += 1;
                sealed
            }
        };

        self.conn
            .set_write_timeout(Some(Duration::from_secs(2)))
            .ok();
        self.conn.write_all(&header).context("write frame header")?;
        self.conn
            .write_all(&frame_payload)
            .context("write frame payload")?;
        Ok(())
    }

    /// dataHeartbeatLoop frame: 128-byte header, byte4=0x02, byte6=0x1e.
    fn send_data_heartbeat(&mut self) -> Result<()> {
        let mut header = [0u8; 128];
        header[4] = 0x02;
        header[6] = 0x1e;
        self.conn
            .set_write_timeout(Some(Duration::from_secs(5)))
            .ok();
        self.conn
            .write_all(&header)
            .context("write data heartbeat")?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// run_mirror: the high-level driver
// ---------------------------------------------------------------------------

/// generateUUID — RFC-4122 v4, formatted like mirror.go's generateUUID.
fn generate_uuid() -> String {
    let mut b = [0u8; 16];
    rand::Rng::fill(&mut rand::thread_rng(), &mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex = |s: &[u8]| s.iter().map(|x| format!("{x:02x}")).collect::<String>();
    format!(
        "{}-{}-{}-{}-{}",
        hex(&b[0..4]),
        hex(&b[4..6]),
        hex(&b[6..8]),
        hex(&b[8..10]),
        hex(&b[10..16])
    )
}

/// uuidToMAC — stable locally-administered MAC from a UUID-ish string.
fn uuid_to_mac(id: &str) -> String {
    let hex: String = id.to_lowercase().chars().filter(|c| *c != '-').collect();
    if hex.len() < 12 {
        return "02:00:00:00:00:01".to_string();
    }
    let b = &hex.as_bytes()[..12];
    let mut parts = [
        std::str::from_utf8(&b[0..2]).unwrap().to_string(),
        std::str::from_utf8(&b[2..4]).unwrap().to_string(),
        std::str::from_utf8(&b[4..6]).unwrap().to_string(),
        std::str::from_utf8(&b[6..8]).unwrap().to_string(),
        std::str::from_utf8(&b[8..10]).unwrap().to_string(),
        std::str::from_utf8(&b[10..12]).unwrap().to_string(),
    ];
    parts[0] = "02".to_string();
    parts.join(":").to_uppercase()
}

/// Run a screen-mirroring session against an established `Session`, until the
/// capture stream ends or Ctrl-C is pressed. Faithful to mirror.go's
/// setupMirrorSession + StreamFrames (video only).
pub fn run_mirror(session: Session, opts: MirrorOpts) -> Result<()> {
    run_mirror_with_stop(session, opts, Arc::new(AtomicBool::new(false)))
}

/// Like `run_mirror`, but driven by a caller-owned stop flag so an external
/// controller (e.g. the tray) can stop or switch the mirror at any time.
pub fn run_mirror_with_stop(
    session: Session,
    opts: MirrorOpts,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    use plist::Value;

    // The mirror RTSP request line uses the full rtsp:// URI as the path. We
    // reconstruct host/port from the connected socket's peer address.
    let peer = session
        .transport
        .peer_addr()
        .context("query control socket peer addr")?;
    let host = peer.0;
    let port = peer.1;

    let session_uuid = generate_uuid();
    let client_device_id = uuid_to_mac(&session.session_id);

    // ---- Encryption key material (mirror.go: encKey/encIV = streamKey/iv) ----
    let enc_key = session.stream_key;
    let enc_iv = session.iv;

    // Receiver presentation (display) size from GET /info; the codec header
    // carries this so the receiver can center/pillarbox content (mirror.go feeds
    // DisplaySize() when nonzero, else sendCodecFrame falls back to content size).
    let (display_w, display_h) = session.info.display_size();
    if display_w > 0 && display_h > 0 {
        eprintln!("[mirror] receiver display size: {display_w}x{display_h}");
    }

    // Keep the pieces we need from the session before moving the control
    // transport behind an Arc<Mutex> so the keepalive threads can share it.
    let ekey = session.ekey.clone();
    let pair_shared_secret = session.pair_keys.shared_secret.clone();
    // Whether the control channel is HAP-encrypted (pair-verify happened). This
    // drives selectAudioSecurityMode + the ChaCha video-cipher gate (mirror.go
    // c.encrypted), NOT shared-secret emptiness.
    let encrypted = session.transport.is_encrypted();
    // Receiver playout-latency floor (mirror.go ReceiverInfo.playoutLatencyFloor):
    // 0 for FairPlay-SAP receivers (feature bit 1<<14), else conservative 500ms.
    // Computed inline from the features bit to avoid coupling to info.rs.
    let supports_fairplay_sap = session.info.features & (1 << 14) != 0;
    let playout_latency_floor = if supports_fairplay_sap {
        Duration::ZERO
    } else {
        latency::CONSERVATIVE_PLAYOUT_LATENCY
    };
    let control = Arc::new(Mutex::new(session.transport));

    // ---- Allocate 3 consecutive UDP ports: timing(N), control(N+1), data(N+2).
    // Real Apple senders use consecutive ports; the Apple TV classifies incoming
    // audio by source port and expects this pattern (mirror.go:113-124
    // allocateConsecutiveUDPPortsInRange). The control + data sockets feed the
    // audio stream; the declared controlPort in the SETUP descriptor is N+1, the
    // socket we actually send sync packets from. ----
    let audio_ports = allocate_consecutive_udp(3).context("allocate audio ports")?;
    let mut ports_iter = audio_ports.into_iter();
    let timing_sock = ports_iter.next().unwrap();
    let audio_ctrl_conn = Some(ports_iter.next().unwrap());
    let audio_data_conn = Some(ports_iter.next().unwrap());
    let timing_port = timing_sock.local_addr()?.port();

    // Start NTP timing responder BEFORE sending SETUP so it's ready when the
    // Apple TV probes us (mirror.go:126-128).
    {
        let stop = stop.clone();
        std::thread::spawn(move || ntp_timing_responder(timing_sock, stop));
    }

    // ---- Event (reverse) channel: open a TCP listener, avoiding the audio UDP
    // triple [timingPort, timingPort+2], accept the receiver's event connection,
    // and keep it open for the session lifetime, draining reads
    // (mirror.go:130-161). Go does NOT carry the sender's event port in the
    // SETUP plist; it reserves the listener and separately dials the receiver's
    // own eventPort read back from the SETUP response. ----
    let event_listener = listen_tcp_avoiding(timing_port).context("listen event port")?;
    let event_port = event_listener.local_addr()?.port();
    eprintln!("[mirror] event listener on TCP port {event_port}");
    {
        let stop = stop.clone();
        std::thread::spawn(move || event_accept_loop(event_listener, stop));
    }

    let audio_control_lport = audio_ctrl_conn
        .as_ref()
        .and_then(|c| c.local_addr().ok())
        .map(|a| a.port())
        .unwrap_or(0);

    // ---- Audio security mode (mirror.go selectAudioSecurityMode(c.encrypted)):
    // an encrypted (HAP pair-verified) session uses ChaCha20-Poly1305 with a
    // fresh random 32-byte direct stream key published via `shk`; otherwise the
    // legacy AES-128-CBC path with the FairPlay key/IV. Keyed on whether the
    // control channel is encrypted, matching Go's c.encrypted. ----
    let audio_mode = if encrypted {
        AudioSecurityMode::ChaCha
    } else {
        AudioSecurityMode::LegacyAes
    };
    let audio_chacha_key: Option<[u8; 32]> = if audio_mode == AudioSecurityMode::ChaCha {
        let mut k = [0u8; 32];
        rand::Rng::fill(&mut rand::thread_rng(), &mut k);
        Some(k)
    } else {
        None
    };
    // Legacy AES path reuses the FairPlay key/IV (mirror.go: audioKey = c.fpKey,
    // audioIV = c.fpIV), which in this port are session.stream_key / session.iv
    // (the hashed fpKey + random fpIV). Audio encryption is DISABLED when those
    // are absent (mirror.go: `c.fpKey != nil && c.fpIV != nil`); they are always
    // present here after FairPlay SAP, so the legacy AES path is enabled.
    let audio_aes_key: Option<[u8; 16]> = if audio_mode == AudioSecurityMode::LegacyAes {
        Some(enc_key)
    } else {
        None
    };
    let audio_aes_iv: Option<[u8; 16]> = if audio_mode == AudioSecurityMode::LegacyAes {
        Some(enc_iv)
    } else {
        None
    };

    // ---- Phase 1: audio SETUP (creates the session). ----
    let audio_stream_connection_id: i64 =
        (now_unix_nanos() & 0x7FFF_FFFF_FFFF_FFFF) as i64;
    let audio_uri = format!("rtsp://{host}:{port}/{audio_stream_connection_id}");

    // redundantAudio: 2 when FEC is on (legacy), 0 for ChaCha (audio.go
    // useAudioFEC); disableRetransmits when redundantAudio == 0.
    let audio_redundant: i64 = if audio::use_audio_fec(audio_mode == AudioSecurityMode::ChaCha) {
        2
    } else {
        0
    };
    // sessionLatency = max(TargetLatency(), playoutLatencyFloor()); audio and
    // video share it so they stay in sync (mirror.go:163-171,218-220). The
    // RECORD response may later override it (mirror.go:496-508). Audio latency in
    // 44.1 kHz samples = samplesFor44k1(sessionLatency).
    let mut session_latency = latency::target_latency();
    if session_latency < playout_latency_floor {
        session_latency = playout_latency_floor;
    }
    let mut audio_latency_samples = latency::samples_for_44k1(session_latency);

    let mut audio_stream_desc = plist::Dictionary::new();
    audio_stream_desc.insert("type".into(), Value::Integer(96i64.into()));
    audio_stream_desc.insert(
        "streamConnectionID".into(),
        Value::Integer(audio_stream_connection_id.into()),
    );
    audio_stream_desc.insert("ct".into(), Value::Integer(2i64.into())); // ALAC
    audio_stream_desc.insert("spf".into(), Value::Integer(352i64.into()));
    audio_stream_desc.insert("sr".into(), Value::Integer(44100i64.into()));
    audio_stream_desc.insert("audioFormat".into(), Value::Integer(0x40000i64.into()));
    audio_stream_desc.insert("audioFormatIndex".into(), Value::Integer(0x12i64.into()));
    audio_stream_desc.insert(
        "controlPort".into(),
        Value::Integer((audio_control_lport as i64).into()),
    );
    audio_stream_desc.insert("audioMode".into(), Value::String("default".into()));
    audio_stream_desc.insert("usingScreen".into(), Value::Boolean(true));
    audio_stream_desc.insert(
        "latencyMin".into(),
        Value::Integer((audio_latency_samples as i64).into()),
    );
    audio_stream_desc.insert(
        "latencyMax".into(),
        Value::Integer((audio_latency_samples as i64).into()),
    );
    audio_stream_desc.insert(
        "redundantAudio".into(),
        Value::Integer(audio_redundant.into()),
    );
    if audio_redundant == 0 {
        audio_stream_desc.insert("disableRetransmits".into(), Value::Boolean(true));
    }

    let mut audio_setup = plist::Dictionary::new();
    audio_setup.insert("deviceID".into(), Value::String(client_device_id.clone()));
    audio_setup.insert("macAddress".into(), Value::String(client_device_id.clone()));
    audio_setup.insert("sessionUUID".into(), Value::String(session_uuid.clone()));
    audio_setup.insert("sourceVersion".into(), Value::String("935.7.1".into()));
    audio_setup.insert("timingProtocol".into(), Value::String("NTP".into()));
    audio_setup.insert("timingPort".into(), Value::Integer((timing_port as i64).into()));
    audio_setup.insert("osBuildVersion".into(), Value::String("23F79".into()));
    audio_setup.insert("model".into(), Value::String("MacBookPro18,3".into()));
    audio_setup.insert("name".into(), Value::String("MacBook Pro".into()));

    // Modern HAP receivers look for shk on the audio stream descriptor; legacy
    // receivers read the FairPlay ekey/eiv from the root (mirror.go).
    match (&audio_chacha_key, audio_mode) {
        (Some(key), AudioSecurityMode::ChaCha) => {
            audio_stream_desc.insert("shk".into(), Value::Data(key.to_vec()));
            audio_stream_desc.insert("isMedia".into(), Value::Boolean(true));
            audio_stream_desc.insert("supportsDynamicStreamID".into(), Value::Boolean(true));

            let mut rtp = plist::Dictionary::new();
            rtp.insert(
                "streamConnectionKeyUseStreamEncryptionKey".into(),
                Value::Boolean(true),
            );
            let mut rtcp = plist::Dictionary::new();
            rtcp.insert(
                "streamConnectionKeyPort".into(),
                Value::Integer((audio_control_lport as i64).into()),
            );
            let mut connections = plist::Dictionary::new();
            connections.insert("streamConnectionTypeRTP".into(), Value::Dictionary(rtp));
            connections.insert("streamConnectionTypeRTCP".into(), Value::Dictionary(rtcp));
            audio_stream_desc
                .insert("streamConnections".into(), Value::Dictionary(connections));
        }
        _ => {
            // FairPlay ekey/eiv (legacy AES path on the receiver). et=32. Only
            // added when both FpEkey and fpIV are present (mirror.go:274-281:
            // `c.FpEkey != nil && c.fpIV != nil`). fpIV (= enc_iv) is always
            // present here, so the guard reduces to a non-empty ekey.
            if !ekey.is_empty() {
                audio_setup.insert("et".into(), Value::Integer(32i64.into()));
                audio_setup.insert("ekey".into(), Value::Data(ekey.clone()));
                audio_setup.insert("eiv".into(), Value::Data(enc_iv.to_vec()));
            }
        }
    }

    audio_setup.insert(
        "streams".into(),
        Value::Array(vec![Value::Dictionary(audio_stream_desc)]),
    );

    let audio_body = marshal_plist(&Value::Dictionary(audio_setup))?;
    let audio_resp = control
        .lock()
        .unwrap()
        .request(
            "SETUP",
            &audio_uri,
            "application/x-apple-binary-plist",
            &audio_body,
            &[],
        )
        .context("SETUP phase 1 (audio)")?;
    let audio_resp_plist = parse_plist(&audio_resp.body).ok();

    // Parse the audio data + control ports (type=96 stream) from the response.
    let (audio_data_port, audio_control_port) = audio_resp_plist
        .as_ref()
        .and_then(extract_audio_ports)
        .unwrap_or((0, 0));
    if audio_data_port > 0 {
        eprintln!(
            "[audio] stream: dataPort={audio_data_port} controlPort={audio_control_port}"
        );
    }

    // The receiver advertises its own event port in the SETUP response; the
    // sender dials back to it (mirror.go:336-346).
    let mut receiver_event_port: u16 = audio_resp_plist
        .as_ref()
        .and_then(|p| p.as_dictionary())
        .and_then(|d| d.get("eventPort"))
        .and_then(plist_int)
        .filter(|p| *p > 0)
        .map(|p| p as u16)
        .unwrap_or(0);

    // ---- Phase 2: video SETUP ----
    let video_stream_connection_id: i64 =
        (now_unix_nanos() & 0x7FFF_FFFF_FFFF_FFFF) as i64;
    let video_uri = format!("rtsp://{host}:{port}/{video_stream_connection_id}");

    let mut video_stream_desc = plist::Dictionary::new();
    video_stream_desc.insert("type".into(), Value::Integer(110i64.into()));
    video_stream_desc.insert(
        "streamConnectionID".into(),
        Value::Integer(video_stream_connection_id.into()),
    );
    let ts_names = ["SubSu", "BePxT", "AfPxT", "BefEn", "EmEnc"];
    let ts_info: Vec<Value> = ts_names
        .iter()
        .map(|n| {
            let mut d = plist::Dictionary::new();
            d.insert("name".into(), Value::String((*n).into()));
            Value::Dictionary(d)
        })
        .collect();
    video_stream_desc.insert("timestampInfo".into(), Value::Array(ts_info));
    if !opts.no_encrypt {
        video_stream_desc.insert("shk".into(), Value::Data(enc_key.to_vec()));
        video_stream_desc.insert("shiv".into(), Value::Data(enc_iv.to_vec()));
    }

    let mut video_setup = plist::Dictionary::new();
    video_setup.insert("deviceID".into(), Value::String(client_device_id.clone()));
    video_setup.insert("macAddress".into(), Value::String(client_device_id.clone()));
    video_setup.insert("sessionUUID".into(), Value::String(session_uuid.clone()));
    video_setup.insert("sourceVersion".into(), Value::String("935.7.1".into()));
    video_setup.insert("isScreenMirroringSession".into(), Value::Boolean(true));
    video_setup.insert("timingProtocol".into(), Value::String("NTP".into()));
    video_setup.insert("timingPort".into(), Value::Integer((timing_port as i64).into()));
    video_setup.insert("osBuildVersion".into(), Value::String("23F79".into()));
    video_setup.insert("model".into(), Value::String("MacBookPro18,3".into()));
    video_setup.insert("name".into(), Value::String("MacBook Pro".into()));
    if !opts.no_encrypt {
        // UxPlay reads ekey/eiv from the root level.
        video_setup.insert("ekey".into(), Value::Data(ekey.clone()));
        video_setup.insert("eiv".into(), Value::Data(enc_iv.to_vec()));
    }
    video_setup.insert(
        "streams".into(),
        Value::Array(vec![Value::Dictionary(video_stream_desc)]),
    );

    let video_body = marshal_plist(&Value::Dictionary(video_setup))?;
    let video_resp = control
        .lock()
        .unwrap()
        .request(
            "SETUP",
            &video_uri,
            "application/x-apple-binary-plist",
            &video_body,
            &[],
        )
        .context("SETUP phase 2 (video)")?;
    let video_resp_plist =
        parse_plist(&video_resp.body).context("unmarshal video setup response")?;

    // Fall back to the video SETUP response's eventPort when the audio response
    // did not carry one (mirror.go:426-437).
    if receiver_event_port == 0 {
        if let Some(p) = video_resp_plist
            .as_dictionary()
            .and_then(|d| d.get("eventPort"))
            .and_then(plist_int)
            .filter(|p| *p > 0)
        {
            receiver_event_port = p as u16;
        }
    }

    // Connect to the receiver's event port if it advertised one (mirror.go:439-448).
    // The connection is kept open for the session lifetime as the outbound event
    // channel; we hold it so it is not dropped/closed early.
    let _receiver_event_conn: Option<TcpStream> = if receiver_event_port > 0 {
        use std::net::ToSocketAddrs;
        let event_addr = format!("{host}:{receiver_event_port}");
        match event_addr.to_socket_addrs().ok().and_then(|mut a| a.next()) {
            Some(sa) => match TcpStream::connect_timeout(&sa, Duration::from_secs(3)) {
                Ok(c) => {
                    eprintln!("[event] connected to receiver event port {event_addr}");
                    Some(c)
                }
                Err(e) => {
                    eprintln!("[event] connect to receiver event port {event_addr} failed: {e}");
                    None
                }
            },
            None => None,
        }
    } else {
        None
    };

    // Extract the video data port (type=110 stream's dataPort).
    let data_port = extract_video_data_port(&video_resp_plist)
        .ok_or_else(|| anyhow!("no video data port in SETUP response"))?;

    // ---- Connect to the receiver's video data TCP port ----
    let data_addr = format!("{host}:{data_port}");
    let conn = TcpStream::connect_timeout(
        &data_addr
            .parse()
            .or_else(|_| -> Result<std::net::SocketAddr> {
                use std::net::ToSocketAddrs;
                data_addr
                    .to_socket_addrs()?
                    .next()
                    .ok_or_else(|| anyhow!("resolve {data_addr}"))
            })?,
        Duration::from_secs(5),
    )
    .with_context(|| format!("connect data port {data_addr}"))?;
    conn.set_nodelay(true).ok();
    eprintln!("[mirror] data channel connected: {data_addr}");

    // ---- RECORD to start the session ----
    let record_resp = control
        .lock()
        .unwrap()
        .request(
            "RECORD",
            &audio_uri,
            "",
            &[],
            &[
                ("Session", session_uuid.as_str()),
                ("Range", "npt=0-"),
                ("RTP-Info", "seq=0;rtptime=0"),
            ],
        )
        .context("RECORD")?;

    // The receiver may report its authoritative playout latency via the
    // Audio-Latency response header. When present and > 0, drive both audio and
    // video from it so they stay in sync, overriding our fallback floor
    // (mirror.go:496-508). headers are lowercased by the transport.
    if let Some(value) = record_resp.headers.get("audio-latency") {
        match value.trim().parse::<u32>() {
            Ok(parsed) if parsed > 0 => {
                audio_latency_samples = parsed;
                session_latency = Duration::from_nanos(
                    (parsed as u64) * 1_000_000_000 / 44_100,
                );
                eprintln!(
                    "[mirror] receiver audio latency: {parsed} samples ({:?}); using for audio+video",
                    session_latency
                );
            }
            _ => {}
        }
    }

    // The per-session video frame NTP timestamps use this session latency as
    // their forward bias (mirror.go: session.timestampBias = sessionLatency).
    let timestamp_bias = session_latency;

    // ---- SET_PARAMETER volume, sent twice like real senders. The initial
    // volume is always 0.000000 (max); muting is a separate runtime call
    // (mirror.go:510-519 SetAudioMuted). --mute is applied as a post-setup
    // SET_PARAMETER below, after the two initial 0.000000 sends. ----
    let volume_body: &[u8] = b"volume: 0.000000\r\n";
    let _ = control.lock().unwrap().request(
        "SET_PARAMETER",
        &audio_uri,
        "text/parameters",
        volume_body,
        &[],
    );
    let _ = control.lock().unwrap().request(
        "SET_PARAMETER",
        &audio_uri,
        "text/parameters",
        volume_body,
        &[],
    );
    // --mute: separate post-setup SET_PARAMETER mirroring SetAudioMuted(true)
    // (volume -144 dB = muted). The two initial sends above stay 0.000000.
    if opts.mute_audio {
        let _ = control.lock().unwrap().request(
            "SET_PARAMETER",
            &audio_uri,
            "text/parameters",
            b"volume: -144.000000\r\n",
            &[],
        );
    }

    // ---- Select the video cipher (mirror.go:544-598 setupMirrorSession) ----
    // Take the ChaCha20-Poly1305 path when the control channel is encrypted and
    // either a pair-verify shared secret OR the raw FairPlay AES key is present;
    // IKM = shared secret if present, else fpAesKey (mirror.go:547-558).
    //
    // In this port `enc_key` (= Go c.fpKey) is always present after FairPlay SAP,
    // and HAP encryption is always derived from the pair-verify shared secret, so
    // `encrypted` implies a non-empty shared secret. The fpAesKey-only IKM
    // fallback is therefore not reachable here (it would require encrypted ==
    // true with an empty shared secret, which the HAP path never produces); the
    // raw fpAesKey is not threaded onto Session. Otherwise (UxPlay / plaintext,
    // not encrypted) fall back to AES-128-CTR.
    let cipher = if opts.no_encrypt {
        eprintln!("[mirror] video frame encryption DISABLED");
        VideoCipher::None
    } else if encrypted && !pair_shared_secret.is_empty() {
        let chacha_key =
            derive_chacha_key(&pair_shared_secret, video_stream_connection_id)?;
        let aead = ChaCha20Poly1305::new_from_slice(&chacha_key)
            .map_err(|_| anyhow!("chacha key length"))?;
        eprintln!("[mirror] cipher: ChaCha20-Poly1305 (HKDF-SHA512)");
        VideoCipher::ChaCha { aead, nonce: 0 }
    } else {
        let (k, iv) = derive_video_keys(&enc_key, video_stream_connection_id);
        eprintln!("[mirror] cipher: AES-128-CTR (SHA-512 derived)");
        VideoCipher::AesCtr(MirrorCipher::new(&k, &iv))
    };

    // Receiver display/presentation size from GET /info: fed into the codec
    // header (offsets 56/60). When the receiver advertised no usable size these
    // stay 0 and sendCodecFrame falls back to the encoded content size
    // (mirror.go behaviour when DisplaySize() is 0).
    let data = Arc::new(Mutex::new(DataChannel {
        conn,
        cipher,
        timestamp_bias,
        frame_seq: 0,
        display_w: display_w as i32,
        display_h: display_h as i32,
        video_w: 0,
        video_h: 0,
    }));

    // first-frame gate: data-heartbeat / feedback wait for it (mirror.go).
    let first_frame = Arc::new(AtomicBool::new(false));

    // ---- Background loops ----
    // Data-channel heartbeat (1s) after the first frame.
    {
        let data = data.clone();
        let first_frame = first_frame.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !first_frame.load(Ordering::Relaxed) {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_secs(1));
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                let mut dc = data.lock().unwrap();
                if dc.send_data_heartbeat().is_err() {
                    return;
                }
            }
        });
    }

    // RTSP keepalive loops on the control channel (mirror.go heartbeatLoop +
    // feedbackLoop). Both run on background threads sharing the control
    // transport behind the Arc<Mutex>, and stop when `stop` is set.
    spawn_heartbeat_loop(
        control.clone(),
        audio_uri.clone(),
        session_uuid.clone(),
        stop.clone(),
    );
    spawn_feedback_loop(control.clone(), stop.clone());

    // Ctrl-C handler: flip the stop flag so the capture loop exits cleanly.
    {
        let stop = stop.clone();
        let _ = ctrlc_set(move || stop.store(true, Ordering::Relaxed));
    }

    // ---- Audio: set up the RTP audio stream + start capture, then run the
    // StreamAudio loop on its own thread gated on the same first-frame / stop
    // flags as video (mirror.go: setupAudioStream is created after RECORD and
    // StreamAudio is launched alongside StreamFrames). ----
    let mut audio_handle: Option<std::thread::JoinHandle<()>> = None;
    if !opts.no_audio {
        if let (Some(ctrl_conn), Some(data_conn)) = (audio_ctrl_conn, audio_data_conn) {
            if audio_data_port > 0 {
                let audio_ct = audio::AUDIO_CT_ALAC;
                match audio::setup_audio_stream(
                    &host,
                    audio_data_port,
                    audio_control_port,
                    audio_aes_key,
                    audio_aes_iv,
                    audio_chacha_key,
                    audio_mode,
                    audio_ct,
                    audio_latency_samples,
                    ctrl_conn,
                    data_conn,
                ) {
                    Ok(stream) => {
                        let audio_stream = Arc::new(Mutex::new(stream));
                        match audio::AudioCapture::start(false) {
                            Ok(mut capture) => {
                                eprintln!("[audio] capture started; streaming audio alongside video");
                                let first_frame = first_frame.clone();
                                let stop = stop.clone();
                                let boot = boot_origin();
                                audio_handle = Some(std::thread::spawn(move || {
                                    if let Err(e) = audio::stream_audio(
                                        &mut capture,
                                        audio_stream,
                                        &first_frame,
                                        &stop,
                                        boot,
                                    ) {
                                        eprintln!("[audio] stream ended: {e}");
                                    }
                                    capture.stop();
                                }));
                            }
                            Err(e) => {
                                eprintln!("[audio] capture start failed: {e}; continuing video-only");
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[audio] stream setup failed: {e}; continuing video-only");
                    }
                }
            } else {
                eprintln!("[audio] receiver did not provide audio ports; skipping audio");
            }
        }
    } else {
        eprintln!("[audio] disabled (--no-audio)");
    }

    // ---- Capture + stream (mirror.go StreamFrames) ----
    let capture_cfg = CaptureConfig {
        fps: opts.fps,
        bitrate_kbps: opts.bitrate_kbps,
        fit_pct: opts.fit_pct,
        force_software: opts.force_software_encoder,
    };
    let mut capture = CaptureSource::start(&capture_cfg).context("start capture")?;
    eprintln!("[mirror] streaming… (Ctrl-C to stop)");

    let result = stream_frames(&mut capture, &data, &first_frame, &stop);

    stop.store(true, Ordering::Relaxed);
    capture.stop();

    // Let the audio thread observe `stop` and wind down its capture/sender.
    if let Some(h) = audio_handle.take() {
        let _ = h.join();
    }

    // ---- TEARDOWN ----
    let _ = control
        .lock()
        .unwrap()
        .request("TEARDOWN", &audio_uri, "", &[], &[]);

    result
}

/// allocateConsecutiveUDPPortsInRange (ephemeral path) — allocate `count`
/// consecutive UDP ports: timing(N), control(N+1), data(N+2). The OS picks the
/// base port; subsequent ports are base+1, base+2, … The Apple TV classifies
/// incoming audio by source port and expects this consecutive pattern
/// (mirror.go:1812-1871). Retries up to 20 times, matching Go.
fn allocate_consecutive_udp(count: usize) -> Result<Vec<std::net::UdpSocket>> {
    use std::net::UdpSocket;
    for _ in 0..20 {
        let first = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(_) => continue,
        };
        let base = match first.local_addr() {
            Ok(a) => a.port(),
            Err(_) => continue,
        };
        if base == 0 || (base as usize) + count - 1 > u16::MAX as usize {
            continue;
        }
        let mut conns = vec![first];
        let mut ok = true;
        for i in 1..count {
            match UdpSocket::bind(("0.0.0.0", base + i as u16)) {
                Ok(c) => conns.push(c),
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            return Ok(conns);
        }
        // Drop the partial set and retry.
    }
    Err(anyhow!(
        "could not allocate {count} consecutive UDP ports after 20 attempts"
    ))
}

/// listenTCPInRange (ephemeral path) — open a TCP listener for the event
/// channel. With an OS-assigned ephemeral port there is no range to scan; we
/// re-bind until the chosen port does not overlap the audio UDP triple
/// [skip_base, skip_base+2] (mirror.go:1873-1893).
fn listen_tcp_avoiding(skip_base: u16) -> Result<std::net::TcpListener> {
    use std::net::TcpListener;
    for _ in 0..32 {
        let l = TcpListener::bind("0.0.0.0:0").context("listen event TCP")?;
        let p = l.local_addr()?.port();
        if skip_base > 0 && p >= skip_base && p <= skip_base.saturating_add(2) {
            // Overlaps the audio UDP triple; re-bind to get a different port.
            continue;
        }
        return Ok(l);
    }
    Err(anyhow!("no free TCP port for the event channel"))
}

/// event_accept_loop — accept the receiver's inbound event (reverse) connection,
/// then keep it open for the session lifetime, draining reads until the peer
/// closes or `stop` is set (mirror.go:139-161).
fn event_accept_loop(listener: std::net::TcpListener, stop: Arc<AtomicBool>) {
    let conn = match listener.accept() {
        Ok((c, addr)) => {
            eprintln!("[event] Apple TV connected for reverse events from {addr}");
            c
        }
        Err(_) => return,
    };
    // Short read timeout so the drain loop can observe the stop flag.
    conn.set_read_timeout(Some(Duration::from_secs(1))).ok();
    let mut buf = [0u8; 4096];
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        match (&conn).read(&mut buf) {
            Ok(0) => return, // peer closed
            Ok(_n) => {}
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(_) => return,
        }
    }
}

/// extract_audio_ports — find the type=96 stream's data/control ports in a SETUP
/// response plist (mirror.go plistStreamPorts: dataPort/controlPort, or the
/// modern streamConnections RTP/RTCP `streamConnectionKeyPort`).
fn extract_audio_ports(resp: &plist::Value) -> Option<(u16, u16)> {
    let dict = resp.as_dictionary()?;
    let streams = dict.get("streams")?.as_array()?;
    for s in streams {
        let sd = match s.as_dictionary() {
            Some(d) => d,
            None => continue,
        };
        if sd.get("type").and_then(plist_int) != Some(96) {
            continue;
        }
        let mut data_port = sd.get("dataPort").and_then(plist_int).unwrap_or(0);
        let mut control_port = sd.get("controlPort").and_then(plist_int).unwrap_or(0);
        if let Some(conns) = sd.get("streamConnections").and_then(|v| v.as_dictionary()) {
            if let Some(rtp) = conns
                .get("streamConnectionTypeRTP")
                .and_then(|v| v.as_dictionary())
            {
                if let Some(p) = rtp.get("streamConnectionKeyPort").and_then(plist_int) {
                    if p > 0 {
                        data_port = p;
                    }
                }
            }
            if let Some(rtcp) = conns
                .get("streamConnectionTypeRTCP")
                .and_then(|v| v.as_dictionary())
            {
                if let Some(p) = rtcp.get("streamConnectionKeyPort").and_then(plist_int) {
                    if p > 0 {
                        control_port = p;
                    }
                }
            }
        }
        return Some((data_port as u16, control_port as u16));
    }
    None
}

// ---------------------------------------------------------------------------
// RTSP control-channel keepalive loops (mirror.go heartbeatLoop + feedbackLoop)
// ---------------------------------------------------------------------------

/// heartbeatLoop — periodic GET_PARAMETER on the control URI every 15s, with
/// the `Session` header. Some receivers (Apple TV) return 400 for
/// GET_PARAMETER; after 3 consecutive failures we silently stop (the /feedback
/// POST and data-channel heartbeat provide redundant keepalive). Starts at SETUP
/// time (mirror.go:634), not gated on the first frame, and stops when `stop` is
/// set.
fn spawn_heartbeat_loop(
    control: Arc<Mutex<Transport>>,
    uri: String,
    session_id: String,
    stop: Arc<AtomicBool>,
) {
    std::thread::spawn(move || {
        // mirror.go:634 starts this loop at SETUP time (immediately), NOT gated
        // on the first frame. The 15s ticker fires the first request after 15s.
        let mut consecutive_failures = 0u32;
        loop {
            // 15s tick, checking the stop flag every 100ms.
            let mut waited = Duration::ZERO;
            while waited < Duration::from_secs(15) {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
                waited += Duration::from_millis(100);
            }
            if stop.load(Ordering::Relaxed) {
                return;
            }

            let res = {
                let mut t = control.lock().unwrap();
                t.request(
                    "GET_PARAMETER",
                    &uri,
                    "",
                    &[],
                    &[("Session", session_id.as_str())],
                )
            };
            match res {
                Ok(_) => consecutive_failures = 0,
                Err(_) => {
                    consecutive_failures += 1;
                    if consecutive_failures >= 3 {
                        // Silently disable GET_PARAMETER keepalive.
                        return;
                    }
                }
            }
        }
    });
}

/// feedbackLoop — POST /feedback every 2s, with an immediate first feedback to
/// beat UxPlay's ~3s timeout. Starts at SETUP time (mirror.go:636), not gated on
/// the first frame, so the immediate first feedback actually happens early. Stops
/// when `stop` is set. Faithful port of mirror.go's feedbackLoop.
fn spawn_feedback_loop(
    control: Arc<Mutex<Transport>>,
    stop: Arc<AtomicBool>,
) {
    std::thread::spawn(move || {
        // Immediate first feedback (mirror.go sends one before the ticker).
        {
            let mut t = control.lock().unwrap();
            let _ = t.request("POST", "/feedback", "", &[], &[]);
        }

        loop {
            let mut waited = Duration::ZERO;
            while waited < Duration::from_secs(2) {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
                waited += Duration::from_millis(100);
            }
            if stop.load(Ordering::Relaxed) {
                return;
            }
            let mut t = control.lock().unwrap();
            let _ = t.request("POST", "/feedback", "", &[], &[]);
        }
    });
}

/// stream_frames — the NAL-parsing send loop, a faithful port of
/// mirror.go's StreamFrames (without the congestion controller's logging
/// noise; the drop logic is preserved).
fn stream_frames(
    capture: &mut CaptureSource,
    data: &Arc<Mutex<DataChannel>>,
    first_frame: &Arc<AtomicBool>,
    stop: &Arc<AtomicBool>,
) -> Result<()> {
    let mut buf = vec![0u8; 256 * 1024];
    let mut parser = H264Parser::new();

    let mut latest_sps: Option<Vec<u8>> = None;
    let mut latest_pps: Option<Vec<u8>> = None;
    let mut vcl_buf: Vec<u8> = Vec::new();
    let mut pending_keyframe = false;
    let mut codec_sent = false;
    let mut stream_primed = false;
    let mut frame_count: i64 = 0;
    let mut cc = CongestionController::new();

    // Closure-free flush implemented inline via a helper fn would need many
    // params; keep it a local macro-like block.
    macro_rules! flush_vcl {
        () => {{
            let res: Result<()> = (|| {
                if vcl_buf.is_empty() {
                    return Ok(());
                }
                if !stream_primed
                    && (!pending_keyframe || latest_sps.is_none() || latest_pps.is_none())
                {
                    vcl_buf.clear();
                    return Ok(());
                }
                if !pending_keyframe && cc.should_drop(frame_count) {
                    vcl_buf.clear();
                    return Ok(());
                }

                // Per-session NTP bias (mirror.go: packetTimestamp = s.ntpTimeNow()).
                let ntp = data.lock().unwrap().ntp_time_now();

                if pending_keyframe && !codec_sent {
                    if let (Some(sps), Some(pps)) = (&latest_sps, &latest_pps) {
                        if let Some((w, h)) = sps_dimensions(sps) {
                            let mut dc = data.lock().unwrap();
                            dc.video_w = w;
                            dc.video_h = h;
                        }
                        let avcc = build_avcc_config(sps, pps);
                        {
                            let mut dc = data.lock().unwrap();
                            dc.send_codec_frame(&avcc, ntp)?;
                        }
                        first_frame.store(true, Ordering::Relaxed);
                        codec_sent = true;
                        stream_primed = true;
                    }
                }

                let send_start = Instant::now();
                let sent_len = {
                    let mut dc = data.lock().unwrap();
                    dc.send_frame(&vcl_buf, pending_keyframe, ntp)?;
                    vcl_buf.len()
                };
                cc.record_send(sent_len + 128, send_start.elapsed());
                vcl_buf.clear();
                pending_keyframe = false;
                codec_sent = false;
                frame_count += 1;
                Ok(())
            })();
            res
        }};
    }

    loop {
        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }

        let n = capture.read(&mut buf)?;
        if n == 0 {
            // EOF: flush and stop.
            flush_vcl!()?;
            return Ok(());
        }

        let nals = parser.push(&buf[..n]);
        for nal in nals {
            let nt = nal_type(&nal);
            let raw = strip_start_code(&nal).to_vec();

            match nt {
                9 => {
                    // AUD — flush previous AU.
                    flush_vcl!()?;
                }
                7 => {
                    // SPS — flush before keyframe.
                    flush_vcl!()?;
                    latest_sps = Some(raw);
                }
                8 => {
                    latest_pps = Some(raw);
                }
                6 => {
                    // SEI — skip.
                }
                5 => {
                    // IDR VCL slice.
                    if !vcl_buf.is_empty() && !pending_keyframe {
                        flush_vcl!()?;
                    }
                    if !vcl_buf.is_empty() && pending_keyframe && is_first_slice(&raw) {
                        flush_vcl!()?;
                    }
                    pending_keyframe = true;
                    vcl_buf.extend_from_slice(&avcc_wrap(&raw));
                }
                1 | 2 | 3 | 4 => {
                    // non-IDR VCL slice.
                    if !vcl_buf.is_empty() && pending_keyframe {
                        flush_vcl!()?;
                    }
                    if !vcl_buf.is_empty() && !pending_keyframe && is_first_slice(&raw) {
                        flush_vcl!()?;
                    }
                    vcl_buf.extend_from_slice(&avcc_wrap(&raw));
                }
                _ => {}
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Congestion controller (mirror.go congestionController)
// ---------------------------------------------------------------------------

#[derive(PartialEq, Clone, Copy)]
enum CongestionLevel {
    None,
    Light,
    Medium,
    Heavy,
}

struct CongestionController {
    ewma_ns_per_byte: f64,
    samples: u64,
    level: CongestionLevel,
    skipped: u64,
}

impl CongestionController {
    fn new() -> CongestionController {
        CongestionController {
            ewma_ns_per_byte: 0.0,
            samples: 0,
            level: CongestionLevel::None,
            skipped: 0,
        }
    }

    fn record_send(&mut self, bytes: usize, dur: Duration) {
        if bytes == 0 {
            return;
        }
        let ns_per_byte = dur.as_nanos() as f64 / bytes as f64;
        const ALPHA: f64 = 0.3;
        if self.samples == 0 {
            self.ewma_ns_per_byte = ns_per_byte;
        } else {
            self.ewma_ns_per_byte = ALPHA * ns_per_byte + (1.0 - ALPHA) * self.ewma_ns_per_byte;
        }
        self.samples += 1;

        let new_level = if self.ewma_ns_per_byte > 50000.0 {
            CongestionLevel::Heavy
        } else if self.ewma_ns_per_byte > 20000.0 {
            CongestionLevel::Medium
        } else if self.ewma_ns_per_byte > 10000.0 {
            CongestionLevel::Light
        } else {
            CongestionLevel::None
        };
        if new_level != self.level {
            if new_level == CongestionLevel::None {
                self.skipped = 0;
            }
            self.level = new_level;
        }
    }

    fn should_drop(&mut self, frame_count: i64) -> bool {
        match self.level {
            CongestionLevel::Light => {
                if frame_count % 3 == 0 {
                    self.skipped += 1;
                    return true;
                }
            }
            CongestionLevel::Medium => {
                if frame_count % 2 == 0 {
                    self.skipped += 1;
                    return true;
                }
            }
            CongestionLevel::Heavy => {
                self.skipped += 1;
                return true;
            }
            CongestionLevel::None => {}
        }
        false
    }
}

// ---------------------------------------------------------------------------
// NTP timing responder (mirror.go ntpTimingResponder)
// ---------------------------------------------------------------------------

fn ntp_timing_responder(sock: std::net::UdpSocket, stop: Arc<AtomicBool>) {
    sock.set_read_timeout(Some(Duration::from_secs(3))).ok();
    let mut buf = [0u8; 128];
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let (n, addr) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(_) => return,
        };
        if n < 32 {
            continue;
        }
        let now = ntp_boot_timestamp();
        let mut reply = [0u8; 32];
        reply[..32].copy_from_slice(&buf[..32]);
        reply[0] = 0x80;
        reply[1] = 0xd3;
        // Reference = sender's transmit timestamp (echo bytes 24..32).
        reply[8..16].copy_from_slice(&buf[24..32]);
        // Receive + Transmit timestamps = now (BE).
        reply[16..24].copy_from_slice(&now.to_be_bytes());
        reply[24..32].copy_from_slice(&now.to_be_bytes());
        let _ = sock.send_to(&reply, addr);
    }
}

// ---------------------------------------------------------------------------
// plist helpers + small utilities
// ---------------------------------------------------------------------------

fn marshal_plist(v: &plist::Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    plist::to_writer_binary(&mut out, v).context("marshal binary plist")?;
    Ok(out)
}

fn parse_plist(data: &[u8]) -> Result<plist::Value> {
    plist::Value::from_reader(std::io::Cursor::new(data)).context("parse plist")
}

/// extract_video_data_port — find the type=110 stream's dataPort in a SETUP
/// response plist (mirror.go's loop over response["streams"]).
fn extract_video_data_port(resp: &plist::Value) -> Option<u16> {
    let dict = resp.as_dictionary()?;
    let streams = dict.get("streams")?.as_array()?;
    for s in streams {
        let sd = match s.as_dictionary() {
            Some(d) => d,
            None => continue,
        };
        let st = sd.get("type").and_then(plist_int);
        if st == Some(110) {
            if let Some(p) = sd.get("dataPort").and_then(plist_int) {
                return Some(p as u16);
            }
        }
    }
    None
}

fn plist_int(v: &plist::Value) -> Option<i64> {
    if let Some(i) = v.as_signed_integer() {
        Some(i)
    } else {
        v.as_unsigned_integer().map(|u| u as i64)
    }
}

fn now_unix_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Install a SIGINT (Ctrl-C) handler that flips the stop flag. Best-effort:
/// errors (e.g. a handler already set) are ignored.
fn ctrlc_set<F: Fn() + Send + 'static>(f: F) -> Result<()> {
    ctrlc::set_handler(f).map_err(|e| anyhow!("set ctrl-c handler: {e}"))
}
