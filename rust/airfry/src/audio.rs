//! AirPlay mirrored-audio streaming — a faithful Rust port of doubletake's
//! internal/airplay/audio.go (plus the audio-related constants from
//! latency.go).
//!
//! The receiver expects, byte-for-byte:
//!
//!   * Raw system output (the default sink's PulseAudio **monitor**) captured as
//!     S16LE / 44100 Hz / stereo, then encoded into ALAC "verbatim" frames in
//!     code (`encode_alac_verbatim`) — 352 samples per frame (spf).
//!   * Each frame sent as an RTP packet (PT=96, SSRC=0, frame-based sequence,
//!     rtpTime advancing by spf), with the payload encrypted under the
//!     negotiated audio security mode:
//!       - ChaCha20-Poly1305 with an **8-byte (64-bit) nonce** — the original
//!         Bernstein construction from github.com/aead/chacha20poly1305
//!         `NewCipher`, NOT the IETF 12-byte variant. The 64-bit nonce value is
//!         appended (LE) after the AEAD output on the wire.
//!       - or legacy AES-128-CBC over full blocks only (trailing bytes clear).
//!   * Periodic NTP sync packets on the control port (20-byte layout).
//!
//! All wire-format / crypto / timing details are ported verbatim from audio.go.

#![allow(dead_code)]

use std::io::Read;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use aes::cipher::{BlockEncryptMut, KeyIvInit};
use anyhow::{anyhow, bail, Context, Result};
use chacha20::cipher::{StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20Legacy;
use poly1305::universal_hash::{KeyInit as _, UniversalHash};
use poly1305::Poly1305;

use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app as gst_app;

// ---------------------------------------------------------------------------
// Constants (audio.go + latency.go)
// ---------------------------------------------------------------------------

/// Samples per frame for the ALAC mirrored-audio codec (audio.go: spf=352).
pub const AUDIO_SPF: u16 = 352;
/// Audio sample rate (44.1 kHz).
pub const AUDIO_SAMPLE_RATE: u32 = 44100;
/// ALAC compression type (ct=2).
pub const AUDIO_CT_ALAC: u8 = 2;
/// audio.go: audioChaChaNonceSize = 8 (64-bit nonce).
const AUDIO_CHACHA_NONCE_SIZE: usize = 8;

/// audio.go audioSecurityMode.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AudioSecurityMode {
    LegacyAes,
    ChaCha,
}

/// audio.go audioChaChaNonceMode.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AudioChaChaNonceMode {
    Counter,
    Seq,
    SeqZeroBased,
    Rtp,
}

impl AudioChaChaNonceMode {
    fn as_str(self) -> &'static str {
        match self {
            AudioChaChaNonceMode::Seq => "seq",
            AudioChaChaNonceMode::SeqZeroBased => "seq0",
            AudioChaChaNonceMode::Rtp => "rtp",
            AudioChaChaNonceMode::Counter => "counter",
        }
    }
}

/// audio.go audioChaChaAADMode.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AudioChaChaAadMode {
    None,
    RtpHeader,
    TimestampSsrc,
}

impl AudioChaChaAadMode {
    fn as_str(self) -> &'static str {
        match self {
            AudioChaChaAadMode::RtpHeader => "rtp-header",
            AudioChaChaAadMode::TimestampSsrc => "timestamp-ssrc",
            AudioChaChaAadMode::None => "none",
        }
    }
}

/// audio.go defaultAudioChaChaNonceMode() = counter.
pub fn default_audio_chacha_nonce_mode() -> AudioChaChaNonceMode {
    AudioChaChaNonceMode::Counter
}

/// audio.go defaultAudioChaChaAADMode() = timestamp-ssrc.
pub fn default_audio_chacha_aad_mode() -> AudioChaChaAadMode {
    AudioChaChaAadMode::TimestampSsrc
}

/// audio.go useAudioFEC: FEC enabled unless the session is modern-encrypted
/// (ChaCha). ChaCha sessions send each frame exactly once.
pub fn use_audio_fec(modern_encrypted: bool) -> bool {
    !modern_encrypted
}

// ---------------------------------------------------------------------------
// Latency (latency.go) — the audio path uses the negotiated session latency in
// 44.1 kHz samples; the receiver may override it via the RECORD response, which
// the caller passes here.
// ---------------------------------------------------------------------------

// The 44.1 kHz sample math (samplesFor44k1 / targetLatencySamples44k1) lives in
// the centralized `latency` module — the single source of truth for the
// sender's playout-latency target. audio.rs delegates to it below.

/// audio.go audioLatencySamplesForCodec: the override wins when > 0; otherwise
/// the process-global target latency in 44.1 kHz samples (latency.rs).
pub fn audio_latency_samples_for_codec(_ct: u8, override_samples: u32) -> u32 {
    if override_samples > 0 {
        override_samples
    } else {
        crate::latency::target_latency_samples_44k1()
    }
}

// ---------------------------------------------------------------------------
// 64-bit-nonce ChaCha20-Poly1305 AEAD (github.com/aead/chacha20poly1305
// NewCipher, with chacha.NonceSize = 8).
//
// Construction (matches the Go `c20p1305.Seal`/`Open`):
//   * Poly1305 one-time key  = first 32 bytes of the ChaCha20 keystream at the
//     given nonce, block counter 0.
//   * Encryption keystream   = ChaCha20 from block counter 1 (byte offset 64).
//   * Tag = Poly1305_key( AAD ‖ pad16 ‖ CT ‖ pad16 ‖ LE64(len(AAD)) ‖ LE64(len(CT)) )
//   * Seal output = CT ‖ tag(16).
// ---------------------------------------------------------------------------

/// The audio AEAD: the original 64-bit-nonce ChaCha20-Poly1305 construction.
#[derive(Clone)]
pub struct AudioChaCha64 {
    key: [u8; 32],
}

/// Poly1305 tag size (audio.go: Overhead() == poly1305.TagSize == 16).
pub const AUDIO_CHACHA_OVERHEAD: usize = 16;

impl AudioChaCha64 {
    pub fn new(key: &[u8]) -> Result<AudioChaCha64> {
        if key.len() != 32 {
            bail!("chacha20poly1305: bad key length ({})", key.len());
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(key);
        Ok(AudioChaCha64 { key: k })
    }

    pub fn overhead(&self) -> usize {
        AUDIO_CHACHA_OVERHEAD
    }

    /// Build the Poly1305 one-time key + position the cipher at block counter 1.
    fn init_cipher(&self, nonce: &[u8; AUDIO_CHACHA_NONCE_SIZE]) -> (ChaCha20Legacy, Poly1305) {
        let mut cipher = ChaCha20Legacy::new(
            (&self.key).into(),
            chacha20::LegacyNonce::from_slice(nonce),
        );
        // Poly1305 key = first 32 keystream bytes at block counter 0.
        let mut poly_key = [0u8; 32];
        cipher.apply_keystream(&mut poly_key);
        // Encrypt from block counter 1 (byte offset 64) — matches Go SetCounter(1).
        cipher.seek(64u64);
        let poly = Poly1305::new(poly_key.as_slice().into());
        (cipher, poly)
    }

    /// Compute the Poly1305 tag over AAD ‖ pad ‖ CT ‖ pad ‖ len(AAD) ‖ len(CT).
    fn tag(mut poly: Poly1305, aad: &[u8], ct: &[u8]) -> [u8; 16] {
        poly.update_padded(aad);
        poly.update_padded(ct);
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
        len_block[8..].copy_from_slice(&(ct.len() as u64).to_le_bytes());
        poly.update(std::slice::from_ref((&len_block).into()));
        let tag = poly.finalize();
        let mut out = [0u8; 16];
        out.copy_from_slice(&tag);
        out
    }

    /// Seal: returns ciphertext ‖ 16-byte tag.
    pub fn seal(
        &self,
        nonce: &[u8; AUDIO_CHACHA_NONCE_SIZE],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Vec<u8> {
        let (mut cipher, poly) = self.init_cipher(nonce);
        let mut out = vec![0u8; plaintext.len() + AUDIO_CHACHA_OVERHEAD];
        out[..plaintext.len()].copy_from_slice(plaintext);
        cipher.apply_keystream(&mut out[..plaintext.len()]);
        let tag = Self::tag(poly, aad, &out[..plaintext.len()]);
        out[plaintext.len()..].copy_from_slice(&tag);
        out
    }

    /// Open: verifies the tag and returns the plaintext (used by tests).
    pub fn open(
        &self,
        nonce: &[u8; AUDIO_CHACHA_NONCE_SIZE],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        if ciphertext.len() < AUDIO_CHACHA_OVERHEAD {
            bail!("chacha20poly1305: message authentication failed");
        }
        let n = ciphertext.len() - AUDIO_CHACHA_OVERHEAD;
        let (mut cipher, poly) = self.init_cipher(nonce);
        let expected = Self::tag(poly, aad, &ciphertext[..n]);
        // Constant-time compare.
        let mut diff = 0u8;
        for i in 0..16 {
            diff |= expected[i] ^ ciphertext[n + i];
        }
        if diff != 0 {
            bail!("chacha20poly1305: message authentication failed");
        }
        let mut plaintext = ciphertext[..n].to_vec();
        cipher.apply_keystream(&mut plaintext);
        Ok(plaintext)
    }
}

// ---------------------------------------------------------------------------
// ALAC verbatim encoder + MSB-first bit writer (audio.go).
// ---------------------------------------------------------------------------

/// bitWriter writes bits MSB-first into a byte buffer (audio.go bitWriter).
struct BitWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
    bit_buf: u32,
    bit_pos: i32,
}

impl<'a> BitWriter<'a> {
    fn new(buf: &'a mut [u8]) -> BitWriter<'a> {
        BitWriter {
            buf,
            pos: 0,
            bit_buf: 0,
            bit_pos: 0,
        }
    }

    fn write(&mut self, mut val: u32, mut nbits: u32) {
        while nbits > 0 {
            let space = 8 - self.bit_pos as u32;
            if nbits <= space {
                self.bit_buf |= (val & ((1u32 << nbits) - 1)) << (space - nbits);
                self.bit_pos += nbits as i32;
                if self.bit_pos == 8 {
                    self.buf[self.pos] = self.bit_buf as u8;
                    self.pos += 1;
                    self.bit_buf = 0;
                    self.bit_pos = 0;
                }
                return;
            }
            // Fill the remaining space in the current byte.
            let shift = nbits - space;
            self.bit_buf |= (val >> shift) & ((1u32 << space) - 1);
            self.buf[self.pos] = self.bit_buf as u8;
            self.pos += 1;
            self.bit_buf = 0;
            self.bit_pos = 0;
            nbits = shift;
            val &= (1u32 << shift) - 1;
        }
    }

    fn flush(&mut self) -> usize {
        if self.bit_pos > 0 {
            self.buf[self.pos] = self.bit_buf as u8;
            self.pos += 1;
        }
        self.pos
    }
}

/// encode_alac_verbatim — produce a verbatim (uncompressed) ALAC frame from
/// interleaved S16LE PCM. Faithful port of audio.go encodeALACVerbatim.
///
/// Frame format (stereo, 16-bit):
///   tag(3)=1 (CPE) | elementInstance(4)=0 | unused(12)=0
///   hasSize(1)=1 | extraBytes(2)=0 | verbatim(1)=1 | numSamples(32)=frameSize
///   per sample: left(16) BE, right(16) BE | endTag(3)=7
pub fn encode_alac_verbatim(
    out: &mut [u8],
    pcm: &[u8],
    frame_size: usize,
    channels: usize,
    bit_depth: u32,
) -> usize {
    let mut bw = BitWriter::new(out);

    // Element header.
    if channels == 2 {
        bw.write(1, 3); // TYPE_CPE (channel pair element)
    } else {
        bw.write(0, 3); // TYPE_SCE (single channel element)
    }
    bw.write(0, 4); // elementInstanceTag
    bw.write(0, 12); // unused

    bw.write(1, 1); // hasSize = 1
    bw.write(0, 2); // extraBytes = 0 (16-bit)
    bw.write(1, 1); // verbatim = 1

    bw.write(frame_size as u32, 32); // numSamples

    // Raw samples: S16LE PCM → big-endian 16-bit (written MSB-first).
    for i in 0..frame_size * channels {
        let off = i * 2;
        let sample = (pcm[off] as u16) | ((pcm[off + 1] as u16) << 8);
        bw.write(sample as u32, bit_depth);
    }

    bw.write(7, 3); // TYPE_END

    bw.flush()
}

// ---------------------------------------------------------------------------
// AudioCapture — system-output (PulseAudio monitor) capture → raw PCM, encoded
// to ALAC verbatim frames on read (audio.go AudioCapture / StartAudioCapture).
//
// Like the video CaptureSource, the pipeline is built in-process with the
// GStreamer Rust bindings and pulls raw PCM off an appsink, rather than shelling
// out to gst-launch-1.0. The contract is identical: each ReadFrame reads exactly
// one frame's worth of PCM (spf*channels*2 bytes) and ALAC-encodes it.
// ---------------------------------------------------------------------------

pub struct AudioCapture {
    pipeline: gst::Pipeline,
    rx: Receiver<Vec<u8>>,
    /// Raw PCM bytes buffered across reads (the appsink delivers arbitrary sizes;
    /// ReadFrame consumes exactly one frame at a time).
    pcm: Vec<u8>,
    eos: Arc<Mutex<bool>>,
    channels: usize,
}

impl AudioCapture {
    /// PCM bytes in one ALAC frame: spf * channels * 2 (S16LE).
    fn frame_pcm_size(&self) -> usize {
        AUDIO_SPF as usize * self.channels * 2
    }

    /// StartAudioCapture analogue. `test_tone` swaps the monitor source for a
    /// 440 Hz sine (audiotestsrc), matching audio.go's debug path.
    pub fn start(test_tone: bool) -> Result<AudioCapture> {
        gst::init().context("gst init (audio)")?;

        let channels = 2usize;
        let pipeline = gst::Pipeline::new();

        // Source: audiotestsrc (test tone) or pulsesrc on the default sink's
        // monitor (system output). audio.go also falls back to pipewiresrc; here
        // we prefer pulsesrc (the task spec) and only fall back to a bare
        // pipewiresrc when pulsesrc cannot be created.
        let src = if test_tone {
            eprintln!("[audio] using test tone (440 Hz sine, spf={AUDIO_SPF})");
            gst::ElementFactory::make("audiotestsrc")
                .property_from_str("wave", "sine")
                .property("freq", 440.0f64)
                .property("is-live", true)
                .property("samplesperbuffer", AUDIO_SPF as i32)
                .build()
                .context("create audiotestsrc")?
        } else if let Some(monitor) = detect_pulse_monitor() {
            eprintln!("[audio] using pulsesrc device={monitor}");
            gst::ElementFactory::make("pulsesrc")
                .property("device", &monitor)
                .build()
                .context("create pulsesrc (install gst-plugin-pulseaudio)")?
        } else if let Ok(p) = gst::ElementFactory::make("pipewiresrc").build() {
            eprintln!("[audio] using pipewiresrc");
            p
        } else {
            bail!("no PulseAudio monitor source found (need pulsesrc or pipewiresrc)");
        };

        let audioconvert = make("audioconvert")?;
        let audioresample = make("audioresample")?;
        let caps = gst::ElementFactory::make("capsfilter")
            .property(
                "caps",
                &gst::Caps::builder("audio/x-raw")
                    .field("rate", AUDIO_SAMPLE_RATE as i32)
                    .field("channels", channels as i32)
                    .field("format", "S16LE")
                    .field("layout", "interleaved")
                    .build(),
            )
            .build()
            .context("create audio capsfilter")?;
        let queue = gst::ElementFactory::make("queue")
            .property("max-size-buffers", 2u32)
            .property("max-size-bytes", 0u32)
            .property("max-size-time", 0u64)
            .property_from_str("leaky", "downstream")
            .build()
            .context("create audio queue")?;

        let appsink = gst_app::AppSink::builder()
            .sync(false)
            .max_buffers(8)
            .drop(false)
            .build();

        let elems: Vec<gst::Element> = vec![
            src.clone(),
            audioconvert.clone(),
            audioresample.clone(),
            caps.clone(),
            queue.clone(),
            appsink.upcast_ref::<gst::Element>().clone(),
        ];
        for e in &elems {
            pipeline.add(e).context("add audio element")?;
        }
        gst::Element::link_many(elems.iter().collect::<Vec<_>>().as_slice())
            .context("link audio pipeline")?;

        let (tx, rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = mpsc::channel();
        let eos = Arc::new(Mutex::new(false));
        let eos_cb = eos.clone();
        appsink.set_callbacks(
            gst_app::AppSinkCallbacks::builder()
                .new_sample(move |sink| {
                    let sample = sink.pull_sample().map_err(|_| gst::FlowError::Eos)?;
                    if let Some(buffer) = sample.buffer() {
                        if let Ok(map) = buffer.map_readable() {
                            if tx.send(map.as_slice().to_vec()).is_err() {
                                return Err(gst::FlowError::Eos);
                            }
                        }
                    }
                    Ok(gst::FlowSuccess::Ok)
                })
                .eos(move |_| {
                    *eos_cb.lock().unwrap() = true;
                })
                .build(),
        );

        pipeline
            .set_state(gst::State::Playing)
            .context("set audio pipeline PLAYING")?;

        Ok(AudioCapture {
            pipeline,
            rx,
            pcm: Vec::new(),
            eos,
            channels,
        })
    }

    /// Block until one full frame of PCM is available, then ALAC-encode it into
    /// `buf`. Returns the encoded length, or 0 at end-of-stream.
    /// Faithful to audio.go ReadFrame (which io.ReadFull's exactly one frame).
    pub fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize> {
        let need = self.frame_pcm_size();
        while self.pcm.len() < need {
            match self.rx.recv() {
                Ok(chunk) => self.pcm.extend_from_slice(&chunk),
                Err(_) => {
                    if *self.eos.lock().unwrap() {
                        return Ok(0);
                    }
                    bail!("audio capture ended unexpectedly");
                }
            }
        }
        let n = encode_alac_verbatim(buf, &self.pcm[..need], AUDIO_SPF as usize, self.channels, 16);
        self.pcm.drain(..need);
        Ok(n)
    }

    /// DrainStale — discard whatever PCM backlog accumulated between capture
    /// start and the first read, so streaming begins from the freshest sample
    /// (audio.go DrainStale). Drops any buffered (already-delivered) PCM plus a
    /// short non-blocking sweep of the channel.
    pub fn drain_stale(&mut self) {
        let mut discarded = self.pcm.len();
        self.pcm.clear();
        // Drain anything already queued without blocking on fresh frames.
        while let Ok(chunk) = self.rx.try_recv() {
            discarded += chunk.len();
        }
        if discarded > 0 {
            let bytes_per_second = (AUDIO_SAMPLE_RATE * 2 * 2) as f64; // 44.1k, stereo, S16LE
            eprintln!(
                "[audio] drained {discarded} bytes (~{:.0}ms) of startup backlog before streaming",
                discarded as f64 / bytes_per_second * 1000.0
            );
        }
    }

    pub fn stop(&self) {
        let _ = self.pipeline.set_state(gst::State::Null);
    }
}

impl Drop for AudioCapture {
    fn drop(&mut self) {
        self.stop();
    }
}

fn make(name: &str) -> Result<gst::Element> {
    gst::ElementFactory::make(name)
        .build()
        .with_context(|| format!("create {name}"))
}

/// detect_pulse_monitor — the default PulseAudio sink's monitor source name
/// (audio.go detectPulseMonitor: `pactl get-default-sink` + ".monitor").
pub fn detect_pulse_monitor() -> Option<String> {
    let out = std::process::Command::new("pactl")
        .arg("get-default-sink")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let sink = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if sink.is_empty() {
        None
    } else {
        Some(format!("{sink}.monitor"))
    }
}

// ---------------------------------------------------------------------------
// AudioStream — the RTP audio channel (audio.go AudioStream).
// ---------------------------------------------------------------------------

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

pub struct AudioStream {
    /// Local UDP socket for sending audio data (controlPort+1 in the Go model).
    conn: UdpSocket,
    /// Control-port socket for sync/resend.
    ctrl_conn: UdpSocket,
    /// Receiver's audio data address.
    remote_addr: std::net::SocketAddr,
    /// Receiver's audio control address.
    ctrl_addr: std::net::SocketAddr,

    rtp_time: u32,
    ssrc: u32,

    // AES-128-CBC (legacy) key/IV; None when not used.
    aes_key: Option<[u8; 16]>,
    aes_iv: Option<[u8; 16]>,

    // ChaCha20-Poly1305 (64-bit nonce) cipher; None when not used.
    chacha: Option<AudioChaCha64>,

    security_mode: AudioSecurityMode,
    chacha_nonce: u64,
    chacha_nonce_mode: AudioChaChaNonceMode,
    chacha_aad_mode: AudioChaChaAadMode,

    ct: u8,
    spf: u16,
    latency_samples: u32,
}

impl AudioStream {
    /// True if the negotiated security mode uses the ChaCha AEAD.
    pub fn is_chacha(&self) -> bool {
        self.chacha.is_some()
    }

    pub fn latency_samples(&self) -> u32 {
        self.latency_samples
    }

    pub fn spf(&self) -> u16 {
        self.spf
    }

    /// audio.go nextAudioChaChaNonce. Returns (value, nonce-bytes). When `reuse`
    /// is Some the supplied value is used verbatim (for FEC retransmits).
    fn next_chacha_nonce(
        &mut self,
        seq: u16,
        rtp_time: u32,
        reuse: Option<u64>,
    ) -> (u64, [u8; AUDIO_CHACHA_NONCE_SIZE]) {
        let value = if let Some(v) = reuse {
            v
        } else {
            match self.chacha_nonce_mode {
                AudioChaChaNonceMode::Seq => seq as u64,
                AudioChaChaNonceMode::SeqZeroBased => {
                    if seq > 0 {
                        (seq - 1) as u64
                    } else {
                        0
                    }
                }
                AudioChaChaNonceMode::Rtp => rtp_time as u64,
                AudioChaChaNonceMode::Counter => {
                    let v = self.chacha_nonce;
                    self.chacha_nonce = self.chacha_nonce.wrapping_add(1);
                    v
                }
            }
        };
        let mut nonce = [0u8; AUDIO_CHACHA_NONCE_SIZE];
        nonce.copy_from_slice(&value.to_le_bytes());
        (value, nonce)
    }

    /// audio.go audioChaChaAAD.
    fn chacha_aad(&self, header: &[u8]) -> Vec<u8> {
        match self.chacha_aad_mode {
            AudioChaChaAadMode::RtpHeader => header.to_vec(),
            AudioChaChaAadMode::TimestampSsrc => header[4..12].to_vec(),
            AudioChaChaAadMode::None => Vec::new(),
        }
    }

    /// audio.go sendAudioPacketWithSeqAndNonce. Builds the 12-byte RTP header,
    /// encrypts the payload per the security mode, appends the LE64 nonce for
    /// the ChaCha path, and sends. Returns the nonce that was used.
    fn send_packet(
        &mut self,
        payload: &[u8],
        rtp_time: u32,
        seq: u16,
        reuse_nonce: Option<u64>,
    ) -> Result<u64> {
        // RTP header: 12 bytes.
        let mut header = [0u8; 12];
        header[0] = 0x80;
        header[1] = 0x60; // M=0, PT=96 (marker never set, matching Apple senders)
        header[2..4].copy_from_slice(&seq.to_be_bytes());
        header[4..8].copy_from_slice(&rtp_time.to_be_bytes());
        header[8..12].copy_from_slice(&self.ssrc.to_be_bytes());

        let mut used_nonce = 0u64;
        let packet_payload: Vec<u8> = if let Some(chacha) = self.chacha.clone() {
            let (n, nonce) = self.next_chacha_nonce(seq, rtp_time, reuse_nonce);
            used_nonce = n;
            let aad = self.chacha_aad(&header);
            let sealed = chacha.seal(&nonce, payload, &aad);
            // Wire layout: sealed (CT‖tag) followed by the 8-byte LE nonce.
            let mut pp = Vec::with_capacity(sealed.len() + 8);
            pp.extend_from_slice(&sealed);
            pp.extend_from_slice(&used_nonce.to_le_bytes());
            pp
        } else if let (Some(key), Some(iv)) = (self.aes_key, self.aes_iv) {
            aes_encrypt_audio_payload(&key, &iv, payload)
        } else {
            payload.to_vec()
        };

        let mut packet = Vec::with_capacity(12 + packet_payload.len());
        packet.extend_from_slice(&header);
        packet.extend_from_slice(&packet_payload);

        self.conn
            .send_to(&packet, self.remote_addr)
            .context("send audio rtp")?;

        // Track the latest RTP time for sync packets (only advance forward).
        if rtp_time >= self.rtp_time {
            self.rtp_time = rtp_time;
        }
        Ok(used_nonce)
    }

    /// audio.go sendSyncPacket — 20-byte control-port timing/sync packet.
    fn send_sync_packet(&self, ntp_time: u64, is_first: bool) -> Result<()> {
        let rtp_now = self.rtp_time;
        let anchor_latency = self.latency_samples;

        let mut packet = [0u8; 20];
        packet[0] = if is_first { 0x90 } else { 0x80 }; // V=2, X=1/0
        packet[1] = 0xd4; // M=1, PT=84
        packet[2..4].copy_from_slice(&4u16.to_be_bytes()); // seq constant 4
        // sync_rtp = current playback position = receive head - anchorLatency.
        let sync_rtp = if rtp_now >= anchor_latency {
            rtp_now - anchor_latency
        } else {
            rtp_now
        };
        packet[4..8].copy_from_slice(&sync_rtp.to_be_bytes());
        packet[8..16].copy_from_slice(&ntp_time.to_be_bytes());
        packet[16..20].copy_from_slice(&rtp_now.to_be_bytes()); // next_rtp = receive head

        self.ctrl_conn
            .send_to(&packet, self.ctrl_addr)
            .context("send audio sync")?;
        Ok(())
    }
}

/// aesEncryptAudioPayload — AES-128-CBC over full 16-byte blocks only; trailing
/// bytes are sent in the clear. Faithful port of audio.go aesEncryptAudioPayload.
pub fn aes_encrypt_audio_payload(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let block_size = 16usize;
    let enc_len = (data.len() / block_size) * block_size;
    if enc_len == 0 {
        return data.to_vec();
    }
    let mut out = data.to_vec();
    let mut enc = Aes128CbcEnc::new(key.into(), iv.into());
    // Encrypt each full block in place using the running CBC chain.
    for chunk in out[..enc_len].chunks_mut(block_size) {
        let block = aes::cipher::generic_array::GenericArray::from_mut_slice(chunk);
        enc.encrypt_block_mut(block);
    }
    out
}

// ---------------------------------------------------------------------------
// setup_audio_stream — build the AudioStream state (audio.go setupAudioStream).
//
// Real AirPlay senders use two UDP sockets for audio: the declared controlPort
// socket sends sync/control, and a separate data socket (controlPort+1) sends
// the RTP audio data. Both are passed in already bound, matching the Go signature
// (ctrlConn, dataConn).
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub fn setup_audio_stream(
    host: &str,
    data_port: u16,
    control_port: u16,
    aes_key: Option<[u8; 16]>,
    aes_iv: Option<[u8; 16]>,
    chacha_key: Option<[u8; 32]>,
    security_mode: AudioSecurityMode,
    ct: u8,
    latency_override: u32,
    ctrl_conn: UdpSocket,
    data_conn: UdpSocket,
) -> Result<AudioStream> {
    use std::net::ToSocketAddrs;
    let remote_addr = format!("{host}:{data_port}")
        .to_socket_addrs()
        .context("resolve audio remote")?
        .next()
        .ok_or_else(|| anyhow!("resolve audio remote: no address"))?;
    let ctrl_addr = format!("{host}:{control_port}")
        .to_socket_addrs()
        .context("resolve audio control remote")?
        .next()
        .ok_or_else(|| anyhow!("resolve audio control: no address"))?;

    let chacha = if security_mode == AudioSecurityMode::ChaCha {
        let key = chacha_key.ok_or_else(|| anyhow!("chacha mode requires a key"))?;
        Some(AudioChaCha64::new(&key)?)
    } else {
        None
    };

    let latency_samples = audio_latency_samples_for_codec(ct, latency_override);

    let security_name = if chacha.is_some() {
        "chacha20-poly1305-64x64"
    } else if aes_key.is_some() {
        "aes-128-cbc"
    } else {
        "none"
    };
    eprintln!(
        "[audio] stream setup: dataPort={data_port} controlPort={control_port} ct={ct} spf={AUDIO_SPF} ssrc=0x00000000 security={security_name}"
    );

    let stream = AudioStream {
        conn: data_conn,
        ctrl_conn,
        remote_addr,
        ctrl_addr,
        rtp_time: 0,
        ssrc: 0,
        aes_key: if chacha.is_some() { None } else { aes_key },
        aes_iv: if chacha.is_some() { None } else { aes_iv },
        chacha,
        security_mode,
        chacha_nonce: 0,
        chacha_nonce_mode: default_audio_chacha_nonce_mode(),
        chacha_aad_mode: default_audio_chacha_aad_mode(),
        ct,
        spf: AUDIO_SPF,
        latency_samples,
    };

    if stream.chacha.is_some() {
        eprintln!(
            "[audio] chacha config: nonce={} aad={}",
            stream.chacha_nonce_mode.as_str(),
            stream.chacha_aad_mode.as_str()
        );
    }

    Ok(stream)
}

// ---------------------------------------------------------------------------
// stream_audio — read ALAC frames + send RTP audio + periodic sync packets.
// Faithful port of audio.go StreamAudio.
//
// `first_frame` gates audio start on the first video frame (audio.go waits on
// s.firstFrameSent). `boot_origin` provides the NTP boot-relative clock the
// sync packets use; `stop` is the shared mirror stop flag.
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub fn stream_audio(
    capture: &mut AudioCapture,
    audio: Arc<Mutex<AudioStream>>,
    first_frame: &Arc<AtomicBool>,
    stop: &Arc<AtomicBool>,
    boot_origin: Instant,
) -> Result<()> {
    let spf = {
        let a = audio.lock().unwrap();
        a.spf as u32
    };

    // Wait for the first video frame before starting audio (audio.go).
    eprintln!("[audio] waiting for first video frame before starting audio...");
    while !first_frame.load(Ordering::Relaxed) {
        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    eprintln!("[audio] first video frame sent, starting audio");

    // Initial sync burst: 7 identical X=1 sync packets before any audio data.
    let ntp_now = ntp_boot_timestamp(boot_origin);
    {
        let a = audio.lock().unwrap();
        for _ in 0..7 {
            if let Err(e) = a.send_sync_packet(ntp_now, true) {
                eprintln!("[audio] initial sync error: {e}");
            }
        }
    }

    // Start data RTP time at latencySamples so the first audio packet's rtp is
    // >= next_rtp from the sync packets.
    let latency_samples = {
        let mut a = audio.lock().unwrap();
        let ls = a.latency_samples;
        a.rtp_time = ls;
        ls
    };
    let mut next_rtp = latency_samples;
    eprintln!("[audio] sent initial sync burst (7 packets), starting audio at rtp={next_rtp}");

    // Periodic sync sender: every 200ms for the first 5s, then every 1s.
    {
        let audio = audio.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            let start = Instant::now();
            loop {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                let interval = if start.elapsed() < Duration::from_secs(5) {
                    Duration::from_millis(200)
                } else {
                    Duration::from_secs(1)
                };
                std::thread::sleep(interval);
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                let nt = ntp_boot_timestamp(boot_origin);
                let a = audio.lock().unwrap();
                if let Err(e) = a.send_sync_packet(nt, false) {
                    eprintln!("[audio] sync error: {e}");
                }
            }
        });
    }

    // Control-port listener (resend requests) in the background.
    {
        let ctrl = {
            let a = audio.lock().unwrap();
            a.ctrl_conn.try_clone().ok()
        };
        if let Some(ctrl) = ctrl {
            let stop = stop.clone();
            std::thread::spawn(move || {
                ctrl.set_read_timeout(Some(Duration::from_secs(1))).ok();
                let mut buf = [0u8; 1024];
                loop {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    match ctrl.recv_from(&mut buf) {
                        Ok(_) => {}
                        Err(ref e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.kind() == std::io::ErrorKind::TimedOut =>
                        {
                            continue;
                        }
                        Err(_) => return,
                    }
                }
            });
        }
    }

    // Redundant audio (FEC) is kept only for legacy/plaintext sessions; modern
    // ChaCha-encrypted receivers decode more reliably when each frame is sent
    // once (audio.go useAudioFEC).
    let use_fec = {
        let a = audio.lock().unwrap();
        use_audio_fec(a.is_chacha())
    };
    if use_fec {
        eprintln!("[audio] FEC enabled: burst-8 + interleaved retransmit");
    } else {
        eprintln!("[audio] FEC disabled for ChaCha-encrypted sessions: each frame sent once");
    }

    const RETRANSMIT_DEPTH: usize = 8;
    #[derive(Clone, Default)]
    struct AudioFrame {
        payload: Vec<u8>,
        rtp_time: u32,
        seq: u16,
        nonce: u64,
    }
    let mut retransmit_buf: Vec<AudioFrame> = vec![AudioFrame::default(); RETRANSMIT_DEPTH];
    let mut frame_seq: u16 = 1; // first frame = seq 1
    let mut frame_count: u64 = 0;
    let mut retransmit_idx = 0usize;
    let mut burst_done = false;
    let mut frame_buf = vec![0u8; 8192];

    // The capture started before video did; drop the stale backlog so audio
    // lines up with video (audio.go DrainStale).
    capture.drain_stale();

    loop {
        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }

        let n = capture.read_frame(&mut frame_buf)?;
        if n == 0 {
            // EOF.
            return Ok(());
        }

        let payload = frame_buf[..n].to_vec();
        frame_count += 1;

        if !use_fec {
            let mut a = audio.lock().unwrap();
            a.send_packet(&payload, next_rtp, frame_seq, None)
                .context("audio send")?;
        } else if !burst_done {
            let nonce = {
                let mut a = audio.lock().unwrap();
                a.send_packet(&payload, next_rtp, frame_seq, None)
                    .context("audio send")?
            };
            retransmit_buf[retransmit_idx] = AudioFrame {
                payload: payload.clone(),
                rtp_time: next_rtp,
                seq: frame_seq,
                nonce,
            };
            retransmit_idx += 1;
            if retransmit_idx >= RETRANSMIT_DEPTH {
                burst_done = true;
                retransmit_idx = 0;
                eprintln!("[audio] initial burst of {RETRANSMIT_DEPTH} frames complete");
            }
        } else {
            // Steady state: retransmit an old frame, then send the new one.
            let old = retransmit_buf[retransmit_idx].clone();
            {
                let mut a = audio.lock().unwrap();
                a.send_packet(&old.payload, old.rtp_time, old.seq, Some(old.nonce))
                    .context("audio retransmit")?;
            }
            let nonce = {
                let mut a = audio.lock().unwrap();
                a.send_packet(&payload, next_rtp, frame_seq, None)
                    .context("audio send")?
            };
            retransmit_buf[retransmit_idx] = AudioFrame {
                payload: payload.clone(),
                rtp_time: next_rtp,
                seq: frame_seq,
                nonce,
            };
            retransmit_idx = (retransmit_idx + 1) % RETRANSMIT_DEPTH;
        }

        frame_seq = frame_seq.wrapping_add(1);
        next_rtp = next_rtp.wrapping_add(spf);

        if frame_count <= 10 || frame_count % 100 == 0 {
            eprintln!(
                "[audio] sent frame {frame_count}: seq={} payload={n} rtp={}",
                frame_seq - 1,
                next_rtp - spf
            );
        }
    }
}

/// ntpBootTimestamp — boot-relative time with the NTP epoch (1900) added.
/// Matches mirror.go ntpBootTimestamp / the existing mirror.rs helper.
const SECONDS_FROM_1900_TO_1970: u64 = 2208988800;
fn ntp_boot_timestamp(origin: Instant) -> u64 {
    let d = origin.elapsed();
    let sec = d.as_secs() + SECONDS_FROM_1900_TO_1970;
    let nsec_frac = d.subsec_nanos() as u64;
    let frac = (nsec_frac << 32) / 1_000_000_000u64;
    (sec << 32) | frac
}

// Keep the unused-import lint quiet for Read (kept to mirror audio.go's
// io.ReadFull contract should the capture move back to a pipe reader).
#[allow(dead_code)]
fn _io_read_marker(_r: &mut dyn Read) {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alac_verbatim_known_frame() {
        // A tiny 2-sample stereo S16LE frame: L0=0x0102, R0=0x0304,
        // L1=0x0506, R1=0x0708 (little-endian on the wire).
        let pcm: [u8; 8] = [0x02, 0x01, 0x04, 0x03, 0x06, 0x05, 0x08, 0x07];
        let mut out = [0u8; 64];
        let n = encode_alac_verbatim(&mut out, &pcm, 2, 2, 16);

        // Bit layout (MSB-first), as emitted by audio.go encodeALACVerbatim:
        //   tag=1 (3b) | elemInstance=0 (4b) | unused=0 (12b)
        //   hasSize=1 (1b) | extraBytes=0 (2b) | verbatim=1 (1b)
        //   numSamples=2 (32b) | 4 BE 16-bit samples | endTag=7 (3b)
        // total = 3+4+12 + 1+2+1 + 32 + 4*16 + 3 = 122 bits → 16 bytes.
        // The exact expected byte stream (verified independently):
        let expected: [u8; 16] = [
            0x20, 0x00, 0x12, 0x00, 0x00, 0x00, 0x04, // header + numSamples=2
            0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, // samples 0102 0304 0506 0708
            0x11, 0xc0, // last sample tail + endTag=7, padded
        ];
        assert_eq!(n, 16);
        assert_eq!(&out[..n], &expected[..]);

        // Determinism / stability check.
        let mut out2 = [0u8; 64];
        let n2 = encode_alac_verbatim(&mut out2, &pcm, 2, 2, 16);
        assert_eq!(n, n2);
        assert_eq!(&out[..n], &out2[..n2]);
    }

    #[test]
    fn chacha64_roundtrip() {
        let key = [7u8; 32];
        let aead = AudioChaCha64::new(&key).unwrap();
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        let aad = b"timestampssrc12"; // arbitrary AAD
        let plaintext = b"hello airplay audio frame payload that spans many blocks!!";

        let sealed = aead.seal(&nonce, plaintext, aad);
        assert_eq!(sealed.len(), plaintext.len() + AUDIO_CHACHA_OVERHEAD);

        let opened = aead.open(&nonce, &sealed, aad).unwrap();
        assert_eq!(&opened, plaintext);

        // Tamper with the tag → auth must fail.
        let mut bad = sealed.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xff;
        assert!(aead.open(&nonce, &bad, aad).is_err());

        // Wrong AAD → auth must fail.
        assert!(aead.open(&nonce, &sealed, b"different aad!!!").is_err());

        // Empty plaintext still round-trips (just the tag).
        let s2 = aead.seal(&nonce, b"", aad);
        assert_eq!(s2.len(), AUDIO_CHACHA_OVERHEAD);
        assert_eq!(aead.open(&nonce, &s2, aad).unwrap(), b"");
    }

    #[test]
    fn chacha64_vector_rfc7539_djb() {
        // Cross-check the 64-bit-nonce construction against a self-derived
        // reference: encrypt, then independently recompute the keystream/tag the
        // same way the Go aead lib does, proving the poly1305 key comes from
        // block 0 and the ciphertext from block 1.
        let key = [0u8; 32];
        let nonce = [0u8; 8];
        let aead = AudioChaCha64::new(&key).unwrap();
        let pt = [0u8; 40];
        let sealed = aead.seal(&nonce, &pt, &[]);

        // Reference keystream: ChaCha20Legacy from block 1 over 40 zero bytes.
        let mut cipher = ChaCha20Legacy::new(
            (&key).into(),
            chacha20::LegacyNonce::from_slice(&nonce),
        );
        let mut polykey = [0u8; 32];
        cipher.apply_keystream(&mut polykey);
        cipher.seek(64u64);
        let mut ref_ct = pt;
        cipher.apply_keystream(&mut ref_ct);
        assert_eq!(&sealed[..40], &ref_ct[..]);

        // Reference tag via update_padded over (aad=∅, ct, len-block).
        let mut poly = Poly1305::new(polykey.as_slice().into());
        poly.update_padded(&ref_ct);
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&0u64.to_le_bytes());
        len_block[8..].copy_from_slice(&40u64.to_le_bytes());
        poly.update(std::slice::from_ref((&len_block).into()));
        let tag = poly.finalize();
        assert_eq!(&sealed[40..], tag.as_slice());

        // And the sealed output must Open cleanly.
        assert_eq!(aead.open(&nonce, &sealed, &[]).unwrap().as_slice(), &pt[..]);
    }
}
