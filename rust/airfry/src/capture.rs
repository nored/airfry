//! Screen capture + H.264 encode pipeline (GStreamer), the Rust analogue of
//! doubletake's internal/airplay/capture.go.
//!
//! capture.go shells out to `gst-launch-1.0` and reads an Annex-B H.264
//! byte-stream from the child's stdout, which `StreamFrames` then parses for
//! NAL units. We keep that exact contract — a stream of raw Annex-B bytes — but
//! build the pipeline in-process with the GStreamer Rust bindings and pull the
//! encoded buffers off an `appsink`. The pipeline mirrors capture.go's:
//!
//!   Wayland: pipewiresrc fd=<portal fd> path=<node> do-timestamp=true
//!            ! videoconvert ! videorate drop-only ! capsfilter(framerate)
//!            ! queue(leaky=downstream) [! videoscale/videobox for fit]
//!            ! <encoder> ! h264parse config-interval=-1
//!            ! video/x-h264,stream-format=byte-stream,alignment=au ! appsink
//!   X11:     ximagesrc ! ... (same tail)
//!
//! Encoder selection follows capture.go's fallback chain but adapted to the
//! task's required order: vaapih264enc -> vah264enc -> x264enc.
//!
//! The capture runs on its own GStreamer thread; encoded byte chunks are pushed
//! through an `mpsc` channel. `CaptureSource::read` reassembles them into the
//! caller's buffer exactly like `capture.Read` filled a slice from stdout.

#![allow(dead_code)]

use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Context, Result};
use gstreamer as gst;
use gstreamer::prelude::*;
use gstreamer_app as gst_app;

/// Capture configuration (subset of capture.go's CaptureConfig that the mirror
/// pipeline actually uses).
#[derive(Clone, Debug)]
pub struct CaptureConfig {
    /// Target frame rate (defaults to 30 if 0).
    pub fps: u32,
    /// Video bitrate in kbps (0 = auto, sized from the source resolution).
    pub bitrate_kbps: u32,
    /// "fit"/underscan percent (0 = native passthrough). Shrinks the desktop
    /// into the centre by this percent and pads black, to counter Apple TVs
    /// that overscan/zoom. Clamped to 25 like capture.go.
    pub fit_pct: u8,
    /// Force the software encoder (x264enc). Useful where VA-API is absent.
    pub force_software: bool,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        CaptureConfig {
            fps: 30,
            bitrate_kbps: 0,
            fit_pct: 0,
            force_software: false,
        }
    }
}

const DEFAULT_VIDEO_BITRATE_KBPS: u32 = 4500;
const MIN_VIDEO_BITRATE_KBPS: u32 = 1800;
const MAX_VIDEO_BITRATE_KBPS: u32 = 12000;

/// recommendedBitrateKbps — capture.go's auto-bitrate heuristic.
fn recommended_bitrate_kbps(width: u32, height: u32, fps: u32) -> u32 {
    if width == 0 || height == 0 || fps == 0 {
        return DEFAULT_VIDEO_BITRATE_KBPS;
    }
    let bitrate = (width * height * fps + 7500) / 15000;
    bitrate.clamp(MIN_VIDEO_BITRATE_KBPS, MAX_VIDEO_BITRATE_KBPS)
}

/// keyframeIntervalFrames — capture.go: fps * 4.
fn keyframe_interval_frames(fps: u32) -> u32 {
    let fps = if fps == 0 { 30 } else { fps };
    fps * 4
}

/// A running screen-capture pipeline. Drop or call `stop()` to tear it down.
pub struct CaptureSource {
    pipeline: gst::Pipeline,
    rx: Receiver<Vec<u8>>,
    /// Bytes left over from the previous `read` that didn't fit the caller buf.
    leftover: Vec<u8>,
    /// Kept alive so the portal session / PipeWire fd stay open for the
    /// pipeline's lifetime (Wayland only).
    _portal: Option<PortalSession>,
    eos: Arc<Mutex<bool>>,
}

impl CaptureSource {
    /// Detect the display server (Wayland vs X11) and start the matching
    /// capture+encode pipeline. Mirrors capture.go's StartCapture dispatch.
    pub fn start(cfg: &CaptureConfig) -> Result<CaptureSource> {
        gst::init().context("gst init")?;

        if std::env::var_os("WAYLAND_DISPLAY").is_some() {
            Self::start_wayland(cfg)
        } else if std::env::var_os("DISPLAY").is_some() {
            Self::start_x11(cfg)
        } else {
            bail!("no display server detected (neither WAYLAND_DISPLAY nor DISPLAY is set)")
        }
    }

    fn start_wayland(cfg: &CaptureConfig) -> Result<CaptureSource> {
        let portal = request_screencast().context("screencast portal")?;
        let (src_w, src_h) = portal.size;
        eprintln!(
            "[capture] portal node={} size={}x{}",
            portal.node_id, src_w, src_h
        );

        // pipewiresrc wants the raw fd of the portal's PipeWire remote.
        let fd = portal.fd.as_raw_fd();
        let src = gst::ElementFactory::make("pipewiresrc")
            .property("fd", fd)
            .property("path", portal.node_id.to_string())
            .property("do-timestamp", true)
            .build()
            .context("create pipewiresrc (install gst-plugin-pipewire)")?;

        Self::build_pipeline(cfg, src, src_w, src_h, Some(portal))
    }

    fn start_x11(cfg: &CaptureConfig) -> Result<CaptureSource> {
        let src = gst::ElementFactory::make("ximagesrc")
            .property("use-damage", false)
            .build()
            .context("create ximagesrc (install gst-plugins-good)")?;
        // We do not crop to the primary monitor here (capture.go uses xrandr);
        // ximagesrc captures the full X screen. Source size is unknown → 0,0,
        // which makes the auto-bitrate fall back to a 1080p budget.
        Self::build_pipeline(cfg, src, 0, 0, None)
    }

    /// Build and link the shared encode tail and an appsink, then start the
    /// pipeline and spawn the appsink pump.
    fn build_pipeline(
        cfg: &CaptureConfig,
        src: gst::Element,
        src_w: u32,
        src_h: u32,
        portal: Option<PortalSession>,
    ) -> Result<CaptureSource> {
        let fps = if cfg.fps == 0 { 30 } else { cfg.fps };
        let pipeline = gst::Pipeline::new();

        let videoconvert = make("videoconvert")?;
        let videorate = gst::ElementFactory::make("videorate")
            .property("drop-only", true)
            .property("skip-to-first", true)
            .build()
            .context("create videorate")?;
        let rate_caps = gst::ElementFactory::make("capsfilter")
            .property(
                "caps",
                &gst::Caps::builder("video/x-raw")
                    .field("framerate", gst::Fraction::new(fps as i32, 1))
                    .build(),
            )
            .build()
            .context("create framerate capsfilter")?;
        let queue = gst::ElementFactory::make("queue")
            .property("max-size-buffers", 1u32)
            .property("max-size-bytes", 0u32)
            .property("max-size-time", 0u64)
            .property_from_str("leaky", "downstream")
            .build()
            .context("create queue")?;

        // Optional fit/underscan scaling stage (videoscale [+ videobox]).
        let fit_elems = build_fit_stage(cfg.fit_pct, src_w, src_h)?;

        let encoder = build_encoder(cfg, src_w, src_h, fps)?;

        let h264parse = gst::ElementFactory::make("h264parse")
            .property("config-interval", -1i32)
            .build()
            .context("create h264parse")?;
        let parse_caps = gst::ElementFactory::make("capsfilter")
            .property(
                "caps",
                &gst::Caps::builder("video/x-h264")
                    .field("stream-format", "byte-stream")
                    .field("alignment", "au")
                    .build(),
            )
            .build()
            .context("create h264 byte-stream capsfilter")?;

        let appsink = gst_app::AppSink::builder()
            .sync(false)
            .max_buffers(8)
            .drop(false)
            .build();

        // Assemble element list in order.
        let mut elems: Vec<gst::Element> = vec![
            src.clone(),
            videoconvert.clone(),
            videorate.clone(),
            rate_caps.clone(),
            queue.clone(),
        ];
        elems.extend(fit_elems.iter().cloned());
        elems.push(encoder.clone());
        elems.push(h264parse.clone());
        elems.push(parse_caps.clone());
        elems.push(appsink.upcast_ref::<gst::Element>().clone());

        for e in &elems {
            pipeline.add(e).context("add element to pipeline")?;
        }
        gst::Element::link_many(elems.iter().collect::<Vec<_>>().as_slice())
            .context("link pipeline")?;

        // appsink pump: push each encoded buffer's bytes down the channel.
        let (tx, rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = mpsc::channel();
        let eos = Arc::new(Mutex::new(false));
        let eos_cb = eos.clone();
        appsink.set_callbacks(
            gst_app::AppSinkCallbacks::builder()
                .new_sample(move |sink| {
                    let sample = sink.pull_sample().map_err(|_| gst::FlowError::Eos)?;
                    if let Some(buffer) = sample.buffer() {
                        if let Ok(map) = buffer.map_readable() {
                            // Channel send failure means the consumer dropped;
                            // signal EOS upstream so the pipeline can wind down.
                            if tx.send(map.as_slice().to_vec()).is_err() {
                                return Err(gst::FlowError::Eos);
                            }
                        }
                    }
                    Ok(gst::FlowSuccess::Ok)
                })
                .eos(move |_sink| {
                    *eos_cb.lock().unwrap() = true;
                })
                .build(),
        );

        pipeline
            .set_state(gst::State::Playing)
            .context("set pipeline PLAYING")?;

        Ok(CaptureSource {
            pipeline,
            rx,
            leftover: Vec::new(),
            _portal: portal,
            eos,
        })
    }

    /// Fill `buf` with the next chunk of the Annex-B H.264 byte-stream, the
    /// faithful analogue of capture.go's `(*ScreenCapture).Read`. Returns the
    /// number of bytes written, or 0 at end-of-stream.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.leftover.is_empty() {
            match self.rx.recv() {
                Ok(chunk) => self.leftover = chunk,
                Err(_) => {
                    // Channel closed: EOS or pipeline gone.
                    if *self.eos.lock().unwrap() {
                        return Ok(0);
                    }
                    bail!("capture pipeline ended unexpectedly (channel closed)");
                }
            }
        }
        let n = buf.len().min(self.leftover.len());
        buf[..n].copy_from_slice(&self.leftover[..n]);
        self.leftover.drain(..n);
        Ok(n)
    }

    pub fn stop(&self) {
        let _ = self.pipeline.set_state(gst::State::Null);
    }
}

impl Drop for CaptureSource {
    fn drop(&mut self) {
        self.stop();
    }
}

fn make(name: &str) -> Result<gst::Element> {
    gst::ElementFactory::make(name)
        .build()
        .with_context(|| format!("create {name}"))
}

/// build_fit_stage — the videoscale/videobox segment for the fit/underscan
/// percentage, mirroring capture.go's applyOutputScale fit branch. Needs the
/// source size; if it is unknown (0) we can only pass through (no fit), since
/// the absolute videobox borders depend on the frame size.
fn build_fit_stage(fit_pct: u8, src_w: u32, src_h: u32) -> Result<Vec<gst::Element>> {
    if fit_pct == 0 || src_w == 0 || src_h == 0 {
        return Ok(Vec::new());
    }
    let mut fit = fit_pct as i32;
    if fit > 25 {
        fit = 25;
    }
    let tw = src_w as i32;
    let th = src_h as i32;
    let mut cw = tw * (100 - fit) / 100;
    let mut ch = th * (100 - fit) / 100;
    cw -= cw % 2;
    ch -= ch % 2;
    let bx = (tw - cw) / 2;
    let by = (th - ch) / 2;

    let videoscale = make("videoscale")?;
    let scale_caps = gst::ElementFactory::make("capsfilter")
        .property(
            "caps",
            &gst::Caps::builder("video/x-raw")
                .field("width", cw)
                .field("height", ch)
                .build(),
        )
        .build()
        .context("create fit scale capsfilter")?;
    // videobox with negative borders pads (adds) pixels; matches capture.go's
    // left/right/top/bottom = -bx/-by with fill=black.
    let videobox = gst::ElementFactory::make("videobox")
        .property_from_str("fill", "black")
        .property("autocrop", false)
        .property("left", -bx)
        .property("right", -bx)
        .property("top", -by)
        .property("bottom", -by)
        .build()
        .context("create videobox")?;
    let box_caps = gst::ElementFactory::make("capsfilter")
        .property(
            "caps",
            &gst::Caps::builder("video/x-raw")
                .field("width", tw)
                .field("height", th)
                .build(),
        )
        .build()
        .context("create fit out capsfilter")?;

    eprintln!(
        "[capture] fit {fit}%: desktop {cw}x{ch} centered in {tw}x{th} frame (border {bx}/{by})"
    );
    Ok(vec![videoscale, scale_caps, videobox, box_caps])
}

/// build_encoder — runtime encoder selection with the required fallback chain:
/// vaapih264enc -> vah264enc -> x264enc. Configures low-latency CBR and a
/// keyframe interval, matching the spirit of capture.go's detectGstEncoder.
fn build_encoder(
    cfg: &CaptureConfig,
    src_w: u32,
    src_h: u32,
    fps: u32,
) -> Result<gst::Element> {
    let bitrate = if cfg.bitrate_kbps > 0 {
        cfg.bitrate_kbps
    } else {
        let (w, h) = if src_w > 0 && src_h > 0 {
            (src_w, src_h)
        } else {
            (1920, 1080)
        };
        let b = recommended_bitrate_kbps(w, h, fps);
        eprintln!("[capture] auto bitrate: {b} kbps for {w}x{h}@{fps}fps");
        b
    };
    let key_int = keyframe_interval_frames(fps);

    if !cfg.force_software {
        // vaapih264enc (legacy VA-API). bitrate in kbps; keyframe-period frames.
        if let Ok(enc) = gst::ElementFactory::make("vaapih264enc")
            .property("bitrate", bitrate)
            .property("keyframe-period", key_int)
            .property_from_str("rate-control", "cbr")
            .build()
        {
            eprintln!("[capture] encoder: vaapih264enc (bitrate={bitrate} kbps)");
            return Ok(enc);
        }
        // vah264enc (newer VA-API). bitrate in kbps; key-int-max in frames.
        if let Ok(enc) = gst::ElementFactory::make("vah264enc")
            .property("bitrate", bitrate)
            .property("key-int-max", key_int)
            .property("b-frames", 0u32)
            .property_from_str("rate-control", "cbr")
            .build()
        {
            eprintln!("[capture] encoder: vah264enc (bitrate={bitrate} kbps)");
            return Ok(enc);
        }
    }

    // Software fallback: x264enc, low-latency, no B-frames, Annex-B + AUDs.
    let vbv = vbv_buffer_kbit(bitrate, fps);
    let maxrate = bitrate + bitrate / 4;
    let enc = gst::ElementFactory::make("x264enc")
        .property_from_str("tune", "zerolatency")
        .property_from_str("speed-preset", "superfast")
        .property("bitrate", bitrate)
        .property("vbv-buf-capacity", vbv)
        .property("key-int-max", key_int)
        .property_from_str("pass", "cbr")
        .property("option-string", format!("vbv-maxrate={maxrate}"))
        .property("b-frames", 0u32)
        .property("sliced-threads", true)
        .property("byte-stream", true)
        .property("aud", true)
        .build()
        .context("create x264enc (install gst-plugins-ugly / libx264)")?;
    eprintln!("[capture] encoder: x264enc software (bitrate={bitrate} kbps)");
    Ok(enc)
}

/// vbvBufferKbit — capture.go: ~2 frames of data, floored at 200.
fn vbv_buffer_kbit(bitrate_kbps: u32, fps: u32) -> u32 {
    if bitrate_kbps == 0 || fps == 0 {
        return 300;
    }
    let vbv = bitrate_kbps * 2 / fps;
    vbv.max(200)
}

// ---------------------------------------------------------------------------
// XDG ScreenCast portal (Wayland) — ashpd analogue of capture.go's
// requestScreencast. We drive ashpd's async API on a small current-thread
// tokio runtime and hand back the PipeWire node id, the source size, and the
// OwnedFd of the portal's PipeWire remote (kept alive for the pipeline).
// ---------------------------------------------------------------------------

/// A live screencast portal session: holds the PipeWire remote fd and node id.
pub struct PortalSession {
    pub node_id: u32,
    pub size: (u32, u32),
    pub fd: OwnedFd,
}

fn request_screencast() -> Result<PortalSession> {
    use ashpd::desktop::screencast::{CursorMode, Screencast, SourceType};
    use ashpd::desktop::PersistMode;
    use ashpd::WindowIdentifier;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build tokio runtime for portal")?;

    rt.block_on(async {
        let proxy = Screencast::new()
            .await
            .context("connect ScreenCast portal")?;
        let session = proxy
            .create_session()
            .await
            .context("portal CreateSession")?;

        // MONITOR source, embedded cursor, single source, no persistence — the
        // GNOME portal then always prompts for the display (matches capture.go,
        // which uses persist_mode 0 so "choose display" works reliably).
        proxy
            .select_sources(
                &session,
                CursorMode::Embedded,
                SourceType::Monitor.into(),
                false,
                None,
                PersistMode::DoNot,
            )
            .await
            .context("portal SelectSources")?;

        let identifier = WindowIdentifier::default();
        let response = proxy
            .start(&session, &identifier)
            .await
            .context("portal Start")?
            .response()
            .context("portal Start response")?;

        let streams = response.streams();
        let stream = streams
            .first()
            .ok_or_else(|| anyhow!("portal returned no streams"))?;
        let node_id = stream.pipe_wire_node_id();
        let size = stream
            .size()
            .map(|(w, h)| (w.max(0) as u32, h.max(0) as u32))
            .unwrap_or((0, 0));

        let fd = proxy
            .open_pipe_wire_remote(&session)
            .await
            .context("portal OpenPipeWireRemote")?;

        Ok(PortalSession { node_id, size, fd })
    })
}
