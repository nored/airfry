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
//! Encoder selection follows capture.go's detectGstEncoder fallback chain
//! exactly: vulkanh264enc (NVENC via Vulkan) -> nvh264enc (legacy NVENC) ->
//! vah264enc (VA-API) -> x264enc, gated by an HWAccel mode
//! ("auto"/"nvenc"/"vaapi"/"none", read from $AIRFRY_HWACCEL /
//! $DOUBLETAKE_HWACCEL, default "auto").
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

/// Callback invoked with the XDG ScreenCast portal's returned restore token, so
/// the caller can persist it (e.g. credentials.save_restore_token) and reuse it
/// on the next run to avoid re-prompting. Mirrors capture.go's
/// `CaptureConfig.SaveRestoreToken` (capture.go:24-25,75-79).
pub type RestoreTokenCallback = Arc<dyn Fn(&str) + Send + Sync>;

/// Capture configuration (subset of capture.go's CaptureConfig that the mirror
/// pipeline actually uses).
#[derive(Clone)]
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
    /// Use the synthetic videotestsrc pipeline (main.go -test / capture.go
    /// StartTestCapture) instead of real screen capture. Runs with no
    /// display/portal.
    pub test: bool,
    /// XDG ScreenCast portal restore token from a previous run (Wayland). When
    /// set, ashpd is asked to restore the prior grant so the portal does not
    /// re-prompt for the display (capture.go:24,71; daemon.go:533-537).
    pub restore_token: Option<String>,
    /// Invoked with the portal's NEW restore token once a session is granted, so
    /// the caller can persist it for next time (capture.go:25,75-79;
    /// daemon.go:729-733). Only fires on Wayland.
    pub on_restore_token: Option<RestoreTokenCallback>,
}

impl std::fmt::Debug for CaptureConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptureConfig")
            .field("fps", &self.fps)
            .field("bitrate_kbps", &self.bitrate_kbps)
            .field("fit_pct", &self.fit_pct)
            .field("force_software", &self.force_software)
            .field("test", &self.test)
            .field("restore_token", &self.restore_token)
            .field("on_restore_token", &self.on_restore_token.is_some())
            .finish()
    }
}

impl Default for CaptureConfig {
    fn default() -> Self {
        CaptureConfig {
            fps: 30,
            bitrate_kbps: 0,
            fit_pct: 0,
            force_software: false,
            test: false,
            restore_token: None,
            on_restore_token: None,
        }
    }
}

const DEFAULT_VIDEO_BITRATE_KBPS: u32 = 4500;
const MIN_VIDEO_BITRATE_KBPS: u32 = 1800;
const MAX_VIDEO_BITRATE_KBPS: u32 = 12000;

/// Synthetic test-source dimensions (capture.go:35-36 testCaptureWidth/Height).
const TEST_CAPTURE_WIDTH: i32 = 1920;
const TEST_CAPTURE_HEIGHT: i32 = 1080;

/// Read an env var, trying the AIRFRY_ name first and falling back to the
/// DOUBLETAKE_ name (the original Go reads DOUBLETAKE_*; we honor both).
fn env_var(suffix: &str) -> Option<String> {
    std::env::var(format!("AIRFRY_{suffix}"))
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var(format!("DOUBLETAKE_{suffix}"))
                .ok()
                .filter(|s| !s.is_empty())
        })
}

/// $DOUBLETAKE_OUTPUT_HEIGHT (applyOutputScale, capture.go:596).
fn output_height_env() -> i32 {
    env_var("OUTPUT_HEIGHT")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// $DOUBLETAKE_FIT_PCT (applyOutputScale, capture.go:613). When set it
/// overrides any CLI-supplied fit percent, matching Go (which only reads fit
/// from the env).
fn fit_pct_env(cfg: &CaptureConfig) -> i32 {
    if let Some(v) = env_var("FIT_PCT").and_then(|s| s.parse::<i32>().ok()) {
        return v;
    }
    cfg.fit_pct as i32
}

/// HWAccel mode: "auto" (default), "nvenc", "vaapi", "none". Mirrors
/// cfg.HWAccel in capture.go's detectGstEncoder. `force_software` maps to
/// "none". Read from $AIRFRY_HWACCEL / $DOUBLETAKE_HWACCEL otherwise.
fn hwaccel_mode(cfg: &CaptureConfig) -> String {
    if cfg.force_software {
        return "none".to_string();
    }
    env_var("HWACCEL").unwrap_or_else(|| "auto".to_string())
}

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

        if cfg.test {
            return Self::start_test(cfg);
        }

        if std::env::var_os("WAYLAND_DISPLAY").is_some() {
            Self::start_wayland(cfg)
        } else if std::env::var_os("DISPLAY").is_some() {
            Self::start_x11(cfg)
        } else {
            bail!("no display server detected (neither WAYLAND_DISPLAY nor DISPLAY is set)")
        }
    }

    /// StartTestCapture (capture.go:484-553) — synthetic H.264 stream from
    /// videotestsrc (pattern=18, the bouncing ball) + timeoverlay + x264enc High
    /// profile, Annex-B byte-stream. Runs with no display/portal. Built in-process
    /// with the same element graph the Go code passes to gst-launch-1.0.
    fn start_test(cfg: &CaptureConfig) -> Result<CaptureSource> {
        let fps = if cfg.fps == 0 { 30 } else { cfg.fps };
        // captureBitrateKbps over the fixed test dims (capture.go:496).
        let scale = OutputScale {
            enc_w: TEST_CAPTURE_WIDTH,
            enc_h: TEST_CAPTURE_HEIGHT,
            scale_args: None,
        };
        let bitrate = capture_bitrate_kbps(cfg, &scale, fps);
        let key_int = keyframe_interval_frames(fps);

        eprintln!("[CAPTURE] test mode: videotestsrc pattern=18 ! timeoverlay ! x264enc (bitrate={bitrate} kbps)");

        let pipeline = gst::Pipeline::new();

        // videotestsrc pattern=18 (ball) is-live=true do-timestamp=true.
        let src = gst::ElementFactory::make("videotestsrc")
            .property_from_str("pattern", "ball")
            .property("is-live", true)
            .property("do-timestamp", true)
            .build()
            .context("create videotestsrc")?;
        // video/x-raw,width,height,framerate.
        let src_caps = gst::ElementFactory::make("capsfilter")
            .property(
                "caps",
                &gst::Caps::builder("video/x-raw")
                    .field("width", TEST_CAPTURE_WIDTH)
                    .field("height", TEST_CAPTURE_HEIGHT)
                    .field("framerate", gst::Fraction::new(fps as i32, 1))
                    .build(),
            )
            .build()
            .context("create test src capsfilter")?;
        let timeoverlay = make("timeoverlay")?;
        let videoconvert = make("videoconvert")?;
        // x264enc tune=zerolatency speed-preset=superfast bitrate key-int-max
        // threads=1 sliced-threads=true byte-stream=true (capture.go:508-515).
        let enc = gst::ElementFactory::make("x264enc")
            .property_from_str("tune", "zerolatency")
            .property_from_str("speed-preset", "superfast")
            .property("bitrate", bitrate)
            .property("key-int-max", key_int)
            .property("threads", 1u32)
            .property("sliced-threads", true)
            .property("byte-stream", true)
            .build()
            .context("create x264enc (install gst-plugins-ugly / libx264)")?;
        // video/x-h264,profile=high,stream-format=byte-stream (capture.go:516).
        let enc_caps = gst::ElementFactory::make("capsfilter")
            .property(
                "caps",
                &gst::Caps::builder("video/x-h264")
                    .field("profile", "high")
                    .field("stream-format", "byte-stream")
                    .build(),
            )
            .build()
            .context("create test h264 capsfilter")?;

        let appsink = gst_app::AppSink::builder()
            .sync(false)
            .max_buffers(8)
            .drop(false)
            .build();

        let elems: Vec<gst::Element> = vec![
            src,
            src_caps,
            timeoverlay,
            videoconvert,
            enc,
            enc_caps,
            appsink.upcast_ref::<gst::Element>().clone(),
        ];
        for e in elems.iter() {
            pipeline.add(e).context("add test element")?;
        }
        gst::Element::link_many(elems.iter().collect::<Vec<_>>().as_slice())
            .context("link test pipeline")?;

        let (rx, eos) = wire_appsink(&appsink);

        pipeline
            .set_state(gst::State::Playing)
            .context("set test pipeline PLAYING")?;

        Ok(CaptureSource {
            pipeline,
            rx,
            leftover: Vec::new(),
            _portal: None,
            eos,
        })
    }

    fn start_wayland(cfg: &CaptureConfig) -> Result<CaptureSource> {
        let portal =
            request_screencast(cfg.restore_token.as_deref()).context("screencast portal")?;
        // Surface the portal's (possibly new) restore token so the caller can
        // persist it for next time (capture.go:75-79).
        if let Some(token) = portal.restore_token.as_deref() {
            if !token.is_empty() {
                if let Some(cb) = &cfg.on_restore_token {
                    cb(token);
                }
            }
        }
        let (src_w, src_h) = portal.size;
        eprintln!(
            "[capture] portal node={} size={}x{}",
            portal.node_id, src_w, src_h
        );

        // applyOutputScale (capture.go:81): compute the encoded (target) dims
        // and the optional videoscale segment from the portal's native size.
        let scale = OutputScale::compute(cfg, src_w as i32, src_h as i32);

        Self::build_wayland_pipeline(cfg, portal, &scale, false)
    }

    /// Build the Wayland pipeline. `force_software` forces the x264 encoder
    /// (runtime retry path, capture.go:230-237 analogue).
    fn build_wayland_pipeline(
        cfg: &CaptureConfig,
        portal: PortalSession,
        scale: &OutputScale,
        force_software: bool,
    ) -> Result<CaptureSource> {
        let fps = if cfg.fps == 0 { 30 } else { cfg.fps };
        let pipeline = gst::Pipeline::new();

        // pipewiresrc wants the raw fd of the portal's PipeWire remote.
        let fd = portal.fd.as_raw_fd();
        let src = gst::ElementFactory::make("pipewiresrc")
            .property("fd", fd)
            .property("path", portal.node_id.to_string())
            .property("do-timestamp", true)
            .build()
            .context("create pipewiresrc (install gst-plugin-pipewire)")?;

        // Wayland tail (capture.go:103-110):
        //   pipewiresrc ! videoconvert ! videorate drop-only skip-to-first
        //   ! caps(framerate) ! queue(leaky) [! outputScale] [! vulkanupload]
        //   ! encoder ! ...
        let videoconvert = make("videoconvert")?;
        let videorate = gst::ElementFactory::make("videorate")
            .property("drop-only", true)
            .property("skip-to-first", true)
            .build()
            .context("create videorate")?;
        let rate_caps = framerate_caps(fps)?;
        let queue = leaky_queue()?;

        let mut elems: Vec<gst::Element> = vec![
            src.clone(),
            videoconvert.clone(),
            videorate.clone(),
            rate_caps.clone(),
            queue.clone(),
        ];

        let (enc, eos, rx) = Self::finish_pipeline(
            cfg, &pipeline, &mut elems, scale, fps, force_software,
        )?;
        let _ = enc;

        pipeline
            .set_state(gst::State::Playing)
            .context("set pipeline PLAYING")?;

        Ok(CaptureSource {
            pipeline,
            rx,
            leftover: Vec::new(),
            _portal: Some(portal),
            eos,
        })
    }

    fn start_x11(cfg: &CaptureConfig) -> Result<CaptureSource> {
        let display = std::env::var("DISPLAY").unwrap_or_default();

        // Detect primary monitor geometry — ximagesrc captures the full X screen
        // (all monitors). Crop to the primary monitor and use its native size for
        // auto-bitrate / fit (capture.go:179-199).
        let (start_x, start_y, end_x, end_y) = detect_primary_monitor(&display);
        let (src_w, src_h) = if end_x > start_x && end_y > start_y {
            (end_x - start_x, end_y - start_y)
        } else {
            (0, 0)
        };

        let scale = OutputScale::compute(cfg, src_w, src_h);

        Self::build_x11_pipeline(cfg, &display, start_x, start_y, end_x, end_y, &scale, false)
    }

    #[allow(clippy::too_many_arguments)]
    fn build_x11_pipeline(
        cfg: &CaptureConfig,
        display: &str,
        start_x: i32,
        start_y: i32,
        end_x: i32,
        end_y: i32,
        scale: &OutputScale,
        force_software: bool,
    ) -> Result<CaptureSource> {
        let fps = if cfg.fps == 0 { 30 } else { cfg.fps };
        let pipeline = gst::Pipeline::new();

        // ximagesrc display-name=<display> use-damage=false [crop to monitor].
        let mut src_b = gst::ElementFactory::make("ximagesrc")
            .property("display-name", display)
            .property("use-damage", false);
        if end_x > start_x && end_y > start_y {
            src_b = src_b
                .property("startx", start_x as u32)
                .property("starty", start_y as u32)
                .property("endx", (end_x - 1) as u32)
                .property("endy", (end_y - 1) as u32);
            eprintln!(
                "[capture] cropping ximagesrc to x={}..{} y={}..{}",
                start_x,
                end_x - 1,
                start_y,
                end_y - 1
            );
        }
        let src = src_b
            .build()
            .context("create ximagesrc (install gst-plugins-good)")?;

        // X11 tail (capture.go:202-207):
        //   ximagesrc ! caps(framerate) ! queue(leaky) ! videoconvert
        //   [! outputScale] [! vulkanupload] ! encoder ! ...
        // NOTE: no videorate on X11 (unlike Wayland).
        let rate_caps = framerate_caps(fps)?;
        let queue = leaky_queue()?;
        let videoconvert = make("videoconvert")?;

        let mut elems: Vec<gst::Element> = vec![
            src.clone(),
            rate_caps.clone(),
            queue.clone(),
            videoconvert.clone(),
        ];

        let (enc, eos, rx) = Self::finish_pipeline(
            cfg, &pipeline, &mut elems, scale, fps, force_software,
        )?;

        // Runtime start-failure retry (capture.go:230-237): if a Vulkan encoder
        // pipeline fails to reach PLAYING, fall back to software (x264).
        let needs_vulkan = enc.factory().map(|f| f.name() == "vulkanh264enc").unwrap_or(false);
        let started = pipeline.set_state(gst::State::Playing);
        match started {
            Ok(_) => Ok(CaptureSource {
                pipeline,
                rx,
                leftover: Vec::new(),
                _portal: None,
                eos,
            }),
            Err(e) => {
                let _ = pipeline.set_state(gst::State::Null);
                if needs_vulkan && !force_software {
                    eprintln!("[capture] vulkanh264enc pipeline failed, falling back to x264enc");
                    Self::build_x11_pipeline(
                        cfg, display, start_x, start_y, end_x, end_y, scale, true,
                    )
                } else {
                    Err(e).context("set pipeline PLAYING")
                }
            }
        }
    }

    /// Append the optional output-scale stage, the (optional vulkanupload +)
    /// encoder, h264parse, the byte-stream caps, and an appsink; add+link the
    /// whole element list; wire the appsink pump. Returns the chosen encoder,
    /// the EOS flag, and the byte-stream receiver. Does NOT start the pipeline
    /// (the caller decides, so the X11 retry can observe a failed start).
    fn finish_pipeline(
        cfg: &CaptureConfig,
        pipeline: &gst::Pipeline,
        elems: &mut Vec<gst::Element>,
        scale: &OutputScale,
        fps: u32,
        force_software: bool,
    ) -> Result<(gst::Element, Arc<Mutex<bool>>, Receiver<Vec<u8>>)> {
        // Optional output-scale stage (videoscale [+ videobox]) — applies the
        // OUTPUT_HEIGHT rescale and/or the fit/underscan border.
        elems.extend(build_output_scale_stage(scale)?);

        let (encoder, needs_vulkan) = build_encoder(cfg, scale, fps, force_software)?;
        if needs_vulkan {
            elems.push(make("vulkanupload")?);
        }
        elems.push(encoder.clone());

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

        elems.push(h264parse);
        elems.push(parse_caps);
        elems.push(appsink.upcast_ref::<gst::Element>().clone());

        for e in elems.iter() {
            pipeline.add(e).context("add element to pipeline")?;
        }
        gst::Element::link_many(elems.iter().collect::<Vec<_>>().as_slice())
            .context("link pipeline")?;

        let (rx, eos) = wire_appsink(&appsink);

        Ok((encoder, eos, rx))
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

/// Attach the new-sample/EOS callbacks to an appsink, pushing each encoded
/// buffer through an mpsc channel. Returns the receiver and the shared EOS flag.
fn wire_appsink(appsink: &gst_app::AppSink) -> (Receiver<Vec<u8>>, Arc<Mutex<bool>>) {
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
            .eos(move |_sink| {
                *eos_cb.lock().unwrap() = true;
            })
            .build(),
    );
    (rx, eos)
}

/// `! video/x-raw,framerate=<fps>/1`.
fn framerate_caps(fps: u32) -> Result<gst::Element> {
    gst::ElementFactory::make("capsfilter")
        .property(
            "caps",
            &gst::Caps::builder("video/x-raw")
                .field("framerate", gst::Fraction::new(fps as i32, 1))
                .build(),
        )
        .build()
        .context("create framerate capsfilter")
}

/// `! queue max-size-buffers=1 max-size-bytes=0 max-size-time=0 leaky=downstream`.
fn leaky_queue() -> Result<gst::Element> {
    gst::ElementFactory::make("queue")
        .property("max-size-buffers", 1u32)
        .property("max-size-bytes", 0u32)
        .property("max-size-time", 0u64)
        .property_from_str("leaky", "downstream")
        .build()
        .context("create queue")
}

/// OutputScale — the result of applyOutputScale (capture.go:587-641).
/// `enc_w`/`enc_h` are the ENCODED (target) dimensions used to size the bitrate
/// and SPS; `scale_args` describes the videoscale (+ videobox) stage, or None
/// for native passthrough.
struct OutputScale {
    enc_w: i32,
    enc_h: i32,
    scale_args: Option<ScaleArgs>,
}

/// Concrete params for the videoscale/videobox stage.
enum ScaleArgs {
    /// `videoscale ! caps(w,h)` — plain rescale, no border.
    Plain { w: i32, h: i32 },
    /// `videoscale ! caps(cw,ch) ! videobox(borders) ! caps(tw,th)` — fit/underscan.
    Fit {
        cw: i32,
        ch: i32,
        tw: i32,
        th: i32,
        bx: i32,
        by: i32,
    },
}

impl OutputScale {
    /// applyOutputScale (capture.go:587). `src_w`/`src_h` are the native source
    /// dimensions (0 → unknown). Computes the encoded size (native, or scaled to
    /// $OUTPUT_HEIGHT) and the videoscale/videobox segment, with the fit border
    /// applied to the POST-scale dims.
    fn compute(cfg: &CaptureConfig, src_w: i32, src_h: i32) -> OutputScale {
        if src_w <= 0 || src_h <= 0 {
            return OutputScale {
                enc_w: src_w,
                enc_h: src_h,
                scale_args: None,
            };
        }

        // Encoded frame size: native, or scaled to $OUTPUT_HEIGHT.
        let mut tw = src_w;
        let mut th = src_h;
        let oh = output_height_env();
        if oh > 0 {
            th = oh;
            tw = src_w * oh / src_h;
        }
        tw -= tw % 2;
        th -= th % 2;
        if tw <= 0 || th <= 0 {
            return OutputScale {
                enc_w: src_w,
                enc_h: src_h,
                scale_args: None,
            };
        }

        let enc_w = tw;
        let enc_h = th;

        let mut fit = fit_pct_env(cfg);
        let scaled = tw != src_w || th != src_h;

        if fit <= 0 && !scaled {
            // native passthrough — nothing to do.
            return OutputScale {
                enc_w,
                enc_h,
                scale_args: None,
            };
        }
        if fit <= 0 {
            return OutputScale {
                enc_w,
                enc_h,
                scale_args: Some(ScaleArgs::Plain { w: tw, h: th }),
            };
        }
        if fit > 25 {
            fit = 25;
        }
        let mut cw = tw * (100 - fit) / 100;
        let mut ch = th * (100 - fit) / 100;
        cw -= cw % 2;
        ch -= ch % 2;
        let bx = (tw - cw) / 2;
        let by = (th - ch) / 2;
        eprintln!(
            "[capture] fit {fit}%: desktop {cw}x{ch} centered in {tw}x{th} frame (border {bx}/{by})"
        );
        OutputScale {
            enc_w,
            enc_h,
            scale_args: Some(ScaleArgs::Fit {
                cw,
                ch,
                tw,
                th,
                bx,
                by,
            }),
        }
    }
}

fn raw_caps(w: i32, h: i32) -> Result<gst::Element> {
    gst::ElementFactory::make("capsfilter")
        .property(
            "caps",
            &gst::Caps::builder("video/x-raw")
                .field("width", w)
                .field("height", h)
                .build(),
        )
        .build()
        .context("create video/x-raw capsfilter")
}

/// build_output_scale_stage — turn an OutputScale into the videoscale (+ videobox)
/// element chain, the in-process analogue of outputScaleArgs.
fn build_output_scale_stage(scale: &OutputScale) -> Result<Vec<gst::Element>> {
    match &scale.scale_args {
        None => Ok(Vec::new()),
        Some(ScaleArgs::Plain { w, h }) => {
            Ok(vec![make("videoscale")?, raw_caps(*w, *h)?])
        }
        Some(ScaleArgs::Fit {
            cw,
            ch,
            tw,
            th,
            bx,
            by,
        }) => {
            let videoscale = make("videoscale")?;
            let scale_caps = raw_caps(*cw, *ch)?;
            // videobox with negative borders pads (adds) pixels; matches
            // capture.go's left/right/top/bottom = -bx/-by with fill=black.
            let videobox = gst::ElementFactory::make("videobox")
                .property_from_str("fill", "black")
                .property("autocrop", false)
                .property("left", -*bx)
                .property("right", -*bx)
                .property("top", -*by)
                .property("bottom", -*by)
                .build()
                .context("create videobox")?;
            let box_caps = raw_caps(*tw, *th)?;
            Ok(vec![videoscale, scale_caps, videobox, box_caps])
        }
    }
}

/// captureBitrateKbps — capture.go:643. Sized from the ENCODED dims (post-scale).
fn capture_bitrate_kbps(cfg: &CaptureConfig, scale: &OutputScale, fps: u32) -> u32 {
    if cfg.bitrate_kbps > 0 {
        return cfg.bitrate_kbps;
    }
    let (w, h) = if scale.enc_w > 0 && scale.enc_h > 0 {
        (scale.enc_w as u32, scale.enc_h as u32)
    } else {
        (1920, 1080)
    };
    let b = recommended_bitrate_kbps(w, h, fps);
    eprintln!("[capture] auto bitrate selected: {b} kbps for {w}x{h}@{fps}fps");
    b
}

/// build_encoder — detectGstEncoder (capture.go:400-482). Probes encoders in
/// priority order, gated by the HWAccel mode: vulkanh264enc (NVENC via Vulkan)
/// -> nvh264enc (legacy NVENC) -> vah264enc (VA-API) -> x264enc. Returns the
/// encoder and whether it needs a `vulkanupload` stage before it.
///
/// `force_software` (runtime retry) collapses the mode to "none".
fn build_encoder(
    cfg: &CaptureConfig,
    scale: &OutputScale,
    fps: u32,
    force_software: bool,
) -> Result<(gst::Element, bool)> {
    let bitrate = capture_bitrate_kbps(cfg, scale, fps);
    let key_int = keyframe_interval_frames(fps);
    let hwaccel = if force_software {
        "none".to_string()
    } else {
        hwaccel_mode(cfg)
    };

    // Try Vulkan H.264 (NVENC via Vulkan API).
    if hwaccel == "auto" || hwaccel == "nvenc" {
        if let Ok(enc) = gst::ElementFactory::make("vulkanh264enc")
            .property("b-frames", 0u32)
            .property("idr-period", key_int)
            .property_from_str("rate-control", "cbr")
            .property("bitrate", bitrate)
            .build()
        {
            eprintln!("[CAPTURE] using NVENC hardware encoding (vulkanh264enc)");
            return Ok((enc, true));
        }
    }

    // Try legacy NVENC.
    if hwaccel == "auto" || hwaccel == "nvenc" {
        if let Ok(enc) = gst::ElementFactory::make("nvh264enc")
            .property("bitrate", bitrate)
            .property("gop-size", key_int as i32)
            .property("bframes", 0u32)
            .property_from_str("rc-mode", "cbr")
            .property_from_str("preset", "low-latency-hq")
            .property("zerolatency", true)
            .build()
        {
            eprintln!("[CAPTURE] using NVENC hardware encoding (nvh264enc)");
            return Ok((enc, false));
        }
        if hwaccel == "nvenc" {
            eprintln!("[CAPTURE] nvh264enc not available, falling back to software");
        }
    }

    // Try VAAPI (vah264enc).
    if hwaccel == "auto" || hwaccel == "vaapi" {
        if let Ok(enc) = gst::ElementFactory::make("vah264enc")
            .property("bitrate", bitrate)
            .property("key-int-max", key_int)
            .property("b-frames", 0u32)
            .property_from_str("rate-control", "cbr")
            .build()
        {
            eprintln!("[CAPTURE] using VAAPI hardware encoding (vah264enc)");
            return Ok((enc, false));
        }
        if hwaccel == "vaapi" {
            eprintln!("[CAPTURE] vah264enc not available, falling back to software");
        }
    }

    // Software fallback: x264enc, low-latency, no B-frames, Annex-B + AUDs.
    let vbv = vbv_buffer_kbit(bitrate, fps);
    let maxrate = bitrate + bitrate / 4; // allow 25% overshoot on peaks
    let enc = gst::ElementFactory::make("x264enc")
        .property_from_str("tune", "zerolatency")
        .property_from_str("speed-preset", "superfast")
        .property("bitrate", bitrate)
        .property("vbv-buf-capacity", vbv)
        .property("key-int-max", key_int)
        // pass=0 (VBR). The gst enum value "qual" / "pass1"... — Go uses pass=0,
        // which is the "cbr"/constant-quality default enum; the audit confirms
        // pass=0 and pass=cbr resolve to the same enum value.
        .property_from_str("pass", "cbr")
        .property("option-string", format!("vbv-maxrate={maxrate}"))
        .property("b-frames", 0u32)
        .property("sliced-threads", true)
        .property("byte-stream", true)
        .property("aud", true)
        .build()
        .context("create x264enc (install gst-plugins-ugly / libx264)")?;
    eprintln!("[CAPTURE] using software encoding (x264enc) bitrate={bitrate} kbps");
    Ok((enc, false))
}

/// detect_primary_monitor — detectPrimaryMonitor (capture.go:305). Queries
/// xrandr for the primary monitor geometry. Returns (start_x, start_y, end_x,
/// end_y); all zeros if detection fails (no cropping).
fn detect_primary_monitor(display: &str) -> (i32, i32, i32, i32) {
    let out = std::process::Command::new("xrandr")
        .arg("--display")
        .arg(display)
        .arg("--query")
        .output();
    let out = match out {
        Ok(o) if o.status.success() => o.stdout,
        _ => {
            eprintln!("[capture] xrandr failed, skipping monitor crop");
            return (0, 0, 0, 0);
        }
    };
    let text = String::from_utf8_lossy(&out);

    let mut geom: Option<(i32, i32, i32, i32)> = None; // (x,y,w,h)
    // Try primary first.
    for line in text.lines() {
        if !line.contains(" connected") {
            continue;
        }
        if line.contains(" primary ") {
            if let Some(g) = parse_xrandr_geometry(line) {
                geom = Some(g);
                break;
            }
        }
    }
    // Else first connected output.
    if geom.is_none() {
        for line in text.lines() {
            if !line.contains(" connected") {
                continue;
            }
            if let Some(g) = parse_xrandr_geometry(line) {
                geom = Some(g);
                break;
            }
        }
    }

    match geom {
        Some((x, y, w, h)) if w > 0 && h > 0 => {
            eprintln!("[capture] primary monitor: {w}x{h} at +{x}+{y}");
            (x, y, x + w, y + h)
        }
        _ => {
            eprintln!("[capture] couldn't parse xrandr output, skipping monitor crop");
            (0, 0, 0, 0)
        }
    }
}

/// parse_xrandr_geometry — parseXrandrGeometry (capture.go:356). Extracts
/// (x, y, w, h) from a `WxH+X+Y` field in an xrandr output line.
fn parse_xrandr_geometry(line: &str) -> Option<(i32, i32, i32, i32)> {
    for field in line.split_whitespace() {
        // e.g. "1920x1080+0+0" or "3840x2160+1920+0".
        let (w_str, rest) = match field.split_once('x') {
            Some(parts) => parts,
            None => continue,
        };
        let w: i32 = match w_str.parse() {
            Ok(w) if w >= 640 => w,
            _ => continue,
        };
        // rest e.g. "1080+0+0".
        let plus: Vec<&str> = rest.splitn(3, '+').collect();
        if plus.len() != 3 {
            continue;
        }
        let h: i32 = match plus[0].parse() {
            Ok(h) => h,
            Err(_) => continue,
        };
        let x: i32 = match plus[1].parse() {
            Ok(x) => x,
            Err(_) => continue,
        };
        let y: i32 = match plus[2].parse() {
            Ok(y) => y,
            Err(_) => continue,
        };
        return Some((x, y, w, h));
    }
    None
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

/// A live screencast portal session: holds the PipeWire remote fd and node id,
/// plus the restore token the portal returned (for persistence across runs).
pub struct PortalSession {
    pub node_id: u32,
    pub size: (u32, u32),
    pub fd: OwnedFd,
    /// The new restore token granted by the portal (capture.go newRestoreToken),
    /// or None if the portal did not provide one. Present only when persistence
    /// is granted.
    pub restore_token: Option<String>,
}

/// requestScreencast (capture.go:741) — drive the XDG ScreenCast portal. `in_token`
/// is the restore token from a previous run (capture.go's restoreToken arg): when
/// present, ashpd asks the portal to restore the prior grant (no re-prompt). The
/// portal's NEW restore token is captured and returned for the caller to persist.
///
/// Unlike the Go reference (which forces persist_mode 0 so GNOME always prompts),
/// we honor the in-token and request `PersistMode::ExplicitlyRevoked` (persist
/// until revoked) so a remembered grant is reused — the desired daemon/tray
/// behavior. When no in-token is
/// supplied this still requests persistence so the FIRST run produces a token to
/// save.
fn request_screencast(in_token: Option<&str>) -> Result<PortalSession> {
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

        // MONITOR source, embedded cursor, single source. Request explicit
        // persistence and replay any prior token so the grant is remembered
        // across runs (capture.go restore-token flow).
        let restore = in_token.filter(|t| !t.is_empty());
        proxy
            .select_sources(
                &session,
                CursorMode::Embedded,
                SourceType::Monitor.into(),
                false,
                restore,
                PersistMode::ExplicitlyRevoked,
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

        let restore_token = response.restore_token().map(|s| s.to_string());

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

        Ok(PortalSession {
            node_id,
            size,
            fd,
            restore_token,
        })
    })
}
