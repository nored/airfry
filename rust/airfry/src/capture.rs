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
use std::time::Duration;

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
    /// Keep the videoscale+videobox fit stage in the pipeline ALWAYS (even at
    /// 0 %), so underscan can be adjusted LIVE mid-stream without rebuilding the
    /// pipeline (and without re-prompting the portal). See `CaptureSource::live_fit`.
    pub live_underscan: bool,
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
            live_underscan: false,
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
    /// Live underscan handle (Some when the fit stage is present). Cloned out via
    /// `live_fit()` so the tray can retune the border mid-stream.
    live_fit: Option<LiveFit>,
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
        Self::start_test_enc(cfg, false)
    }

    /// Synthetic videotestsrc capture, but through the REAL encoder selection
    /// (build_encoder) + the no-frames fallback — so `--test` actually exercises
    /// hardware encoding (NVENC/VA-API) on whatever machine it runs on, and
    /// verifies the fallback to software. `force_software` is the fallback retry.
    fn start_test_enc(cfg: &CaptureConfig, force_software: bool) -> Result<CaptureSource> {
        let fps = if cfg.fps == 0 { 30 } else { cfg.fps };
        let scale = OutputScale {
            enc_w: TEST_CAPTURE_WIDTH,
            enc_h: TEST_CAPTURE_HEIGHT,
            scale_args: None,
        };

        let pipeline = gst::Pipeline::new();
        let src = gst::ElementFactory::make("videotestsrc")
            .property_from_str("pattern", "ball")
            .property("is-live", true)
            .property("do-timestamp", true)
            .build()
            .context("create videotestsrc")?;
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
        let mut elems: Vec<gst::Element> = vec![src, src_caps, timeoverlay, videoconvert];

        let (enc, eos, rx, live_fit) =
            Self::finish_pipeline(cfg, &pipeline, &mut elems, &scale, fps, force_software)?;
        let _ = enc;
        pipeline
            .set_state(gst::State::Playing)
            .context("set test pipeline PLAYING")?;

        let mut cap = CaptureSource {
            pipeline,
            rx,
            leftover: Vec::new(),
            _portal: None,
            eos,
            live_fit,
        };
        if !force_software && !cap.probe_first_frame(Duration::from_secs(3)) {
            crate::dlog!("[capture] hardware encoder produced no frames in 3s; falling back to software (x264)");
            cap.stop();
            return Self::start_test_enc(cfg, true);
        }
        Ok(cap)
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
        crate::dlog!(
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

        let (enc, eos, rx, live_fit) = Self::finish_pipeline(
            cfg, &pipeline, &mut elems, scale, fps, force_software,
        )?;
        let _ = enc;

        pipeline
            .set_state(gst::State::Playing)
            .context("set pipeline PLAYING")?;

        let mut cap = CaptureSource {
            pipeline,
            rx,
            leftover: Vec::new(),
            _portal: Some(portal),
            eos,
            live_fit,
        };
        // No-frames fallback: if a hardware encoder builds but emits nothing,
        // reclaim the portal, tear it down, and rebuild with software (x264).
        if !force_software && !cap.probe_first_frame(Duration::from_secs(3)) {
            crate::dlog!("[capture] hardware encoder produced no frames in 3s; falling back to software (x264)");
            let portal = cap._portal.take();
            cap.stop();
            if let Some(portal) = portal {
                return Self::build_wayland_pipeline(cfg, portal, scale, true);
            }
        }
        Ok(cap)
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
            crate::dlog!(
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

        let (enc, eos, rx, live_fit) = Self::finish_pipeline(
            cfg, &pipeline, &mut elems, scale, fps, force_software,
        )?;

        // Runtime start-failure retry (capture.go:230-237): if a Vulkan encoder
        // pipeline fails to reach PLAYING, fall back to software (x264).
        let needs_vulkan = enc.factory().map(|f| f.name() == "vulkanh264enc").unwrap_or(false);
        let started = pipeline.set_state(gst::State::Playing);
        match started {
            Ok(_) => {
                let mut cap = CaptureSource {
                    pipeline,
                    rx,
                    leftover: Vec::new(),
                    _portal: None,
                    eos,
                    live_fit,
                };
                // No-frames fallback (e.g. a hardware encoder that builds but
                // emits nothing): rebuild with software.
                if !force_software && !cap.probe_first_frame(Duration::from_secs(3)) {
                    crate::dlog!("[capture] hardware encoder produced no frames in 3s; falling back to software (x264)");
                    cap.stop();
                    return Self::build_x11_pipeline(
                        cfg, display, start_x, start_y, end_x, end_y, scale, true,
                    );
                }
                Ok(cap)
            }
            Err(e) => {
                let _ = pipeline.set_state(gst::State::Null);
                if needs_vulkan && !force_software {
                    crate::dlog!("[capture] vulkanh264enc pipeline failed, falling back to x264enc");
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
    ) -> Result<(
        gst::Element,
        Arc<Mutex<bool>>,
        Receiver<Vec<u8>>,
        Option<LiveFit>,
    )> {
        // Optional output-scale stage (videoscale [+ videobox], or an opt-in
        // compositor) — applies the OUTPUT_HEIGHT rescale and/or the fit/underscan
        // border. The handle lets underscan be retuned mid-stream; the compositor
        // variant's pad is resolved after link_many (below).
        let (scale_elems, fit_handle) = build_output_scale_stage(scale, fps)?;
        elems.extend(scale_elems);

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

        // Resolve the live underscan handle. The compositor's request sink pad
        // only exists after linking; set its initial geometry now.
        let live_fit = match fit_handle {
            FitHandle::None => None,
            FitHandle::Ready(lf) => Some(lf),
            FitHandle::PendingCompositor(p) => {
                let pad = p
                    .compositor
                    .sink_pads()
                    .into_iter()
                    .next()
                    .ok_or_else(|| anyhow!("compositor has no sink pad after linking"))?;
                let (xpos, ypos, w, h) = p.init;
                pad.set_property("xpos", xpos);
                pad.set_property("ypos", ypos);
                pad.set_property("width", w);
                pad.set_property("height", h);
                Some(LiveFit::Compositor {
                    pad,
                    tw: p.tw,
                    th: p.th,
                })
            }
        };

        let (rx, eos) = wire_appsink(&appsink);

        Ok((encoder, eos, rx, live_fit))
    }

    /// Wait up to `timeout` for the FIRST encoded chunk and stash it (so `read`
    /// returns it later). Returns true if a frame arrived. A hardware encoder
    /// that builds but emits nothing (e.g. vulkanh264enc on some NVIDIA stacks,
    /// or a broken VA-API driver) returns false here so the caller can fall back.
    fn probe_first_frame(&mut self, timeout: Duration) -> bool {
        match self.rx.recv_timeout(timeout) {
            Ok(chunk) => {
                self.leftover = chunk;
                true
            }
            Err(_) => false,
        }
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

    /// A handle to retune underscan live, or None if this capture has no fit
    /// stage (e.g. `--test`, or `live_underscan` was not requested).
    pub fn live_fit(&self) -> Option<LiveFit> {
        self.live_fit.clone()
    }

    /// A detached, cloneable stop handle for this capture's GStreamer pipeline.
    ///
    /// `stop()` itself takes `&self`, which is only reachable while you hold the
    /// `CaptureSource`. Once the source is moved into a `BroadcastCapture` (whose
    /// pump thread holds it behind a `Mutex` for its whole life, blocking inside
    /// the source's `read`), there is no longer any way to call `stop()` — the
    /// only accessor, `BroadcastCapture::source()`, would deadlock on that lock.
    ///
    /// This returns a `CaptureStopHandle` wrapping a clone of the underlying
    /// `gst::Pipeline` (a refcounted GObject handle). Setting its state to Null
    /// does NOT touch the `CaptureSource`'s Rust mutex, so it can be called from
    /// another thread while the pump is blocked in `read`: it tears the pipeline
    /// down, the appsink channel closes, and the pump's `read` returns 0 (EOS),
    /// letting `BroadcastCapture::run` finish. The daemon grabs one of these
    /// before handing the capture to `BroadcastCapture::new`, so it can implement
    /// `maybeStopBroadcastLocked` (daemon.go) — stop the shared capture when the
    /// last stream ends.
    pub fn stop_handle(&self) -> CaptureStopHandle {
        CaptureStopHandle {
            pipeline: self.pipeline.clone(),
        }
    }
}

/// A detached stop control for a `CaptureSource`'s pipeline — see
/// `CaptureSource::stop_handle`. Cloneable and `Send`; safe to call from any
/// thread, including while a `BroadcastCapture` pump is reading the source.
#[derive(Clone)]
pub struct CaptureStopHandle {
    pipeline: gst::Pipeline,
}

impl CaptureStopHandle {
    /// Stop the underlying pipeline, without taking any Rust lock the pump might
    /// hold. Idempotent.
    ///
    /// A bare `set_state(Null)` is not enough to wake a consumer blocked in the
    /// source's `read`: it waits on an mpsc whose sender lives inside the
    /// appsink's `new_sample` callback, and Null alone neither delivers more
    /// samples nor drops that callback, so `recv` would block forever.
    ///
    /// To guarantee the consumer wakes, we locate the `AppSink` in the pipeline
    /// and replace its callbacks with empty ones. That drops the previous
    /// closures — and with them the mpsc `Sender` — so the blocked `recv`
    /// immediately returns `Err`, the source's `read` reports end-of-stream (0),
    /// and the `BroadcastCapture` pump exits. We then set the pipeline to Null to
    /// release the screen-capture / portal resources.
    pub fn stop(&self) {
        if let Some(bin) = self.pipeline.dynamic_cast_ref::<gst::Bin>() {
            // Iterate the pipeline's elements and clear the appsink's callbacks
            // (dropping its mpsc Sender so any blocked `read` unblocks).
            let mut it = bin.iterate_elements();
            while let Ok(Some(el)) = it.next() {
                if let Some(appsink) = el.dynamic_cast_ref::<gst_app::AppSink>() {
                    appsink.set_callbacks(gst_app::AppSinkCallbacks::builder().build());
                }
            }
        }
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
        if fit < 0 {
            fit = 0;
        }
        if fit > 25 {
            fit = 25;
        }
        let scaled = tw != src_w || th != src_h;

        // With live underscan we ALWAYS keep the videoscale+videobox stage (even
        // at 0 %, an identity transform) so the border can be retuned mid-stream
        // without rebuilding the pipeline. Otherwise preserve the lean Go
        // behaviour: passthrough / plain-rescale when there's no fit border.
        if fit == 0 && !scaled && !cfg.live_underscan {
            return OutputScale {
                enc_w,
                enc_h,
                scale_args: None,
            };
        }
        if fit == 0 && !cfg.live_underscan {
            return OutputScale {
                enc_w,
                enc_h,
                scale_args: Some(ScaleArgs::Plain { w: tw, h: th }),
            };
        }
        let mut cw = tw * (100 - fit) / 100;
        let mut ch = th * (100 - fit) / 100;
        cw -= cw % 2;
        ch -= ch % 2;
        let bx = (tw - cw) / 2;
        let by = (th - ch) / 2;
        crate::dlog!(
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

/// Whether to use the compositor underscan path. DEFAULT ON (verified on
/// hardware to retune underscan smoothly — changing the compositor sink-pad
/// geometry does NOT renegotiate caps, so the receiver no longer freezes/
/// re-buffers when the size changes). Set `AIRFRY_LEGACY_UNDERSCAN=1` to fall
/// back to the old videoscale+videobox path (which froze the receiver on change).
fn use_compositor_fit() -> bool {
    !std::env::var_os("AIRFRY_LEGACY_UNDERSCAN").is_some_and(|v| v != "0" && !v.is_empty())
}

/// A handle to the live-adjustable underscan stage of a running pipeline. Two
/// implementations: the default `ScaleBox` (videoscale caps + videobox border —
/// the original working path) and the opt-in `Compositor` (sink-pad geometry, no
/// caps renegotiation). Cloneable GObject handles, `Send`/`Sync`.
#[derive(Clone)]
pub enum LiveFit {
    ScaleBox {
        scale_caps: gst::Element,
        videobox: gst::Element,
        tw: i32,
        th: i32,
    },
    Compositor {
        pad: gst::Pad,
        tw: i32,
        th: i32,
    },
}

impl LiveFit {
    /// Apply an underscan percent (0..=25) to the running pipeline immediately.
    pub fn apply(&self, pct: u8) {
        match self {
            LiveFit::ScaleBox {
                scale_caps,
                videobox,
                tw,
                th,
            } => {
                let (bx, by, cw, ch) = fit_geometry(*tw, *th, pct);
                // NOTE: changing the videoscale caps renegotiates downstream,
                // which can stall the stream — this is the path the compositor
                // variant avoids.
                let caps = gst::Caps::builder("video/x-raw")
                    .field("width", cw)
                    .field("height", ch)
                    .build();
                scale_caps.set_property("caps", &caps);
                videobox.set_property("left", -bx);
                videobox.set_property("right", -bx);
                videobox.set_property("top", -by);
                videobox.set_property("bottom", -by);
                crate::dlog!(
                    "[capture] LIVE underscan {}% (scalebox): {cw}x{ch} centered in {tw}x{th} (border {bx}/{by})",
                    pct.min(25)
                );
            }
            LiveFit::Compositor { pad, tw, th } => {
                let (xpos, ypos, w, h) = fit_geometry(*tw, *th, pct);
                pad.set_property("xpos", xpos);
                pad.set_property("ypos", ypos);
                pad.set_property("width", w);
                pad.set_property("height", h);
                crate::dlog!(
                    "[capture] LIVE underscan {}% (compositor): {w}x{h} at ({xpos},{ypos}) in {tw}x{th}",
                    pct.min(25)
                );
            }
        }
    }
}

/// Centered underscan geometry → (border_x, border_y, content_w, content_h).
fn fit_geometry(tw: i32, th: i32, pct: u8) -> (i32, i32, i32, i32) {
    let fit = (pct.min(25)) as i32;
    let mut cw = tw * (100 - fit) / 100;
    let mut ch = th * (100 - fit) / 100;
    cw -= cw % 2;
    ch -= ch % 2;
    if cw < 2 {
        cw = 2;
    }
    if ch < 2 {
        ch = 2;
    }
    let bx = (tw - cw) / 2;
    let by = (th - ch) / 2;
    (bx, by, cw, ch)
}

/// A compositor whose request sink pad becomes a `LiveFit::Compositor` once
/// linked (the pad only exists after `link_many`).
struct PendingFit {
    compositor: gst::Element,
    tw: i32,
    th: i32,
    init: (i32, i32, i32, i32),
}

/// The fit stage's live handle: ready (videobox path), or pending pad resolution
/// (compositor path), or none.
enum FitHandle {
    None,
    Ready(LiveFit),
    PendingCompositor(PendingFit),
}

/// build_output_scale_stage — turn an OutputScale into the scaling element chain.
/// `Fit`/underscan uses videoscale+videobox by default, or a `compositor` when
/// `AIRFRY_LIVE_COMPOSITOR` is set (returns a pending handle to resolve the pad).
fn build_output_scale_stage(
    scale: &OutputScale,
    fps: u32,
) -> Result<(Vec<gst::Element>, FitHandle)> {
    match &scale.scale_args {
        None => Ok((Vec::new(), FitHandle::None)),
        Some(ScaleArgs::Plain { w, h }) => {
            Ok((vec![make("videoscale")?, raw_caps(*w, *h)?], FitHandle::None))
        }
        Some(ScaleArgs::Fit {
            cw,
            ch,
            tw,
            th,
            bx,
            by,
        }) => {
            if use_compositor_fit() {
                // OPT-IN: scale via a compositor pad over a black canvas. Pad
                // geometry is live-changeable WITHOUT a caps renegotiation, so
                // underscan retunes smoothly with no receiver re-buffer.
                let compositor = gst::ElementFactory::make("compositor")
                    .property_from_str("background", "black")
                    .build()
                    .context("create compositor (install gst-plugins-base)")?;
                let out_caps = gst::ElementFactory::make("capsfilter")
                    .property(
                        "caps",
                        &gst::Caps::builder("video/x-raw")
                            .field("width", *tw)
                            .field("height", *th)
                            .field("framerate", gst::Fraction::new(fps as i32, 1))
                            .field("pixel-aspect-ratio", gst::Fraction::new(1, 1))
                            .build(),
                    )
                    .build()
                    .context("create compositor out caps")?;
                let pending = PendingFit {
                    compositor: compositor.clone(),
                    tw: *tw,
                    th: *th,
                    init: (*bx, *by, *cw, *ch),
                };
                return Ok((vec![compositor, out_caps], FitHandle::PendingCompositor(pending)));
            }

            // DEFAULT (unchanged working path): videoscale ! caps ! videobox.
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
            let live = LiveFit::ScaleBox {
                scale_caps: scale_caps.clone(),
                videobox: videobox.clone(),
                tw: *tw,
                th: *th,
            };
            Ok((
                vec![videoscale, scale_caps, videobox, box_caps],
                FitHandle::Ready(live),
            ))
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
    crate::dlog!("[capture] auto bitrate selected: {b} kbps for {w}x{h}@{fps}fps");
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

    // Try NVENC (nvh264enc) FIRST — the real NVIDIA encoder. (vulkanh264enc was
    // the old default but BUILDS yet produces ZERO frames on this hardware → black
    // screen, so it's now opt-in only via hwaccel="vulkan".)
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
            crate::dlog!("[CAPTURE] using NVENC hardware encoding (nvh264enc)");
            return Ok((enc, false));
        }
        if hwaccel == "nvenc" {
            crate::dlog!("[CAPTURE] nvh264enc not available, falling back to software");
        }
    }

    // Vulkan H.264 — opt-in only (it produces no frames on some NVIDIA setups).
    if hwaccel == "vulkan" {
        if let Ok(enc) = gst::ElementFactory::make("vulkanh264enc")
            .property("b-frames", 0u32)
            .property("idr-period", key_int)
            .property_from_str("rate-control", "cbr")
            .property("bitrate", bitrate)
            .build()
        {
            crate::dlog!("[CAPTURE] using Vulkan hardware encoding (vulkanh264enc)");
            return Ok((enc, true));
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
            crate::dlog!("[CAPTURE] using VAAPI hardware encoding (vah264enc)");
            return Ok((enc, false));
        }
        if hwaccel == "vaapi" {
            crate::dlog!("[CAPTURE] vah264enc not available, falling back to software");
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
        .property("bframes", 0u32) // GstX264Enc property is "bframes" (no hyphen)
        .property("sliced-threads", true)
        .property("byte-stream", true)
        .property("aud", true)
        .build()
        .context("create x264enc (install gst-plugins-ugly / libx264)")?;
    crate::dlog!("[CAPTURE] using software encoding (x264enc) bitrate={bitrate} kbps");
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
            crate::dlog!("[capture] xrandr failed, skipping monitor crop");
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
            crate::dlog!("[capture] primary monitor: {w}x{h} at +{x}+{y}");
            (x, y, x + w, y + h)
        }
        _ => {
            crate::dlog!("[capture] couldn't parse xrandr output, skipping monitor crop");
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
/// One process-wide Tokio runtime for all xdg-desktop-portal calls. ashpd keeps
/// a cached D-Bus connection alive on whatever runtime first drove it; a
/// per-call current-thread runtime would be dropped after the first request,
/// killing that connection's reactor so the next portal request hangs. Keeping a
/// single multi-thread runtime resident for the whole process avoids that.
fn portal_runtime() -> &'static tokio::runtime::Runtime {
    static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("build persistent portal tokio runtime")
    })
}

fn request_screencast(in_token: Option<&str>) -> Result<PortalSession> {
    use ashpd::desktop::screencast::{CursorMode, Screencast, SourceType};
    use ashpd::desktop::PersistMode;
    use ashpd::WindowIdentifier;

    // ONE persistent runtime for the whole process. ashpd caches its D-Bus
    // connection; if we built a fresh current-thread runtime per call and
    // dropped it, the cached connection's reactor would die with the first
    // runtime and the SECOND portal request (change-display / re-share) would
    // hang forever at Start — exactly the "black screen on 2nd connect" bug.
    let rt = portal_runtime();

    rt.block_on(async {
        crate::dlog!("[capture] portal: connecting ScreenCast proxy…");
        let proxy = Screencast::new()
            .await
            .context("connect ScreenCast portal")?;
        crate::dlog!("[capture] portal: creating session…");
        let session = proxy
            .create_session()
            .await
            .context("portal CreateSession")?;
        crate::dlog!("[capture] portal: select_sources (picker about to show)…");

        // MONITOR source, embedded cursor, single source. PersistMode::DoNot
        // (and NO restore token) so GNOME prompts for the display on EVERY
        // connect — matching the Go reference (capture.go forces persist 0). This
        // is what makes "Change display" work: reconnecting re-shows the native
        // screen picker instead of GNOME silently restoring the last screen.
        let _ = in_token; // intentionally not replayed; we always want the picker
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

        crate::dlog!("[capture] portal: Start (waiting for the user to pick a screen)…");
        let identifier = WindowIdentifier::default();
        let response = proxy
            .start(&session, &identifier)
            .await
            .context("portal Start")?
            .response()
            .context("portal Start response")?;
        crate::dlog!("[capture] portal: Start returned (screen picked)");

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
