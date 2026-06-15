//! Playout-latency target — a faithful Rust port of doubletake's
//! internal/airplay/latency.go.
//!
//! This is the single source of truth for the sender's end-to-end playout
//! latency target and the 44.1 kHz sample math derived from it. The mirror
//! (video timestamp bias) and audio (RTP latency samples) paths both read from
//! here so the audio and video clocks stay in sync.

#![allow(dead_code)]

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

/// latency.go defaultTargetLatency = 1 * time.Millisecond.
pub const DEFAULT_TARGET_LATENCY: Duration = Duration::from_millis(1);

/// latency.go conservativePlayoutLatency = 500 * time.Millisecond — the playout
/// lead required by receivers without a robust audio jitter buffer (applied
/// per-receiver, not globally; see ReceiverInfo's playout floor).
pub const CONSERVATIVE_PLAYOUT_LATENCY: Duration = Duration::from_millis(500);

/// Process-global target latency, stored as nanoseconds (latency.go
/// targetLatencyNS atomic.Int64, init to defaultTargetLatency).
static TARGET_LATENCY_NS: AtomicI64 = AtomicI64::new(DEFAULT_TARGET_LATENCY.as_nanos() as i64);

/// SetTargetLatency: set the desired end-to-end playout latency target, clamped
/// to [5ms, 2s] (port of latency.go SetTargetLatency).
pub fn set_target_latency(d: Duration) {
    let mut d = d;
    let min = Duration::from_millis(5);
    let max = Duration::from_secs(2);
    if d < min {
        d = min;
    }
    if d > max {
        d = max;
    }
    TARGET_LATENCY_NS.store(d.as_nanos() as i64, Ordering::Relaxed);
}

/// TargetLatency: the configured playout latency target (port of latency.go
/// TargetLatency). Falls back to the default if a non-positive value is stored.
pub fn target_latency() -> Duration {
    let ns = TARGET_LATENCY_NS.load(Ordering::Relaxed);
    if ns <= 0 {
        DEFAULT_TARGET_LATENCY
    } else {
        Duration::from_nanos(ns as u64)
    }
}

/// targetLatencySamples44k1 — the current target latency in 44.1 kHz samples
/// (port of latency.go targetLatencySamples44k1).
pub fn target_latency_samples_44k1() -> u32 {
    samples_for_44k1(target_latency())
}

/// samplesFor44k1 — round(d * 44100), floored at 1, capped at u32::MAX (port of
/// latency.go samplesFor44k1, using math.Round / round-half-away-from-zero).
pub fn samples_for_44k1(d: Duration) -> u32 {
    let samples = (d.as_secs_f64() * 44100.0).round();
    if samples < 1.0 {
        1
    } else if samples > u32::MAX as f64 {
        u32::MAX
    } else {
        samples as u32
    }
}

/// videoTimestampBias — TargetLatency, floored at 5ms (port of mirror.go
/// videoTimestampBias). With the default 1ms target this returns 5ms.
pub fn video_timestamp_bias() -> Duration {
    let bias = target_latency();
    if bias < Duration::from_millis(5) {
        Duration::from_millis(5)
    } else {
        bias
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_for_44k1_matches_go_math() {
        // round(d * 44100), floored at 1.
        // 1ms  -> round(44.1)   = 44
        assert_eq!(samples_for_44k1(Duration::from_millis(1)), 44);
        // 5ms  -> round(220.5)  = 221 (round half away from zero)
        assert_eq!(samples_for_44k1(Duration::from_millis(5)), 221);
        // 10ms -> round(441.0)  = 441
        assert_eq!(samples_for_44k1(Duration::from_millis(10)), 441);
        // 1s   -> 44100
        assert_eq!(samples_for_44k1(Duration::from_secs(1)), 44100);
        // 500ms (conservative floor) -> round(22050.0) = 22050
        assert_eq!(samples_for_44k1(CONSERVATIVE_PLAYOUT_LATENCY), 22050);
        // Sub-sample durations floor to 1.
        assert_eq!(samples_for_44k1(Duration::from_nanos(1)), 1);
        assert_eq!(samples_for_44k1(Duration::from_secs(0)), 1);
    }

    #[test]
    fn default_target_and_bias() {
        // Default target latency is 1ms; the video bias floors it to 5ms.
        assert_eq!(target_latency(), DEFAULT_TARGET_LATENCY);
        assert_eq!(video_timestamp_bias(), Duration::from_millis(5));
        // The default target in samples is 44 (round(44.1)).
        assert_eq!(target_latency_samples_44k1(), 44);
    }
}
