//! Bufferbloat / network-quality probe.
//!
//! macOS ships `networkQuality(1)` (the same CLI behind System Settings →
//! Wi-Fi → Details → Network Quality). It runs a ~10-15 s test that reports:
//!   • Downlink / uplink throughput
//!   • Responsiveness (RPM — Round-trips Per Minute under load)
//!   • Idle latency baseline
//!
//! High RPM = the network keeps responding while loaded (≈ no bufferbloat).
//! Low RPM = packets queue at the bottleneck, latency-sensitive apps suffer
//! even when raw bandwidth is fine.
//!
//! We invoke with `-c` (JSON output), tolerate the schema being partial, and
//! fall back to scraping the human-readable lines if `-c` is missing on
//! older macOS versions.
//!
//! Linux / Windows: no equivalent shipped tool — this probe returns `None`.

use crate::types::QualityStats;
use serde::Deserialize;
use tokio::process::Command;
use tokio::time::{timeout, Duration};

/// Run the bufferbloat probe. Returns None on non-macOS, on probe timeout,
/// or when the tool isn't installed.
pub async fn measure_quality() -> Option<QualityStats> {
    measure_platform().await
}

/// Same as [`measure_quality`] but returns a human-readable reason string on
/// failure so the on-demand Run-test button can show *why* nothing came back.
#[cfg(target_os = "macos")]
pub async fn measure_quality_verbose() -> Result<QualityStats, String> {
    use std::path::Path;
    // Always use the absolute path: when a Tauri GUI app is launched by
    // launchd/Finder the inherited PATH may not include /usr/bin in some
    // edge cases (and being explicit makes the error message clearer).
    let bin = "/usr/bin/networkQuality";
    if !Path::new(bin).exists() {
        return Err(format!("{bin} is missing (this needs macOS 12+)."));
    }
    let spawn = Command::new(bin).args(["-c", "-s"]).output();
    let out = match timeout(Duration::from_secs(120), spawn).await {
        Err(_) => return Err("networkQuality timed out after 120 s".to_string()),
        Ok(Err(e)) => return Err(format!("could not launch networkQuality: {e}")),
        Ok(Ok(out)) => out,
    };
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stderr_trim = stderr.trim();
        return Err(if stderr_trim.is_empty() {
            format!("networkQuality exited with {}", out.status)
        } else {
            format!("networkQuality exited with {}: {stderr_trim}", out.status)
        });
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    parse_json(&stdout)
        .or_else(|| parse_text(&stdout))
        .ok_or_else(|| {
            let preview: String = stdout.chars().take(160).collect();
            format!("could not parse networkQuality output (got: {preview:?})")
        })
}

#[cfg(not(target_os = "macos"))]
pub async fn measure_quality_verbose() -> Result<QualityStats, String> {
    Err("Bufferbloat measurement requires macOS 12 or later.".to_string())
}

#[cfg(target_os = "macos")]
async fn measure_platform() -> Option<QualityStats> {
    // -c → JSON. -s → sequential up/down (slightly slower but doesn't confuse
    // RPM by saturating both directions at once).
    //
    // Empirically the test takes ~40-50 s end-to-end on a ~100 Mbps link
    // (20 s download phase + 20 s upload phase + handshake/teardown). The
    // older 18 s bound was a leftover from a `-v`-style assumption and
    // silently killed every run. We now give it 90 s of headroom.
    let out = timeout(
        Duration::from_secs(90),
        Command::new("networkQuality").args(["-c", "-s"]).output(),
    )
    .await
    .ok()?
    .ok()?;
    if !out.status.success() {
        tracing::debug!(target: "scan", "networkQuality exited non-zero");
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed = parse_json(&stdout).or_else(|| parse_text(&stdout));
    if parsed.is_none() {
        tracing::debug!(target: "scan", "networkQuality output not parseable");
    }
    parsed
}

#[cfg(not(target_os = "macos"))]
async fn measure_platform() -> Option<QualityStats> {
    None
}

// ── JSON parsing ─────────────────────────────────────────────────────────────
//
// `networkQuality -c` emits a JSON object with a stable subset of fields.
// We parse defensively: every field is optional, and we accept either
// `dl_throughput` (raw bits/s) or the friendlier `dl_throughput_mbps` flavour
// some macOS builds emit.

#[derive(Debug, Deserialize, Default)]
struct RawQuality {
    #[serde(default)]
    dl_throughput: Option<f64>,
    #[serde(default)]
    ul_throughput: Option<f64>,
    #[serde(default)]
    responsiveness: Option<f64>,
    #[serde(default)]
    dl_responsiveness: Option<f64>,
    #[serde(default)]
    ul_responsiveness: Option<f64>,
    #[serde(default)]
    base_rtt: Option<f64>,
    #[serde(default)]
    idle_latency_ms: Option<f64>,
}

fn parse_json(s: &str) -> Option<QualityStats> {
    // `networkQuality -c` emits one big JSON object, optionally preceded by
    // progress lines. Extract from the FIRST `{` to the LAST `}` — picking
    // `rfind('{')` would grab an inner nested object (e.g. `"other": {...}`)
    // and fail to parse.
    let start = s.find('{')?;
    let end = s.rfind('}')?;
    if end <= start {
        return None;
    }
    let raw: RawQuality = serde_json::from_str(&s[start..=end]).ok()?;

    // Throughput: some builds report bits/s, others Mbit/s. Anything > 10k we
    // treat as bits/s; otherwise it's already Mbit/s.
    let to_mbps = |v: Option<f64>| {
        v.map(|x| if x > 10_000.0 { x / 1_000_000.0 } else { x } as f32)
    };

    // Responsiveness in the `-c` JSON is reported in different units across
    // macOS builds. We've observed values like:
    //   • 1063  → already RPM  (text-output style: "1063 RPM")
    //   • 10.07 → milliseconds-per-round-trip (newer JSON style)
    // Heuristic: > 100 → already RPM, otherwise treat as ms/RT and convert
    // with RPM = 60_000 / ms.
    let to_rpm = |v: Option<f64>| {
        v.and_then(|x| {
            if x <= 0.0 {
                None
            } else if x > 100.0 {
                Some(x.round() as u32)
            } else {
                Some((60_000.0 / x).round() as u32)
            }
        })
    };
    let rpm = to_rpm(raw.responsiveness)
        .or_else(|| to_rpm(raw.dl_responsiveness))
        .or_else(|| to_rpm(raw.ul_responsiveness));

    // base_rtt and idle_latency_ms are both already in milliseconds in every
    // macOS build we've seen. Earlier code multiplied base_rtt by 1000,
    // turning a normal 111 ms reading into a nonsensical 111_000 ms.
    let idle = raw
        .idle_latency_ms
        .or(raw.base_rtt)
        .map(|v| v as f32);

    Some(QualityStats {
        dl_throughput_mbps: to_mbps(raw.dl_throughput),
        ul_throughput_mbps: to_mbps(raw.ul_throughput),
        responsiveness_rpm: rpm,
        idle_latency_ms: idle,
        responsiveness_label: rpm.map(rpm_label),
    })
}

// ── Text fallback ────────────────────────────────────────────────────────────
//
// Some macOS versions (and `networkQuality -v` without `-c`) only emit
// human-readable lines such as:
//   Uplink capacity: 92.155 Mbps
//   Downlink capacity: 195.382 Mbps
//   Responsiveness: High (1063 RPM)
//   Idle Latency: 41.667 milli-seconds
//
// Robust to slight wording changes ("capacity" vs "throughput").

fn parse_text(s: &str) -> Option<QualityStats> {
    let mut dl: Option<f32> = None;
    let mut ul: Option<f32> = None;
    let mut rpm: Option<u32> = None;
    let mut label: Option<String> = None;
    let mut idle: Option<f32> = None;

    for line in s.lines() {
        let l = line.trim();
        if let Some(v) = l
            .strip_prefix("Downlink capacity:")
            .or_else(|| l.strip_prefix("Downlink throughput:"))
        {
            dl = parse_mbps(v);
        } else if let Some(v) = l
            .strip_prefix("Uplink capacity:")
            .or_else(|| l.strip_prefix("Uplink throughput:"))
        {
            ul = parse_mbps(v);
        } else if let Some(v) = l.strip_prefix("Responsiveness:") {
            // e.g. "High (1063 RPM)"
            let v = v.trim();
            if let Some(open) = v.find('(') {
                label = Some(v[..open].trim().to_string());
                if let Some(close) = v.find(')') {
                    let inside = &v[open + 1..close];
                    rpm = inside
                        .split_whitespace()
                        .next()
                        .and_then(|n| n.parse::<u32>().ok());
                }
            } else if let Some(n) = v.split_whitespace().next() {
                rpm = n.parse::<u32>().ok();
            }
        } else if let Some(v) = l.strip_prefix("Idle Latency:") {
            // "41.667 milli-seconds"
            idle = v
                .split_whitespace()
                .next()
                .and_then(|n| n.parse::<f32>().ok());
        }
    }

    if dl.is_none() && ul.is_none() && rpm.is_none() {
        return None;
    }
    Some(QualityStats {
        dl_throughput_mbps: dl,
        ul_throughput_mbps: ul,
        responsiveness_rpm: rpm,
        idle_latency_ms: idle,
        responsiveness_label: label.or_else(|| rpm.map(rpm_label)),
    })
}

fn parse_mbps(s: &str) -> Option<f32> {
    // "92.155 Mbps" → 92.155
    s.split_whitespace()
        .next()
        .and_then(|n| n.parse::<f32>().ok())
}

/// Map an RPM number to Apple's qualitative label.
fn rpm_label(rpm: u32) -> String {
    match rpm {
        0..=99 => "Low".into(),
        100..=499 => "Medium".into(),
        _ => "High".into(),
    }
}

/// Threshold below which the network is considered bufferbloated.
pub const BUFFERBLOAT_RPM_THRESHOLD: u32 = 200;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_human_text_high_rpm() {
        let sample = "==== SUMMARY ====
Uplink capacity: 92.155 Mbps
Downlink capacity: 195.382 Mbps
Responsiveness: High (1063 RPM)
Idle Latency: 41.667 milli-seconds
";
        let q = parse_text(sample).expect("parsed");
        assert!((q.dl_throughput_mbps.unwrap() - 195.382).abs() < 0.01);
        assert!((q.ul_throughput_mbps.unwrap() - 92.155).abs() < 0.01);
        assert_eq!(q.responsiveness_rpm, Some(1063));
        assert_eq!(q.responsiveness_label.as_deref(), Some("High"));
        assert!((q.idle_latency_ms.unwrap() - 41.667).abs() < 0.01);
    }

    #[test]
    fn parses_human_text_low_rpm_bufferbloated() {
        let sample = "Responsiveness: Low (45 RPM)\n";
        let q = parse_text(sample).expect("parsed");
        assert_eq!(q.responsiveness_rpm, Some(45));
        assert_eq!(q.responsiveness_label.as_deref(), Some("Low"));
    }

    #[test]
    fn parses_json_bits_per_sec() {
        let sample = r#"{"dl_throughput": 195000000, "ul_throughput": 92000000, "responsiveness": 1063, "base_rtt": 0.041}"#;
        let q = parse_json(sample).expect("parsed");
        assert!((q.dl_throughput_mbps.unwrap() - 195.0).abs() < 1.0);
        assert_eq!(q.responsiveness_rpm, Some(1063));
        assert!(q.idle_latency_ms.unwrap() > 40.0 && q.idle_latency_ms.unwrap() < 42.0);
    }

    #[test]
    fn rpm_label_classifies_correctly() {
        assert_eq!(rpm_label(50), "Low");
        assert_eq!(rpm_label(250), "Medium");
        assert_eq!(rpm_label(1500), "High");
    }
}
