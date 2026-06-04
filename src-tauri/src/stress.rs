//! Active stress tests.
//!
//! On-demand load injectors that pin down whether a slowdown is the AP, the
//! WAN, or a particular service. Each test runs for ~5–10 s, emits
//! `stress:tick` events as samples land, and finishes with a single
//! `stress:complete` event containing the [`StressTestResult`].
//!
//! Three tests ship today:
//!
//! * `ping_flood` — 32 back-to-back ICMP pings at ~50 ms cadence to the
//!   default gateway. Loss > 5 % or jitter > 30 ms strongly implicates the
//!   AP / cabling.
//! * `dns_burst` — 24 concurrent `getaddrinfo` calls against a varied set of
//!   hostnames. P95 > 200 ms or any failures usually means a sad resolver.
//! * `wan_parallel` — 5 parallel HTTPS HEAD requests against well-known
//!   anycast endpoints. Big tail with low local pings means upstream
//!   congestion.

use crate::probes::reachability::{default_gateway_for_iface, ping_via};
use crate::types::{StressSample, StressStats, StressTestResult};
use chrono::Utc;
use std::time::Instant;
use tauri::{AppHandle, Emitter};
use tokio::time::{timeout, Duration};
use uuid::Uuid;

pub const KIND_PING_FLOOD: &str = "ping_flood";
pub const KIND_DNS_BURST: &str = "dns_burst";
pub const KIND_WAN_PARALLEL: &str = "wan_parallel";

pub fn list_kinds() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        (
            KIND_PING_FLOOD,
            "Ping flood",
            "32 quick pings to your gateway. Reveals AP/cable jitter and loss.",
        ),
        (
            KIND_DNS_BURST,
            "DNS burst",
            "24 parallel name resolutions across varied hosts. Surfaces resolver issues.",
        ),
        (
            KIND_WAN_PARALLEL,
            "WAN saturation",
            "5 parallel HTTPS requests to public endpoints. Surfaces upstream congestion.",
        ),
    ]
}

/// Run the named stress test to completion. `iface` (optional) pins the
/// probes that have a notion of "the" gateway (ping_flood) to that NIC's
/// next-hop instead of whatever default route the kernel picks.
pub async fn run(app: AppHandle, kind: &str, iface: Option<&str>) -> Result<StressTestResult, String> {
    match kind {
        KIND_PING_FLOOD => Ok(ping_flood(app, iface).await),
        KIND_DNS_BURST => Ok(dns_burst(app).await),
        KIND_WAN_PARALLEL => Ok(wan_parallel(app).await),
        other => Err(format!("unknown stress test kind: {other}")),
    }
}

// ─── ping flood ──────────────────────────────────────────────────────────────

async fn ping_flood(app: AppHandle, iface: Option<&str>) -> StressTestResult {
    let id = Uuid::new_v4().to_string();
    let start_wall = Utc::now();
    let started = Instant::now();
    let gw = default_gateway_for_iface(iface).await;

    let mut samples: Vec<StressSample> = Vec::with_capacity(32);

    let target = match gw {
        Some(ip) => ip,
        None => {
            return finalize(
                id,
                KIND_PING_FLOOD,
                "Ping flood",
                start_wall,
                started,
                false,
                "Could not resolve default gateway.".to_string(),
                vec!["No route exists or `route` lookup failed.".to_string()],
                StressStats::default(),
                samples,
                app,
            )
            .await;
        }
    };

    for i in 0..32 {
        let t0 = Instant::now();
        let latency = timeout(Duration::from_millis(1500), ping_via(&target, 1, iface))
            .await
            .ok()
            .flatten();
        let success = latency.is_some();
        let sample = StressSample {
            ts: Utc::now(),
            offset_ms: started.elapsed().as_millis() as u64,
            latency_ms: latency,
            success,
            label: format!("#{:02}", i + 1),
        };
        let _ = app.emit("stress:tick", &(id.clone(), sample.clone()));
        samples.push(sample);
        // ~50 ms cadence keeps the test under 2 s total — a real burst.
        if t0.elapsed() < Duration::from_millis(50) {
            tokio::time::sleep(Duration::from_millis(50) - t0.elapsed()).await;
        }
    }

    let stats = compute_stats(&samples);
    let success = stats.failed == 0 && stats.jitter_ms.unwrap_or(0.0) < 30.0;
    let headline = if !success {
        if stats.failed > 0 {
            format!(
                "Gateway dropped {} of {} pings ({:.0} % loss).",
                stats.failed,
                stats.attempted,
                stats.loss_pct.unwrap_or(0.0)
            )
        } else {
            format!(
                "High jitter to gateway: {:.0} ms (target < 30 ms).",
                stats.jitter_ms.unwrap_or(0.0)
            )
        }
    } else {
        format!(
            "Gateway is stable: {:.1} ms avg, {:.0} ms jitter, 0 % loss.",
            stats.avg_ms.unwrap_or(0.0),
            stats.jitter_ms.unwrap_or(0.0)
        )
    };

    let details = vec![
        format!(
            "Latency min/avg/p95/max: {} / {} / {} / {} ms",
            fmt_opt(stats.min_ms),
            fmt_opt(stats.avg_ms),
            fmt_opt(stats.p95_ms),
            fmt_opt(stats.max_ms),
        ),
        format!("Target: {target}"),
    ];

    finalize(
        id,
        KIND_PING_FLOOD,
        "Ping flood",
        start_wall,
        started,
        success,
        headline,
        details,
        stats,
        samples,
        app,
    )
    .await
}

// ─── DNS burst ──────────────────────────────────────────────────────────────

async fn dns_burst(app: AppHandle) -> StressTestResult {
    let id = Uuid::new_v4().to_string();
    let start_wall = Utc::now();
    let started = Instant::now();

    // 24 hosts varied across providers + TLDs so we exercise resolver paths
    // beyond a single cached zone.
    const HOSTS: &[&str] = &[
        "apple.com",
        "google.com",
        "microsoft.com",
        "amazon.com",
        "cloudflare.com",
        "github.com",
        "openai.com",
        "nytimes.com",
        "bbc.co.uk",
        "wikipedia.org",
        "stackoverflow.com",
        "akamai.com",
        "fastly.com",
        "netflix.com",
        "youtube.com",
        "linkedin.com",
        "reddit.com",
        "stripe.com",
        "slack.com",
        "dropbox.com",
        "zoom.us",
        "twitch.tv",
        "discord.com",
        "duckduckgo.com",
    ];

    // Fire all in parallel; we tag each task with its index so the UI can
    // order them.
    let app_inner = app.clone();
    let id_for_tasks = id.clone();
    let started_inner = started;

    let mut handles = Vec::with_capacity(HOSTS.len());
    for (i, host) in HOSTS.iter().enumerate() {
        let app_t = app_inner.clone();
        let id_t = id_for_tasks.clone();
        let host = host.to_string();
        let h = tokio::spawn(async move {
            let t0 = Instant::now();
            let res = timeout(
                Duration::from_millis(3000),
                crate::probes::reachability::dns_resolve_ms(&host),
            )
            .await;
            let latency = match res {
                Ok(Some(ms)) => Some(ms),
                _ => None,
            };
            let success = latency.is_some();
            let sample = StressSample {
                ts: Utc::now(),
                offset_ms: started_inner.elapsed().as_millis() as u64,
                latency_ms: latency,
                success,
                label: host.clone(),
            };
            // Best-effort emit; ignore errors.
            let _ = t0;
            let _ = app_t.emit("stress:tick", &(id_t, sample.clone()));
            (i, sample)
        });
        handles.push(h);
    }

    let mut indexed: Vec<(usize, StressSample)> = Vec::with_capacity(HOSTS.len());
    for h in handles {
        if let Ok(pair) = h.await {
            indexed.push(pair);
        }
    }
    indexed.sort_by_key(|(i, _)| *i);
    let samples: Vec<StressSample> = indexed.into_iter().map(|(_, s)| s).collect();

    let stats = compute_stats(&samples);
    let success = stats.failed == 0 && stats.p95_ms.unwrap_or(0.0) < 200.0;
    let headline = if stats.failed > 0 {
        format!(
            "{} of {} DNS lookups failed.",
            stats.failed, stats.attempted
        )
    } else if !success {
        format!(
            "DNS is slow: p95 {:.0} ms (target < 200 ms).",
            stats.p95_ms.unwrap_or(0.0)
        )
    } else {
        format!(
            "Resolver is healthy: avg {:.0} ms, p95 {:.0} ms, 0 failures.",
            stats.avg_ms.unwrap_or(0.0),
            stats.p95_ms.unwrap_or(0.0)
        )
    };

    let details = vec![
        format!(
            "Resolved {} hostnames in parallel using the system resolver.",
            HOSTS.len()
        ),
        format!(
            "min/avg/p95/max: {} / {} / {} / {} ms",
            fmt_opt(stats.min_ms),
            fmt_opt(stats.avg_ms),
            fmt_opt(stats.p95_ms),
            fmt_opt(stats.max_ms),
        ),
    ];

    finalize(
        id,
        KIND_DNS_BURST,
        "DNS burst",
        start_wall,
        started,
        success,
        headline,
        details,
        stats,
        samples,
        app,
    )
    .await
}

// ─── WAN parallel (HTTPS HEAD) ──────────────────────────────────────────────

async fn wan_parallel(app: AppHandle) -> StressTestResult {
    let id = Uuid::new_v4().to_string();
    let start_wall = Utc::now();
    let started = Instant::now();

    // Anycast / global-CDN HEAD endpoints. We use HEAD so we don't pull
    // bytes; the timing isolates handshake + first-byte path.
    const URLS: &[&str] = &[
        "https://www.apple.com/",
        "https://www.google.com/",
        "https://www.cloudflare.com/",
        "https://www.amazon.com/",
        "https://www.microsoft.com/",
    ];

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return finalize(
                id,
                KIND_WAN_PARALLEL,
                "WAN saturation",
                start_wall,
                started,
                false,
                format!("Could not build HTTP client: {e}"),
                vec![],
                StressStats::default(),
                vec![],
                app,
            )
            .await;
        }
    };

    let mut handles = Vec::with_capacity(URLS.len());
    for (i, url) in URLS.iter().enumerate() {
        let client = client.clone();
        let url = url.to_string();
        let app_t = app.clone();
        let id_t = id.clone();
        let started_inner = started;
        let h = tokio::spawn(async move {
            let t0 = Instant::now();
            let result = client.head(&url).send().await;
            let latency = match result {
                Ok(r) if r.status().is_success() || r.status().is_redirection() => {
                    Some(t0.elapsed().as_secs_f32() * 1000.0)
                }
                _ => None,
            };
            let success = latency.is_some();
            let sample = StressSample {
                ts: Utc::now(),
                offset_ms: started_inner.elapsed().as_millis() as u64,
                latency_ms: latency,
                success,
                label: short_host(&url),
            };
            let _ = app_t.emit("stress:tick", &(id_t, sample.clone()));
            (i, sample)
        });
        handles.push(h);
    }

    let mut indexed: Vec<(usize, StressSample)> = Vec::with_capacity(URLS.len());
    for h in handles {
        if let Ok(pair) = h.await {
            indexed.push(pair);
        }
    }
    indexed.sort_by_key(|(i, _)| *i);
    let samples: Vec<StressSample> = indexed.into_iter().map(|(_, s)| s).collect();

    let stats = compute_stats(&samples);
    let success = stats.failed == 0 && stats.max_ms.unwrap_or(0.0) < 1500.0;
    let headline = if stats.failed > 0 {
        format!(
            "{} of {} parallel WAN requests failed.",
            stats.failed, stats.attempted
        )
    } else if !success {
        format!(
            "WAN is slow under load: worst {:.0} ms (target < 1500 ms).",
            stats.max_ms.unwrap_or(0.0)
        )
    } else {
        format!(
            "WAN handles parallel load: max {:.0} ms across {} endpoints.",
            stats.max_ms.unwrap_or(0.0),
            URLS.len()
        )
    };

    let details = vec![
        "Parallel HTTPS HEAD requests bypass server-side response payload to isolate handshake + first-byte time.".to_string(),
        format!(
            "min/avg/p95/max: {} / {} / {} / {} ms",
            fmt_opt(stats.min_ms),
            fmt_opt(stats.avg_ms),
            fmt_opt(stats.p95_ms),
            fmt_opt(stats.max_ms),
        ),
    ];

    finalize(
        id,
        KIND_WAN_PARALLEL,
        "WAN saturation",
        start_wall,
        started,
        success,
        headline,
        details,
        stats,
        samples,
        app,
    )
    .await
}

// ─── Stats helpers ───────────────────────────────────────────────────────────

fn compute_stats(samples: &[StressSample]) -> StressStats {
    let attempted = samples.len() as u32;
    let succeeded = samples.iter().filter(|s| s.success).count() as u32;
    let failed = attempted - succeeded;

    let mut latencies: Vec<f32> = samples
        .iter()
        .filter_map(|s| s.latency_ms)
        .filter(|v| v.is_finite())
        .collect();
    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let min_ms = latencies.first().copied();
    let max_ms = latencies.last().copied();
    let avg_ms = if latencies.is_empty() {
        None
    } else {
        Some(latencies.iter().sum::<f32>() / latencies.len() as f32)
    };
    let p95_ms = if latencies.is_empty() {
        None
    } else {
        let idx = ((latencies.len() as f32 - 1.0) * 0.95).round() as usize;
        latencies.get(idx).copied()
    };
    let jitter_ms = if latencies.len() < 2 {
        None
    } else {
        let mean = avg_ms.unwrap_or(0.0);
        let var: f32 = latencies
            .iter()
            .map(|v| (v - mean).powi(2))
            .sum::<f32>()
            / latencies.len() as f32;
        Some(var.sqrt())
    };
    let loss_pct = if attempted == 0 {
        None
    } else {
        Some((failed as f32) * 100.0 / (attempted as f32))
    };

    StressStats {
        attempted,
        succeeded,
        failed,
        min_ms,
        avg_ms,
        max_ms,
        p95_ms,
        jitter_ms,
        loss_pct,
    }
}

fn fmt_opt(v: Option<f32>) -> String {
    match v {
        Some(x) => format!("{x:.0}"),
        None => "—".to_string(),
    }
}

fn short_host(url: &str) -> String {
    let s = url.trim_start_matches("https://").trim_start_matches("http://");
    s.split('/').next().unwrap_or(url).to_string()
}

#[allow(clippy::too_many_arguments)]
async fn finalize(
    id: String,
    kind: &str,
    label: &str,
    start_wall: chrono::DateTime<Utc>,
    started: Instant,
    success: bool,
    headline: String,
    details: Vec<String>,
    stats: StressStats,
    samples: Vec<StressSample>,
    app: AppHandle,
) -> StressTestResult {
    let result = StressTestResult {
        id,
        kind: kind.to_string(),
        label: label.to_string(),
        started_at: start_wall,
        finished_at: Utc::now(),
        duration_ms: started.elapsed().as_millis() as u64,
        success,
        headline,
        details,
        stats,
        samples,
    };
    if let Err(e) = app.emit("stress:complete", &result) {
        tracing::warn!(target: "stress", error = %e, "emit stress:complete failed");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(latency: Option<f32>, success: bool) -> StressSample {
        StressSample {
            ts: Utc::now(),
            offset_ms: 0,
            latency_ms: latency,
            success,
            label: "t".into(),
        }
    }

    #[test]
    fn stats_empty() {
        let st = compute_stats(&[]);
        assert_eq!(st.attempted, 0);
        assert_eq!(st.failed, 0);
        assert!(st.avg_ms.is_none());
        assert!(st.loss_pct.is_none());
    }

    #[test]
    fn stats_all_good() {
        let samples = vec![s(Some(10.0), true), s(Some(20.0), true), s(Some(30.0), true)];
        let st = compute_stats(&samples);
        assert_eq!(st.attempted, 3);
        assert_eq!(st.failed, 0);
        assert_eq!(st.min_ms, Some(10.0));
        assert_eq!(st.max_ms, Some(30.0));
        assert!((st.avg_ms.unwrap() - 20.0).abs() < 0.01);
        assert_eq!(st.loss_pct, Some(0.0));
    }

    #[test]
    fn stats_with_loss() {
        let samples = vec![s(Some(5.0), true), s(None, false), s(Some(15.0), true)];
        let st = compute_stats(&samples);
        assert_eq!(st.attempted, 3);
        assert_eq!(st.failed, 1);
        assert_eq!(st.succeeded, 2);
        assert!((st.loss_pct.unwrap() - 33.333).abs() < 0.1);
    }

    #[test]
    fn short_host_strips_scheme() {
        assert_eq!(short_host("https://www.apple.com/path"), "www.apple.com");
        assert_eq!(short_host("http://x.example/"), "x.example");
    }
}
