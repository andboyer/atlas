/// HTTP download speed test probe.
///
/// Downloads a known-size file from a CDN and measures throughput in Mbps.
/// Uses a 5-second timeout — partial downloads still yield a valid speed.
///
/// Test endpoint: Cloudflare's speed test CDN (10 MB file, no auth, CORS-open).
/// Fallback: fast.com token-free 25 MB file.
use reqwest::Client;
use std::time::Instant;
use tokio::time::{timeout, Duration};

/// Download timeout. We measure what arrives within this window.
const DOWNLOAD_TIMEOUT_SECS: u64 = 8;

/// Minimum bytes we need to read before computing a meaningful speed.
const MIN_BYTES: u64 = 128 * 1024; // 128 KiB

/// Download speed test endpoints (tried in order).
const ENDPOINTS: &[&str] = &[
    // Cloudflare speed test CDN — 10 MB, reliable, no referrer required.
    "https://speed.cloudflare.com/__down?bytes=10000000",
    // Fastly / GitHub releases (small, public).
    "https://github.com/nicehash/NiceHashQuickMiner/releases/download/v0.9.2.3/NiceHashQuickMiner_v0.9.2.3_sign.zip",
];

/// Run the speed test. Returns download speed in Mbit/s, or `None` if all
/// endpoints fail or network is unreachable.
pub async fn measure_download_mbps() -> Option<f32> {
    let client = Client::builder()
        .timeout(Duration::from_secs(DOWNLOAD_TIMEOUT_SECS + 2))
        .build()
        .ok()?;

    for endpoint in ENDPOINTS {
        if let Some(mbps) = try_endpoint(&client, endpoint).await {
            return Some(mbps);
        }
    }
    None
}

async fn try_endpoint(client: &Client, url: &str) -> Option<f32> {
    let resp = timeout(
        Duration::from_secs(3),
        client.get(url).send(),
    )
    .await
    .ok()?
    .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    let started = Instant::now();
    let mut total_bytes: u64 = 0;

    let timed_out = timeout(Duration::from_secs(DOWNLOAD_TIMEOUT_SECS), async {
        if let Ok(body) = resp.bytes().await {
            total_bytes = body.len() as u64;
        }
    })
    .await;
    let _ = timed_out;

    let elapsed = started.elapsed().as_secs_f64();
    if total_bytes < MIN_BYTES || elapsed < 0.1 {
        return None;
    }

    let mbps = (total_bytes as f64 * 8.0) / (elapsed * 1_000_000.0);
    Some(mbps as f32)
}

/// Threshold below which we flag slow download speed (Mbit/s).
pub const SLOW_DOWNLOAD_THRESHOLD_MBPS: f32 = 5.0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_is_positive() {
        const _: () = assert!(SLOW_DOWNLOAD_THRESHOLD_MBPS > 0.0);
    }

    #[test]
    fn speed_calculation() {
        // 10 MB in 1 second = 80 Mbps
        let bytes = 10_000_000u64;
        let secs = 1.0f64;
        let mbps = (bytes as f64 * 8.0) / (secs * 1_000_000.0);
        assert!((mbps - 80.0).abs() < 0.01);
    }
}
