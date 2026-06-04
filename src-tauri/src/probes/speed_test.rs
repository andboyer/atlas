/// HTTP download speed test probe.
///
/// Streams from a CDN endpoint and measures throughput in Mbps. The probe
/// is intentionally chunked rather than buffered so that whatever arrives
/// within the budget produces a valid measurement — a fully-downloaded
/// 10 MB file on a fast link and a half-downloaded 10 MB file on a slow
/// link both yield a sensible Mbps. The previous implementation called
/// `resp.bytes()` which returns only when the entire body has arrived; if
/// the budget expired mid-download the future was dropped and we reported
/// `None` even though several megabytes had streamed in.
///
/// Endpoints are tried in order until one returns a sample of at least
/// `MIN_BYTES`. All endpoints below are token-free and CORS-open.
use reqwest::Client;
use std::time::Instant;
use tokio::time::{timeout, Duration};

/// Total budget per probe (covers connect + TLS + body streaming).
const DOWNLOAD_TIMEOUT_SECS: u64 = 8;

/// Headers-received budget (just connect + TLS). Generous so a slow
/// handshake on a flaky link doesn't lose the whole probe.
const HEADERS_TIMEOUT_SECS: u64 = 5;

/// Minimum bytes we need to read before computing a meaningful speed.
/// Lowered from 128 KiB → 64 KiB so single-digit Mbps connections still
/// register a value instead of silently returning `None`.
const MIN_BYTES: u64 = 64 * 1024;

/// Minimum elapsed time before we trust a measurement. A < 100 ms
/// observation is dominated by client-side scheduling jitter.
const MIN_ELAPSED_SECS: f64 = 0.1;

/// Download speed test endpoints (tried in order). All are stable, free,
/// and CORS-open. Mixing providers means a single CDN outage doesn't
/// silently degrade the probe.
const ENDPOINTS: &[&str] = &[
    // Cloudflare speed test CDN — 10 MB, very stable, low first-byte latency.
    "https://speed.cloudflare.com/__down?bytes=10000000",
    // Cloudflare smaller (5 MB) — same provider but a smaller payload so
    // slow links still finish within the budget.
    "https://speed.cloudflare.com/__down?bytes=5000000",
    // OVH speed test — different provider, different ASN.
    "https://proof.ovh.net/files/10Mb.dat",
];

/// Run the speed test. Returns download speed in Mbit/s, or `None` if all
/// endpoints fail or network is unreachable.
pub async fn measure_download_mbps() -> Option<f32> {
    // Client-wide timeout is a safety net only; per-stage timeouts below
    // are tighter and fire first.
    let client = Client::builder()
        .timeout(Duration::from_secs(DOWNLOAD_TIMEOUT_SECS + HEADERS_TIMEOUT_SECS + 2))
        .build()
        .ok()?;

    for endpoint in ENDPOINTS {
        match try_endpoint(&client, endpoint).await {
            Some(mbps) => {
                tracing::debug!(
                    target: "probe::speed",
                    endpoint = endpoint,
                    mbps = mbps,
                    "speed test ok"
                );
                return Some(mbps);
            }
            None => {
                tracing::debug!(
                    target: "probe::speed",
                    endpoint = endpoint,
                    "speed test endpoint produced no usable sample"
                );
            }
        }
    }
    tracing::warn!(target: "probe::speed", "all speed test endpoints failed");
    None
}

async fn try_endpoint(client: &Client, url: &str) -> Option<f32> {
    let resp = match timeout(
        Duration::from_secs(HEADERS_TIMEOUT_SECS),
        client.get(url).send(),
    )
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            tracing::debug!(target: "probe::speed", endpoint = url, error = %e, "send failed");
            return None;
        }
        Err(_) => {
            tracing::debug!(target: "probe::speed", endpoint = url, "headers timed out");
            return None;
        }
    };

    if !resp.status().is_success() {
        tracing::debug!(
            target: "probe::speed",
            endpoint = url,
            status = %resp.status(),
            "non-2xx response"
        );
        return None;
    }

    let started = Instant::now();
    let budget = Duration::from_secs(DOWNLOAD_TIMEOUT_SECS);
    let mut total_bytes: u64 = 0;
    let mut stream = resp;

    loop {
        let remaining = match budget.checked_sub(started.elapsed()) {
            Some(r) if !r.is_zero() => r,
            _ => break,
        };
        match timeout(remaining, stream.chunk()).await {
            Ok(Ok(Some(chunk))) => {
                total_bytes = total_bytes.saturating_add(chunk.len() as u64);
            }
            // Body finished cleanly within the budget.
            Ok(Ok(None)) => break,
            // Network error mid-stream — return whatever we measured.
            Ok(Err(e)) => {
                tracing::debug!(
                    target: "probe::speed",
                    endpoint = url,
                    error = %e,
                    bytes = total_bytes,
                    "stream errored mid-read"
                );
                break;
            }
            // Budget elapsed — return whatever we measured.
            Err(_) => break,
        }
    }

    let elapsed = started.elapsed().as_secs_f64();
    if total_bytes < MIN_BYTES || elapsed < MIN_ELAPSED_SECS {
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
