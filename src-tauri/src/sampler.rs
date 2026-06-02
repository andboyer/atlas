//! Live (~1 Hz) telemetry sampler.
//!
//! Runs three lightweight, decoupled tokio tasks:
//!
//! * **Link refresher** — back-to-back `system_profiler SPAirPortDataType`
//!   calls (the only signal/noise/tx-rate source we have without sudo or
//!   CoreWLAN bindings). Each call takes ~13 s on Apple Silicon, so this
//!   task effectively refreshes the cached snapshot every ~14 s. Writes
//!   into `link_snap`.
//!
//! * **Gateway IP refresher** — `route -n get default` every 30 s. Caches
//!   into `gateway_ip` so the per-tick ping doesn't pay the resolution
//!   cost.
//!
//! * **Sampler tick** — every ~1 s: parallel single-packet pings of
//!   gateway + 1.1.1.1, plus a `getaddrinfo("apple.com")` resolve timing.
//!   Pulls the cached link snapshot, builds a [`LiveSample`], pushes it
//!   into the 3600-deep ring buffer, and emits a `metric:tick` Tauri event
//!   for the frontend chart.
//!
//! The ring buffer is exposed to the frontend via the `get_live_metrics`
//! command (defined in `commands.rs`); the frontend keeps its own
//! mirrored ring buffer that grows incrementally from event ticks.

use crate::collectors::default_collector;
use crate::probes::reachability::{default_gateway, dns_resolve_ms, ping};
use crate::types::{LinkStats, LiveSample};
use chrono::Utc;
use parking_lot::RwLock;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter};
use tokio::time::timeout;

/// 60 minutes of history at 1 Hz.
pub const RING_CAPACITY: usize = 3600;

/// Target tick interval. Probes may take longer; we pace so we never run
/// faster than this but accept that we run slower when the network is sad.
const TICK_INTERVAL: Duration = Duration::from_millis(1000);

/// Per-probe hard cap so a hung probe can't delay the next tick.
const PROBE_BUDGET: Duration = Duration::from_millis(1500);

pub type LiveRing = Arc<RwLock<VecDeque<LiveSample>>>;

pub struct SamplerHandle {
    pub running: Arc<AtomicBool>,
    pub ring: LiveRing,
}

impl SamplerHandle {
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

/// Spawn the three sampler tasks and return the shared ring + stop signal.
pub fn start_sampler(app: AppHandle) -> SamplerHandle {
    let running = Arc::new(AtomicBool::new(true));
    let ring: LiveRing = Arc::new(RwLock::new(VecDeque::with_capacity(RING_CAPACITY)));

    let link_snap: Arc<RwLock<Option<LinkStats>>> = Arc::new(RwLock::new(None));
    spawn_link_refresher(Arc::clone(&link_snap), Arc::clone(&running));

    let gateway_ip: Arc<RwLock<Option<String>>> = Arc::new(RwLock::new(None));
    spawn_gateway_refresher(Arc::clone(&gateway_ip), Arc::clone(&running));

    spawn_tick(
        app,
        Arc::clone(&ring),
        link_snap,
        gateway_ip,
        Arc::clone(&running),
    );

    SamplerHandle { running, ring }
}

fn spawn_link_refresher(snap: Arc<RwLock<Option<LinkStats>>>, running: Arc<AtomicBool>) {
    tokio::spawn(async move {
        let collector = default_collector();
        while running.load(Ordering::Relaxed) {
            match collector.link_stats().await {
                Ok(stats) => {
                    *snap.write() = Some(stats);
                }
                Err(e) => {
                    tracing::debug!(target: "sampler", error = %e, "link refresh failed");
                }
            }
            // Brief gap so we don't peg the CPU even if link_stats returns
            // unexpectedly fast (e.g. the linux collector reads /proc).
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        tracing::debug!(target: "sampler", "link refresher stopped");
    });
}

fn spawn_gateway_refresher(snap: Arc<RwLock<Option<String>>>, running: Arc<AtomicBool>) {
    tokio::spawn(async move {
        // First refresh immediately so the first few ticks have a gateway.
        if let Some(ip) = default_gateway().await {
            *snap.write() = Some(ip);
        }
        while running.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_secs(30)).await;
            if !running.load(Ordering::Relaxed) {
                break;
            }
            if let Some(ip) = default_gateway().await {
                *snap.write() = Some(ip);
            }
        }
        tracing::debug!(target: "sampler", "gateway refresher stopped");
    });
}

fn spawn_tick(
    app: AppHandle,
    ring: LiveRing,
    link_snap: Arc<RwLock<Option<LinkStats>>>,
    gateway_ip: Arc<RwLock<Option<String>>>,
    running: Arc<AtomicBool>,
) {
    tokio::spawn(async move {
        tracing::info!(target: "sampler", "live sampler started");
        // Force the very first tick to fire immediately.
        let mut next_at = Instant::now();
        loop {
            if !running.load(Ordering::Relaxed) {
                tracing::info!(target: "sampler", "live sampler stopping");
                break;
            }

            // Pace at TICK_INTERVAL without drifting forward if probes are slow.
            let now = Instant::now();
            if now < next_at {
                tokio::time::sleep(next_at - now).await;
            }
            next_at = Instant::now() + TICK_INTERVAL;

            let gw_ip = gateway_ip.read().clone();
            let (gw_ms, inet_ms, dns_ms) = tokio::join!(
                bounded_ping(gw_ip.as_deref()),
                bounded_ping(Some("1.1.1.1")),
                bounded_dns("apple.com"),
            );

            let (rssi, snr, tx_rate) = match link_snap.read().as_ref() {
                Some(l) => (l.rssi_dbm, l.snr_db, l.tx_rate_mbps),
                None => (None, None, None),
            };
            let link_up = rssi.is_some() || inet_ms.is_some() || gw_ms.is_some();

            let sample = LiveSample {
                ts: Utc::now(),
                rssi_dbm: rssi,
                snr_db: snr,
                tx_rate_mbps: tx_rate,
                gateway_ms: gw_ms,
                internet_ms: inet_ms,
                dns_ms,
                link_up,
            };

            {
                let mut r = ring.write();
                if r.len() == RING_CAPACITY {
                    r.pop_front();
                }
                r.push_back(sample.clone());
            }

            if let Err(e) = app.emit("metric:tick", &sample) {
                tracing::warn!(target: "sampler", error = %e, "failed to emit metric:tick");
            }
        }
    });
}

async fn bounded_ping(host: Option<&str>) -> Option<f32> {
    let host = host?;
    match timeout(PROBE_BUDGET, ping(host, 1)).await {
        Ok(v) => v,
        Err(_) => None,
    }
}

async fn bounded_dns(host: &str) -> Option<f32> {
    match timeout(PROBE_BUDGET, dns_resolve_ms(host)).await {
        Ok(v) => v,
        Err(_) => None,
    }
}
