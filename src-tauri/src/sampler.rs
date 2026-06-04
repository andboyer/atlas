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
use crate::probes::reachability::{
    default_gateway_for_iface, dns_resolve_ms, ping_via,
};
use crate::settings::Settings;
use crate::types::{LinkStats, LiveSample};
use chrono::Utc;
use parking_lot::RwLock;
use std::collections::VecDeque;
use std::path::PathBuf;
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
///
/// `settings_path` is consulted by the gateway refresher every 30 s so a
/// change to the global NIC pin from the header propagates to the live
/// 1 Hz metrics within that window — no app restart required.
pub fn start_sampler(app: AppHandle, settings_path: PathBuf) -> SamplerHandle {
    let running = Arc::new(AtomicBool::new(true));
    let ring: LiveRing = Arc::new(RwLock::new(VecDeque::with_capacity(RING_CAPACITY)));

    let link_snap: Arc<RwLock<Option<LinkStats>>> = Arc::new(RwLock::new(None));
    spawn_link_refresher(Arc::clone(&link_snap), Arc::clone(&running));

    let gateway_ip: Arc<RwLock<Option<String>>> = Arc::new(RwLock::new(None));
    let pinned_iface: Arc<RwLock<Option<String>>> = Arc::new(RwLock::new(None));
    spawn_gateway_refresher(
        Arc::clone(&gateway_ip),
        Arc::clone(&pinned_iface),
        settings_path,
        Arc::clone(&running),
    );

    spawn_tick(
        app,
        Arc::clone(&ring),
        link_snap,
        gateway_ip,
        pinned_iface,
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

fn spawn_gateway_refresher(
    gateway_snap: Arc<RwLock<Option<String>>>,
    iface_snap: Arc<RwLock<Option<String>>>,
    settings_path: PathBuf,
    running: Arc<AtomicBool>,
) {
    tokio::spawn(async move {
        // Re-read settings every 30 s so changing the global NIC pick
        // from the header propagates without an app restart. The 30 s
        // window matches the gateway-IP refresh cadence (re-resolving
        // both at once keeps them in sync — switching NIC implies the
        // gateway IP changes too).
        async fn refresh(
            gw: &Arc<RwLock<Option<String>>>,
            iface: &Arc<RwLock<Option<String>>>,
            path: &PathBuf,
        ) {
            let pinned = Settings::load(path)
                .ok()
                .map(|s| s.preferred_interface.trim().to_string())
                .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("auto"));
            *iface.write() = pinned.clone();
            if let Some(ip) = default_gateway_for_iface(pinned.as_deref()).await {
                *gw.write() = Some(ip);
            }
        }

        // First refresh immediately so the first few ticks have a gateway.
        refresh(&gateway_snap, &iface_snap, &settings_path).await;
        while running.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_secs(30)).await;
            if !running.load(Ordering::Relaxed) {
                break;
            }
            refresh(&gateway_snap, &iface_snap, &settings_path).await;
        }
        tracing::debug!(target: "sampler", "gateway refresher stopped");
    });
}

fn spawn_tick(
    app: AppHandle,
    ring: LiveRing,
    link_snap: Arc<RwLock<Option<LinkStats>>>,
    gateway_ip: Arc<RwLock<Option<String>>>,
    pinned_iface: Arc<RwLock<Option<String>>>,
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
            let iface = pinned_iface.read().clone();
            let (gw_ms, inet_ms, dns_ms) = tokio::join!(
                bounded_ping_via(gw_ip.as_deref(), iface.as_deref()),
                bounded_ping_via(Some("1.1.1.1"), iface.as_deref()),
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

async fn bounded_ping_via(host: Option<&str>, iface: Option<&str>) -> Option<f32> {
    let host = host?;
    match timeout(PROBE_BUDGET, ping_via(host, 1, iface)).await {
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
