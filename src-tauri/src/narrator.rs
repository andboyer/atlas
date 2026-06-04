//! Causal narrator — auto-explains anomalies surfaced in the live ring.
//!
//! Watches the live sampler ring buffer at ~5 s cadence. When a problem
//! emerges (latency spike, link drop, RSSI cliff, sustained DNS slowness),
//! constructs:
//!
//! 1. a deterministic heuristic narrative grounded in the actual samples
//!    + recent `wifi:event`s, available immediately, no network round-trip,
//! 2. *optionally*, a richer LLM-generated summary if the user has
//!    configured a provider — appended to the same `Narrative` once it
//!    returns.
//!
//! Each narrative is dedup'd against the trailing 5 minutes by `trigger`
//! so a single 30 s slow patch only produces one card, not 30. The card is
//! pushed onto a small ring (50) accessible via `get_narratives` and emitted
//! as a `narrative:new` Tauri event for the frontend.

use crate::sampler::LiveRing;
use crate::settings::Settings;
use crate::types::{LiveSample, Narrative, WifiEvent};
use crate::wifi_events::EventRing;
use chrono::{DateTime, Duration, Utc};
use parking_lot::RwLock;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::{AppHandle, Emitter};
use uuid::Uuid;

pub const RING_CAPACITY: usize = 50;
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
/// Suppress duplicate triggers within this window.
const DEDUP_WINDOW: Duration = Duration::minutes(5);
/// Need this many samples in the ring before we'll even attempt detection.
const MIN_SAMPLES: usize = 30;

pub type NarrativeRing = Arc<RwLock<VecDeque<Narrative>>>;

pub struct NarratorHandle {
    pub running: Arc<AtomicBool>,
    pub ring: NarrativeRing,
}

impl NarratorHandle {
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

pub fn start(
    app: AppHandle,
    live_ring: LiveRing,
    wifi_ring: EventRing,
    settings_path: PathBuf,
) -> NarratorHandle {
    let running = Arc::new(AtomicBool::new(true));
    let ring: NarrativeRing = Arc::new(RwLock::new(VecDeque::with_capacity(RING_CAPACITY)));
    let ring_for_task = Arc::clone(&ring);
    let running_for_task = Arc::clone(&running);

    tokio::spawn(async move {
        tracing::info!(target: "narrator", "causal narrator started");
        loop {
            tokio::time::sleep(POLL_INTERVAL).await;
            if !running_for_task.load(Ordering::Relaxed) {
                break;
            }

            let samples: Vec<LiveSample> = live_ring.read().iter().cloned().collect();
            if samples.len() < MIN_SAMPLES {
                continue;
            }

            let wifi_events: Vec<WifiEvent> = wifi_ring.read().iter().cloned().collect();

            let triggers = detect_triggers(&samples);
            for trig in triggers {
                // Suppress if we already emitted this trigger recently.
                {
                    let r = ring_for_task.read();
                    let cutoff = Utc::now() - DEDUP_WINDOW;
                    if r.iter().any(|n| n.trigger == trig.trigger && n.at > cutoff) {
                        continue;
                    }
                }

                let narrative = build_heuristic_narrative(&trig, &samples, &wifi_events);

                // Push to ring + emit immediately so the UI gets the
                // heuristic instantly.
                push_and_emit(&ring_for_task, &app, narrative.clone());

                // Optional LLM enrichment in the background.
                if let Ok(settings) = Settings::load(&settings_path) {
                    if let Some(provider) = settings.llm_provider.as_deref() {
                        let provider = provider.to_string();
                        let api_key = settings.llm_api_key.unwrap_or_default();
                        let model = settings.llm_model.unwrap_or_default();
                        let base_url = settings.llm_base_url.clone();
                        let needs_key = provider != "ollama";
                        let configured = !provider.is_empty()
                            && !model.is_empty()
                            && (!needs_key || !api_key.is_empty());
                        if configured {
                            let id = narrative.id.clone();
                            let prompt = build_llm_prompt(&trig, &samples, &wifi_events);
                            let ring_clone = Arc::clone(&ring_for_task);
                            let app_clone = app.clone();
                            tokio::spawn(async move {
                                let messages = vec![crate::llm::ChatMessage {
                                    role: "user".to_string(),
                                    content: prompt,
                                }];
                                let reply = crate::llm::dispatch_public(
                                    &provider,
                                    &api_key,
                                    &model,
                                    base_url.as_deref(),
                                    &messages,
                                )
                                .await;
                                if let Ok(text) = reply {
                                    let trimmed = text.trim().to_string();
                                    if trimmed.is_empty() {
                                        return;
                                    }
                                    let mut found = None;
                                    {
                                        let mut r = ring_clone.write();
                                        for n in r.iter_mut() {
                                            if n.id == id {
                                                n.llm_summary = Some(trimmed.clone());
                                                n.source = "heuristic+llm".to_string();
                                                found = Some(n.clone());
                                                break;
                                            }
                                        }
                                    }
                                    if let Some(updated) = found {
                                        let _ = app_clone.emit("narrative:update", &updated);
                                    }
                                } else if let Err(e) = reply {
                                    tracing::debug!(target: "narrator", error = %e, "LLM enrichment failed");
                                }
                            });
                        }
                    }
                }
            }
        }
        tracing::info!(target: "narrator", "causal narrator stopped");
    });

    NarratorHandle { running, ring }
}

fn push_and_emit(ring: &NarrativeRing, app: &AppHandle, narrative: Narrative) {
    {
        let mut r = ring.write();
        if r.len() == RING_CAPACITY {
            r.pop_front();
        }
        r.push_back(narrative.clone());
    }
    if let Err(e) = app.emit("narrative:new", &narrative) {
        tracing::debug!(target: "narrator", error = %e, "emit narrative:new failed");
    }
}

// ─── Trigger detection ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Trigger {
    trigger: String,
    severity: String,
    headline: String,
    /// Time the trigger fired (UTC).
    at: DateTime<Utc>,
}

/// Inspect the most recent samples and return any triggers worth narrating.
/// The detection windows are tuned for a 1 Hz sampler.
fn detect_triggers(samples: &[LiveSample]) -> Vec<Trigger> {
    let mut out = Vec::new();

    // 1) Link drop: the most recent 3 samples are all `link_up=false`.
    let tail = &samples[samples.len().saturating_sub(3)..];
    if tail.len() >= 3 && tail.iter().all(|s| !s.link_up) {
        out.push(Trigger {
            trigger: "link_drop".to_string(),
            severity: "critical".to_string(),
            headline: "The connection dropped — no replies from gateway or internet.".to_string(),
            at: tail.last().unwrap().ts,
        });
        // No point chaining lesser triggers on a hard drop.
        return out;
    }

    // Helpers operating on the last 5s window vs the prior 60s baseline.
    fn recent_avg(
        samples: &[LiveSample],
        n: usize,
        pick: impl Fn(&LiveSample) -> Option<f32>,
    ) -> Option<f32> {
        let xs: Vec<f32> = samples.iter().rev().filter_map(&pick).take(n).collect();
        if xs.is_empty() {
            None
        } else {
            Some(xs.iter().sum::<f32>() / xs.len() as f32)
        }
    }
    fn baseline(
        samples: &[LiveSample],
        skip: usize,
        take: usize,
        pick: impl Fn(&LiveSample) -> Option<f32>,
    ) -> Option<f32> {
        let xs: Vec<f32> = samples
            .iter()
            .rev()
            .filter_map(&pick)
            .skip(skip)
            .take(take)
            .collect();
        if xs.is_empty() {
            None
        } else {
            Some(xs.iter().sum::<f32>() / xs.len() as f32)
        }
    }

    let now_ts = samples.last().unwrap().ts;

    // 2) Latency spike on gateway sustained for >=3s.
    if let (Some(recent), Some(base)) = (
        recent_avg(samples, 5, |s| s.gateway_ms),
        baseline(samples, 5, 60, |s| s.gateway_ms),
    ) {
        if recent > base + 40.0 && recent > 60.0 {
            out.push(Trigger {
                trigger: "gateway_spike".to_string(),
                severity: if recent > 200.0 {
                    "critical".to_string()
                } else {
                    "warn".to_string()
                },
                headline: format!(
                    "Gateway latency spiked to {:.0} ms (baseline {:.0} ms).",
                    recent, base
                ),
                at: now_ts,
            });
        }
    }

    // 3) Internet latency spike.
    if let (Some(recent), Some(base)) = (
        recent_avg(samples, 5, |s| s.internet_ms),
        baseline(samples, 5, 60, |s| s.internet_ms),
    ) {
        if recent > base + 80.0 && recent > 120.0 {
            out.push(Trigger {
                trigger: "internet_spike".to_string(),
                severity: if recent > 300.0 {
                    "critical".to_string()
                } else {
                    "warn".to_string()
                },
                headline: format!(
                    "Internet round-trip jumped to {:.0} ms (baseline {:.0} ms).",
                    recent, base
                ),
                at: now_ts,
            });
        }
    }

    // 4) DNS slowdown.
    if let (Some(recent), Some(base)) = (
        recent_avg(samples, 5, |s| s.dns_ms),
        baseline(samples, 5, 60, |s| s.dns_ms),
    ) {
        if recent > base + 50.0 && recent > 100.0 {
            out.push(Trigger {
                trigger: "dns_slow".to_string(),
                severity: "warn".to_string(),
                headline: format!(
                    "DNS resolves taking {:.0} ms (baseline {:.0} ms).",
                    recent, base
                ),
                at: now_ts,
            });
        }
    }

    // 5) RSSI cliff: dropped >=10 dBm over the last 30s vs the prior minute.
    let rssi_recent = recent_avg(samples, 10, |s| s.rssi_dbm.map(|v| v as f32));
    let rssi_base = baseline(samples, 30, 60, |s| s.rssi_dbm.map(|v| v as f32));
    if let (Some(r), Some(b)) = (rssi_recent, rssi_base) {
        let delta = b - r; // positive => degraded (more negative dBm)
        if delta >= 10.0 && r < -65.0 {
            out.push(Trigger {
                trigger: "rssi_drop".to_string(),
                severity: if r < -80.0 {
                    "critical".to_string()
                } else {
                    "warn".to_string()
                },
                headline: format!(
                    "Signal dropped {:.0} dB (now {:.0} dBm, was {:.0} dBm).",
                    delta, r, b
                ),
                at: now_ts,
            });
        }
    }

    out
}

// ─── Narrative construction ─────────────────────────────────────────────────

fn build_heuristic_narrative(
    trig: &Trigger,
    samples: &[LiveSample],
    wifi_events: &[WifiEvent],
) -> Narrative {
    let recent_wifi: Vec<&WifiEvent> = wifi_events
        .iter()
        .rev()
        .take_while(|e| trig.at - e.ts <= Duration::minutes(2))
        .take(8)
        .collect();

    let (likely_cause, what_to_try) = match trig.trigger.as_str() {
        "link_drop" => link_drop_explanation(samples, &recent_wifi),
        "gateway_spike" => gateway_spike_explanation(samples, &recent_wifi),
        "internet_spike" => internet_spike_explanation(samples, &recent_wifi),
        "dns_slow" => dns_slow_explanation(),
        "rssi_drop" => rssi_drop_explanation(&recent_wifi),
        _ => (
            "Unclassified anomaly.".to_string(),
            vec!["Re-run a quick scan to capture more context.".to_string()],
        ),
    };

    let what_happened = describe_what_happened(trig, samples, &recent_wifi);

    Narrative {
        id: Uuid::new_v4().to_string(),
        at: trig.at,
        severity: trig.severity.clone(),
        trigger: trig.trigger.clone(),
        headline: trig.headline.clone(),
        what_happened,
        likely_cause,
        what_to_try,
        source: "heuristic".to_string(),
        llm_summary: None,
    }
}

fn describe_what_happened(
    trig: &Trigger,
    samples: &[LiveSample],
    wifi_events: &[&WifiEvent],
) -> String {
    let mut parts = Vec::new();
    let last = samples.last().unwrap();
    parts.push(format!(
        "At {}, the sampler observed: gateway {} ms, internet {} ms, DNS {} ms, RSSI {} dBm.",
        last.ts.format("%H:%M:%S"),
        fmt_f(last.gateway_ms),
        fmt_f(last.internet_ms),
        fmt_f(last.dns_ms),
        last.rssi_dbm
            .map(|v| v.to_string())
            .unwrap_or_else(|| "—".to_string()),
    ));
    if !wifi_events.is_empty() {
        let kinds: Vec<String> = wifi_events.iter().map(|e| e.kind.clone()).collect();
        parts.push(format!("Recent Wi-Fi system events: {}.", kinds.join(", ")));
    }
    parts.push(format!(
        "Trigger fired: `{}` ({} severity).",
        trig.trigger, trig.severity
    ));
    parts.join(" ")
}

fn link_drop_explanation(
    samples: &[LiveSample],
    wifi_events: &[&WifiEvent],
) -> (String, Vec<String>) {
    let mut steps = vec![
        "Confirm the AP is powered and broadcasting (look for the SSID on another device)."
            .to_string(),
        "Toggle Wi-Fi off and on once to force a fresh association.".to_string(),
        "If the AP is up but you can't see the SSID, move closer or check the radio configuration."
            .to_string(),
    ];
    let mut cause = "All probes are failing — Wi-Fi is associated but the data path is broken, or the radio is no longer associated.".to_string();
    if wifi_events
        .iter()
        .any(|e| e.kind == "deauth" || e.kind == "disassoc")
    {
        cause = "Wi-Fi was just deauth/disassociated by the AP. This often follows a roam decision, AP reboot, or RADIUS failure.".to_string();
        steps.insert(
            0,
            "Check the AP for recent reboots or RADIUS / 802.1X failures in its log.".to_string(),
        );
    }
    if let Some(last) = samples.last() {
        if last.rssi_dbm.map(|v| v < -85).unwrap_or(false) {
            cause.push_str(" Signal is also very weak (< -85 dBm).");
        }
    }
    (cause, steps)
}

fn gateway_spike_explanation(
    samples: &[LiveSample],
    wifi_events: &[&WifiEvent],
) -> (String, Vec<String>) {
    let last = samples.last().unwrap();
    let mut cause = "Latency to the AP/router climbed but the internet hop is still responsive — this is a Wi-Fi / LAN problem, not WAN.".to_string();
    let mut steps = vec![
        "Run a Ping Flood test to confirm sustained jitter or loss to the gateway.".to_string(),
        "Move closer to the AP and re-test; verify the channel isn't congested in the Airspace tab.".to_string(),
        "Reboot the AP if it has been running for more than 30 days.".to_string(),
    ];
    if let Some(internet) = last.internet_ms {
        if let Some(gw) = last.gateway_ms {
            if internet < gw + 5.0 {
                cause = "Internet hop is no faster than the gateway hop — the AP itself or its uplink (cabling, switch port) is the bottleneck.".to_string();
            }
        }
    }
    if wifi_events.iter().any(|e| e.kind == "roam") {
        cause.push_str(" A Wi-Fi roam happened just before the spike — the new BSSID may be congested or poorly placed.");
        steps.push(
            "In the Airspace tab, verify the new BSSID's channel and signal vs. the previous one."
                .to_string(),
        );
    }
    if last.rssi_dbm.map(|v| v < -72).unwrap_or(false) {
        steps.insert(1, "Signal is weak (< -72 dBm); MAC-layer retries inflate latency. Move closer or add an AP.".to_string());
    }
    (cause, steps)
}

fn internet_spike_explanation(
    samples: &[LiveSample],
    _wifi_events: &[&WifiEvent],
) -> (String, Vec<String>) {
    let last = samples.last().unwrap();
    let mut cause = "Round-trip to 1.1.1.1 is elevated while the gateway is stable — the slowdown is on your ISP / upstream path, not your LAN.".to_string();
    if let (Some(internet), Some(gw)) = (last.internet_ms, last.gateway_ms) {
        if gw > 60.0 {
            cause = "Both gateway and internet latency are elevated — the bottleneck is the LAN/Wi-Fi side, the WAN inherits its slowness.".to_string();
        } else {
            cause = format!(
                "Gateway is fine ({:.0} ms) but internet path is {:.0} ms — the slowdown is upstream of your router.",
                gw, internet
            );
        }
    }
    let steps = vec![
        "Run a WAN saturation test to confirm parallel-request slowdown.".to_string(),
        "Check your modem's status page for signal/SNR errors and recent reboots.".to_string(),
        "If repeated, file a ticket with your ISP citing the timestamps in this card.".to_string(),
    ];
    (cause, steps)
}

fn dns_slow_explanation() -> (String, Vec<String>) {
    (
        "DNS resolves are slow relative to the gateway path — either your configured resolver is overloaded or your DHCP-pushed DNS is throttled.".to_string(),
        vec![
            "Run a DNS Burst test to see if it's a single resolver or multiple.".to_string(),
            "Try a public resolver (1.1.1.1 or 8.8.8.8) temporarily to isolate the resolver from the network.".to_string(),
            "If the issue persists across resolvers, check for a captive portal or DNS-blocking firewall on the LAN.".to_string(),
        ],
    )
}

fn rssi_drop_explanation(wifi_events: &[&WifiEvent]) -> (String, Vec<String>) {
    let mut cause = "Signal strength fell sharply — the device moved away from the AP, the AP power output dropped, or a new obstacle came between them.".to_string();
    if wifi_events.iter().any(|e| e.kind == "roam") {
        cause = "Signal dropped right after a roam — the new BSSID is in a worse RF spot than the previous one.".to_string();
    }
    let steps = vec![
        "Move closer to the AP and re-check the chart to confirm signal recovers.".to_string(),
        "If the room hasn't moved, check the AP for power-save / TX-power changes (firmware tweaks, mesh mode).".to_string(),
        "Run a channel scan; the AP may have switched to a higher band (lower TX range) or DFS channel.".to_string(),
    ];
    (cause, steps)
}

fn fmt_f(v: Option<f32>) -> String {
    match v {
        Some(x) => format!("{x:.0}"),
        None => "—".to_string(),
    }
}

// ─── LLM enrichment prompt ──────────────────────────────────────────────────

fn build_llm_prompt(trig: &Trigger, samples: &[LiveSample], wifi_events: &[WifiEvent]) -> String {
    let mut lines = vec![
        "You are an expert network engineer. The user's local diagnostic tool detected a Wi-Fi anomaly. \
         Below is the live telemetry and recent Wi-Fi system events around the anomaly. \
         Reply with a single short paragraph (3 sentences max) explaining the most likely cause and the *single* most useful next step. \
         Do not repeat the headline."
            .to_string(),
        String::new(),
        format!("## Trigger\n{} ({} severity)\n{}", trig.trigger, trig.severity, trig.headline),
        String::new(),
        "## Last 30 seconds of telemetry (oldest → newest)".to_string(),
    ];

    let tail = &samples[samples.len().saturating_sub(30)..];
    for s in tail {
        lines.push(format!(
            "{}  gw={}  inet={}  dns={}  rssi={}  link_up={}",
            s.ts.format("%H:%M:%S"),
            fmt_f(s.gateway_ms),
            fmt_f(s.internet_ms),
            fmt_f(s.dns_ms),
            s.rssi_dbm
                .map(|v| v.to_string())
                .unwrap_or_else(|| "—".to_string()),
            s.link_up,
        ));
    }

    if !wifi_events.is_empty() {
        lines.push(String::new());
        lines.push("## Recent Wi-Fi system events (newest first)".to_string());
        for e in wifi_events.iter().rev().take(10) {
            lines.push(format!(
                "{}  [{}]  {}",
                e.ts.format("%H:%M:%S"),
                e.kind,
                truncate(&e.message, 140)
            ));
        }
    }

    lines.join("\n")
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(
        ts: DateTime<Utc>,
        gw: Option<f32>,
        inet: Option<f32>,
        dns: Option<f32>,
        rssi: Option<i32>,
        up: bool,
    ) -> LiveSample {
        LiveSample {
            ts,
            rssi_dbm: rssi,
            snr_db: None,
            tx_rate_mbps: None,
            gateway_ms: gw,
            internet_ms: inet,
            dns_ms: dns,
            link_up: up,
        }
    }

    fn good_baseline(count: usize) -> Vec<LiveSample> {
        let now = Utc::now();
        (0..count)
            .map(|i| {
                sample(
                    now - Duration::seconds((count - i) as i64),
                    Some(3.0),
                    Some(20.0),
                    Some(15.0),
                    Some(-55),
                    true,
                )
            })
            .collect()
    }

    #[test]
    fn detects_link_drop() {
        let mut s = good_baseline(60);
        // Override last 3 to link-down.
        for i in s.len() - 3..s.len() {
            s[i].link_up = false;
            s[i].gateway_ms = None;
            s[i].internet_ms = None;
            s[i].dns_ms = None;
        }
        let triggers = detect_triggers(&s);
        assert!(triggers.iter().any(|t| t.trigger == "link_drop"));
    }

    #[test]
    fn detects_gateway_spike() {
        let mut s = good_baseline(120);
        for i in s.len() - 5..s.len() {
            s[i].gateway_ms = Some(150.0);
        }
        let triggers = detect_triggers(&s);
        assert!(triggers.iter().any(|t| t.trigger == "gateway_spike"));
    }

    #[test]
    fn quiet_baseline_no_triggers() {
        let s = good_baseline(120);
        let triggers = detect_triggers(&s);
        assert!(triggers.is_empty(), "got: {:?}", triggers);
    }
}
