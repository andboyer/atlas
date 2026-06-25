use crate::collectors::default_collector;
use crate::detect::{self, AnomalySignal, Context};
use crate::settings::Settings;
use crate::store::{DeviceEvent, IncidentCorrelation, MetricSample, ScanSummary, Store};
use crate::types::{
    AvDiagnosticsResult, DeepProbeResult, DeviceClass, DeviceInfo, IgmpProbeResult, PtpProbeResult,
    ScanResult, StressTestResult,
};
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tauri::State;
use tokio::time::{timeout, Duration};
use uuid::Uuid;

/// Hard cap on the total quick scan. If any probe hangs past this, the
/// command returns an error instead of leaving the UI spinning forever.
const QUICK_SCAN_BUDGET: Duration = Duration::from_secs(45);

/// Per-probe timeout. Each probe should already self-bound, but we wrap
/// them defensively so a single misbehaving probe can't sink the join.
/// 25 s gives the macOS `networkQuality` bufferbloat probe (which itself
/// self-bounds at 18 s) some headroom — at 20 s it would race the inner
/// timeout and silently drop the result on slow links.
const PROBE_TIMEOUT: Duration = Duration::from_secs(25);

async fn timed<T, F>(label: &'static str, fut: F) -> Option<T>
where
    F: std::future::Future<Output = T>,
{
    let started = Instant::now();
    let res = timeout(PROBE_TIMEOUT, fut).await;
    let elapsed_ms = started.elapsed().as_millis();
    match res {
        Ok(v) => {
            tracing::info!(target: "scan", probe = label, elapsed_ms, "probe ok");
            Some(v)
        }
        Err(_) => {
            tracing::warn!(target: "scan", probe = label, elapsed_ms, "probe timed out");
            None
        }
    }
}

pub struct AppState {
    pub store: Store,
    pub settings_path: PathBuf,
    /// Stop signal for the active monitoring task (None if not running).
    pub monitor_handle: Mutex<Option<Arc<AtomicBool>>>,
    /// Handle to the live 1 Hz sampler (started/stopped alongside the
    /// monitor). `None` when the sampler isn't running.
    pub sampler_handle: Mutex<Option<crate::sampler::SamplerHandle>>,
    /// Handle to the macOS Wi-Fi event subscriber (`log stream` tail).
    pub wifi_events_handle: Mutex<Option<crate::wifi_events::WifiEventsHandle>>,
    /// Handle to the causal narrator (watches the sampler ring for anomalies).
    pub narrator_handle: Mutex<Option<crate::narrator::NarratorHandle>>,
    /// Most recent AV-over-IP diagnostics result, populated whenever
    /// `run_av_diagnostics` is invoked. Used by `export_report` so the
    /// printed report carries Dante / multicast / heuristic warnings even
    /// though the AV sweep runs on-demand outside the scan pipeline.
    pub last_av_diagnostics: Mutex<Option<AvDiagnosticsResult>>,
    /// Most recent deep-probe result (IGMP / PTP / DSCP / LLDP / link
    /// audit / SAP), populated by `run_deep_probes`. Each call merges its
    /// populated field into this cache so the report can show every probe
    /// the operator has ever run during this session.
    pub last_deep_probe: Mutex<Option<DeepProbeResult>>,
    /// Ring of recent stress-test results (most recent first, capped at 20),
    /// populated by `run_stress_test`. Included in the exported report so
    /// the operator can show "here's the active stress evidence I captured".
    pub recent_stress_results: Mutex<Vec<StressTestResult>>,
    // ── Phase 2-6: device-execution subsystem ────────────────────────────
    /// Inventory file path (`<app-data>/hosts.toml`). Mutated in place by
    /// `upsert_host` / `delete_host` and re-read by the engine before
    /// every runbook execution to pick up changes without a restart.
    pub inventory: Arc<Mutex<crate::device::inventory::Inventory>>,
    pub inventory_path: PathBuf,
    /// In-memory skill pack registry. Read-only after process start
    /// (packs are embedded in the binary via `include_str!`).
    pub packs: crate::device::pack::PackRegistry,
    /// Append-only audit log of every `device.exec` invocation.
    pub audit: crate::device::audit::Audit,
    /// Approval centre for `Mutate` / `Dangerous` commands.
    pub approval: crate::device::approval::ApprovalCenter,
    /// User runbooks directory (`<app-data>/runbooks/`).
    pub user_runbooks_dir: PathBuf,
}

#[tauri::command]
pub async fn run_quick_scan(state: State<'_, AppState>) -> Result<ScanResult, String> {
    let started_at = Utc::now();
    let scan_started = Instant::now();
    tracing::info!(target: "scan", "quick scan starting");

    let scan = async {
        let collector = default_collector();
        let link = timed("link_stats", collector.link_stats())
            .await
            .ok_or_else(|| "link_stats timed out".to_string())?
            .map_err(|e| format!("link_stats: {e}"))?;
        let mut link = link;
        // Pin reachability to the operator's selected NIC so the gateway
        // tile reflects that NIC's next-hop instead of whichever default
        // route currently wins the kernel's metric tie-break.
        let pinned_iface = resolved_iface(&state, None);
        let reach = timed(
            "reachability",
            collector.reachability(pinned_iface.as_deref()),
        )
        .await
        .ok_or_else(|| "reachability timed out".to_string())?
        .map_err(|e| format!("reachability: {e}"))?;

        // Load settings to drive profile-specific behaviour.
        let settings = Settings::load(&state.settings_path).unwrap_or_default();
        let profile = profile_hints_from(&settings);
        let targets = effective_targets(&settings);

        // LAN discovery + all active probes run concurrently, each individually time-bounded.
        //
        // NOTE: the bufferbloat / `networkQuality` probe takes ~40-50 s and
        // would dominate the quick-scan budget, so it lives on its own
        // command (`run_quality_test`) driven by the panel's Run-test button.
        let (
            devices_opt,
            services_opt,
            captive_opt,
            dns_leak_opt,
            mtu_opt,
            nearby_opt,
            speed_opt,
            wan_opt,
        ) = tokio::join!(
            timed("discover", crate::discovery::scan::discover_and_probe()),
            timed(
                "services",
                crate::probes::services::probe_services(&targets)
            ),
            timed("captive", crate::probes::captive::is_captive_portal()),
            timed("dns_leak", crate::probes::dns_leak::is_dns_leak()),
            timed("mtu", crate::probes::mtu::discover_mtu()),
            timed("channel_scan", crate::probes::channel_scan::scan_nearby()),
            timed(
                "speed_test",
                crate::probes::speed_test::measure_download_mbps()
            ),
            timed("wan", crate::probes::wan::probe_wan()),
        );

        let mut devices = devices_opt.unwrap_or_default();
        let services = services_opt.unwrap_or_default();
        let captive_portal = captive_opt.unwrap_or(false);
        let dns_leak = dns_leak_opt.unwrap_or(false);
        let mtu_bytes = mtu_opt.flatten();
        let mut nearby_aps = nearby_opt.unwrap_or_default();
        let speed_mbps = speed_opt.flatten();
        let quality: Option<crate::types::QualityStats> = None;
        let wan = wan_opt.flatten();

        // OUI vendor lookup for every visible AP and our own link.
        for ap in &mut nearby_aps {
            if let Some(bssid) = ap.bssid.as_deref() {
                ap.vendor = crate::oui::lookup(bssid).map(str::to_string);
            }
        }
        link.vendor = link
            .bssid
            .as_deref()
            .and_then(crate::oui::lookup)
            .map(str::to_string);
        link.wifi_generation =
            crate::wifi_gen::wifi_generation(link.phy_mode.as_deref(), link.band.as_deref());

        if devices.is_empty() {
            devices = demo_devices();
        }

        // Anomaly detection reads from persisted samples (empty on first scan).
        let anomalies: Vec<AnomalySignal> = detect::anomaly::compute_anomalies(&state.store);

        let findings = detect::evaluate(&Context {
            link: &link,
            reach: &reach,
            devices: &devices,
            services: &services,
            profile,
            anomalies,
            captive_portal,
            dns_leak,
            mtu_bytes,
            nearby_aps: nearby_aps.clone(),
            speed_mbps,
        });
        let recommendations = detect::collect_recommendations(&findings);

        // ── Post-process advanced analytics ──
        //
        // These computations are pure functions of the scan we just built, so
        // we keep them outside the lifetime-parameterised `Context` (which
        // would force a wider re-sweep through the detection rules). They
        // produce structured side-panels the UI renders separately from the
        // primary findings list.
        let interference = Some(crate::probes::interference::build_report(
            &nearby_aps,
            link.channel,
        ));
        let phy_efficiency = crate::probes::phy_efficiency::evaluate(&link);
        let rogue_aps = crate::probes::rogue::detect(&nearby_aps);

        // BSSID-change roaming detection: compare current link.bssid to the
        // most-recent persisted scan's BSSID on the SAME ssid; record an event
        // when the BSSID changed. Same-SSID guard avoids false positives when
        // the user manually switches networks.
        if let (Some(cur_bssid), Some(cur_ssid)) = (link.bssid.as_ref(), link.ssid.as_ref()) {
            if let Ok(Some((prev_ssid, prev_bssid))) = state.store.last_link_identity() {
                if prev_ssid.as_deref() == Some(cur_ssid.as_str())
                    && prev_bssid.is_some()
                    && prev_bssid.as_deref() != Some(cur_bssid.as_str())
                {
                    let evt = crate::types::RoamingEvent {
                        at: Utc::now(),
                        ssid: Some(cur_ssid.clone()),
                        from_bssid: prev_bssid.clone(),
                        to_bssid: Some(cur_bssid.clone()),
                        rssi_at_roam_dbm: link.rssi_dbm,
                    };
                    if let Err(e) = state.store.record_roaming_event(&evt) {
                        tracing::warn!(target: "scan", error = %e, "failed to persist roaming event");
                    }
                }
            }
        }

        // Summarise roaming history for the UI/LLM.
        let roaming = {
            let day_ago = Utc::now() - chrono::Duration::hours(24);
            match state.store.roaming_events_since(day_ago) {
                Ok(events) => Some(crate::probes::roaming::summarise(&events, &link)),
                Err(e) => {
                    tracing::warn!(target: "scan", error = %e, "failed to load roaming history");
                    None
                }
            }
        };

        // Trend deltas vs previous-hour metric samples (best-effort, may be None on first scan).
        let trends = crate::detect::trends::build_report(&state.store, &link, &reach);
        let alternate_ap = crate::wifi_gen::alternate_ap(&link, &nearby_aps);

        let result = ScanResult {
            run_id: Uuid::new_v4().to_string(),
            started_at,
            finished_at: Utc::now(),
            link,
            reachability: reach,
            devices,
            findings,
            recommendations,
            service_reachability: services,
            captive_portal,
            dns_leak,
            mtu_bytes,
            nearby_aps,
            speed_mbps,
            quality,
            interference,
            phy_efficiency,
            roaming,
            rogue_aps,
            wan,
            trends,
            alternate_ap,
        };

        if let Err(e) = state.store.record_scan(&result) {
            tracing::warn!(target: "scan", error = %e, "failed to persist scan");
        }

        Ok::<ScanResult, String>(result)
    };

    match timeout(QUICK_SCAN_BUDGET, scan).await {
        Ok(Ok(result)) => {
            tracing::info!(
                target: "scan",
                elapsed_ms = scan_started.elapsed().as_millis(),
                "quick scan complete",
            );
            Ok(result)
        }
        Ok(Err(e)) => {
            tracing::error!(target: "scan", error = %e, "quick scan failed");
            Err(e)
        }
        Err(_) => {
            tracing::error!(
                target: "scan",
                budget_secs = QUICK_SCAN_BUDGET.as_secs(),
                "quick scan exceeded overall budget",
            );
            Err(format!(
                "quick scan exceeded {} s budget — see logs for which probe hung",
                QUICK_SCAN_BUDGET.as_secs()
            ))
        }
    }
}

/// Build the ProfileHints struct used by the detection engine from current Settings.
pub fn profile_hints_from(settings: &Settings) -> detect::ProfileHints {
    detect::ProfileHints {
        watchlist: settings.watchlist.clone(),
        service_high_latency_ms: crate::profiles::high_latency_threshold_ms(
            &settings.industry_profile,
        ),
    }
}

/// Return the list of `host:port` targets to probe, falling back to the
/// profile defaults if the user hasn't customised them.
pub fn effective_targets(settings: &Settings) -> Vec<String> {
    if !settings.pos_targets.is_empty() {
        settings.pos_targets.clone()
    } else {
        crate::profiles::default_targets_for(&settings.industry_profile)
    }
}

#[tauri::command]
pub async fn get_recent_scans(
    state: State<'_, AppState>,
    limit: Option<i64>,
) -> Result<Vec<ScanSummary>, String> {
    state
        .store
        .recent_scans(limit.unwrap_or(50))
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_device_events(
    state: State<'_, AppState>,
    mac: String,
    limit: Option<i64>,
) -> Result<Vec<DeviceEvent>, String> {
    state
        .store
        .device_events_for(&mac, limit.unwrap_or(100))
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_recent_device_events(
    state: State<'_, AppState>,
    limit: Option<i64>,
) -> Result<Vec<DeviceEvent>, String> {
    state
        .store
        .recent_device_events(limit.unwrap_or(100))
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_incident_correlation(
    state: State<'_, AppState>,
    at: String,
    window_secs: Option<i64>,
    exclude_mac: Option<String>,
) -> Result<IncidentCorrelation, String> {
    let parsed = DateTime::parse_from_rfc3339(&at)
        .map_err(|e| format!("invalid timestamp: {e}"))?
        .with_timezone(&Utc);
    state
        .store
        .correlate(parsed, window_secs.unwrap_or(120), exclude_mac.as_deref())
        .map_err(|e| e.to_string())
}

// ── Settings ─────────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn get_settings(state: State<'_, AppState>) -> Result<Settings, String> {
    Settings::load(&state.settings_path).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn update_settings(state: State<'_, AppState>, settings: Settings) -> Result<(), String> {
    settings
        .save(&state.settings_path)
        .map_err(|e| e.to_string())
}

// ── Monitoring ────────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn start_monitoring(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    let interval = Settings::load(&state.settings_path)
        .map_err(|e| e.to_string())?
        .scan_interval_secs;

    let handle = crate::monitor::start_monitoring(app.clone(), interval);
    *state.monitor_handle.lock() = Some(handle);

    // Start (or restart) the live 1 Hz sampler alongside the heavy monitor.
    // Replacing any existing handle implicitly stops the previous sampler
    // because `SamplerHandle::Drop` will be called and the inner tasks check
    // the `running` flag once per second.
    if let Some(prev) = state.sampler_handle.lock().take() {
        prev.stop();
    }
    let sampler = crate::sampler::start_sampler(app.clone(), state.settings_path.clone());
    let sampler_ring = sampler.ring.clone();
    *state.sampler_handle.lock() = Some(sampler);

    // Wi-Fi system event subscriber (macOS `log stream` tail). No-op on
    // other platforms.
    if let Some(prev) = state.wifi_events_handle.lock().take() {
        prev.stop();
    }
    let events = crate::wifi_events::start(app.clone());
    let events_ring = events.ring.clone();
    *state.wifi_events_handle.lock() = Some(events);

    // Causal narrator watches the sampler ring for anomalies and writes
    // narratives back into its own ring + emits `narrative:new` events.
    if let Some(prev) = state.narrator_handle.lock().take() {
        prev.stop();
    }
    let narrator =
        crate::narrator::start(app, sampler_ring, events_ring, state.settings_path.clone());
    *state.narrator_handle.lock() = Some(narrator);
    Ok(())
}

#[tauri::command]
pub async fn stop_monitoring(state: State<'_, AppState>) -> Result<(), String> {
    if let Some(handle) = state.monitor_handle.lock().take() {
        handle.store(false, Ordering::Relaxed);
    }
    if let Some(sampler) = state.sampler_handle.lock().take() {
        sampler.stop();
    }
    if let Some(events) = state.wifi_events_handle.lock().take() {
        events.stop();
    }
    if let Some(narrator) = state.narrator_handle.lock().take() {
        narrator.stop();
    }
    Ok(())
}

/// Lightweight status query so the UI can render a live indicator without
/// guessing from `settings.monitoring_enabled` (which can fall out of sync if
/// the backend was reset, the user toggled it in another window, etc.).
#[derive(serde::Serialize)]
pub struct MonitorStatus {
    pub running: bool,
    pub interval_secs: u64,
}

#[tauri::command]
pub async fn get_monitor_status(state: State<'_, AppState>) -> Result<MonitorStatus, String> {
    let running = state.monitor_handle.lock().is_some();
    let interval_secs = Settings::load(&state.settings_path)
        .map(|s| s.scan_interval_secs)
        .unwrap_or(15);
    Ok(MonitorStatus {
        running,
        interval_secs,
    })
}

/// Snapshot of the live sampler ring buffer (up to 3600 samples = 60 min @ 1 Hz).
/// Used by the frontend to seed its chart on mount; subsequent updates arrive
/// via the `metric:tick` Tauri event.
#[tauri::command]
pub async fn get_live_metrics(
    state: State<'_, AppState>,
) -> Result<Vec<crate::types::LiveSample>, String> {
    let guard = state.sampler_handle.lock();
    match guard.as_ref() {
        Some(h) => Ok(h.ring.read().iter().cloned().collect()),
        None => Ok(Vec::new()),
    }
}

/// Snapshot of the recent Wi-Fi system events captured by the macOS
/// `log stream` subscriber. Returns an empty list on platforms that don't
/// run a subscriber, or before the first event arrives.
#[tauri::command]
pub async fn get_wifi_events(
    state: State<'_, AppState>,
) -> Result<Vec<crate::types::WifiEvent>, String> {
    let guard = state.wifi_events_handle.lock();
    match guard.as_ref() {
        Some(h) => Ok(h.ring.read().iter().cloned().collect()),
        None => Ok(Vec::new()),
    }
}

#[derive(serde::Serialize)]
pub struct StressTestDescriptor {
    pub kind: String,
    pub label: String,
    pub description: String,
}

/// List the active stress tests that the UI can offer.
#[tauri::command]
pub async fn list_stress_tests() -> Result<Vec<StressTestDescriptor>, String> {
    Ok(crate::stress::list_kinds()
        .into_iter()
        .map(|(kind, label, description)| StressTestDescriptor {
            kind: kind.to_string(),
            label: label.to_string(),
            description: description.to_string(),
        })
        .collect())
}

/// Run a single stress test and return the final result. Live progress is
/// emitted on the `stress:tick` and `stress:complete` events.
#[tauri::command]
pub async fn run_stress_test(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    kind: String,
) -> Result<crate::types::StressTestResult, String> {
    // Pin the gateway-flood test to the operator's selected NIC so the
    // stress sample reflects that NIC's path. DNS / WAN tests are iface-
    // agnostic by design.
    let iface = resolved_iface(&state, None);
    let result = crate::stress::run(app, &kind, iface.as_deref()).await?;
    // Cache for the printable report. Keep most recent first, cap at 20.
    {
        let mut ring = state.recent_stress_results.lock();
        ring.insert(0, result.clone());
        if ring.len() > 20 {
            ring.truncate(20);
        }
    }
    Ok(result)
}

/// Snapshot of the causal-narrative ring buffer (auto-generated explanations
/// of detected anomalies).
#[tauri::command]
pub async fn get_narratives(
    state: State<'_, AppState>,
) -> Result<Vec<crate::types::Narrative>, String> {
    let guard = state.narrator_handle.lock();
    match guard.as_ref() {
        Some(h) => Ok(h.ring.read().iter().cloned().collect()),
        None => Ok(Vec::new()),
    }
}

/// Run the bufferbloat / responsiveness probe on demand. Returns a real
/// error reason on failure (binary missing, spawn error, non-zero exit,
/// parse failure, timeout) so the UI can show the actual cause instead of
/// a generic "didn't return a result".
#[tauri::command]
pub async fn run_quality_test() -> Result<crate::types::QualityStats, String> {
    crate::probes::quality::measure_quality_verbose().await
}

/// Run an IP-layer route trace from this host to `target` (default
/// `1.1.1.1`). Returns an empty vec on any failure so the UI can render
/// a clean "no hops resolved" state without having to inspect an error
/// code path. **L2 switches never appear here** — they're transparent
/// to IP and don't decrement TTL; the directly-attached switch, when
/// discoverable, surfaces via LLDP in the AV tab.
///
/// `iface` pins the trace to a specific NIC; when `None` we fall back
/// to `Settings.preferred_interface` (the global header pin). Honoured
/// on Unix via `traceroute -i <iface>` and on Windows via
/// `tracert -S <ipv4-of-iface>` (the closest equivalent that flag set
/// supports; routing-table override happens at the source-IP layer).
#[tauri::command]
pub async fn run_traceroute(
    state: State<'_, AppState>,
    target: Option<String>,
    iface: Option<String>,
) -> Result<Vec<crate::probes::traceroute::TraceHop>, String> {
    let target = target
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("1.1.1.1");
    let pinned = resolved_iface(&state, iface.as_deref());
    let cfg = crate::probes::traceroute::TraceConfig {
        iface: pinned,
        ..crate::probes::traceroute::TraceConfig::default()
    };
    Ok(crate::probes::traceroute::traceroute(target, cfg).await)
}

// ── LLM ──────────────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn explain_findings(
    state: State<'_, AppState>,
    scan_result: ScanResult,
) -> Result<String, String> {
    let settings = Settings::load(&state.settings_path).map_err(|e| e.to_string())?;

    let provider = settings.llm_provider.as_deref().unwrap_or("openai");
    let api_key = resolve_api_key(provider, settings.llm_api_key.clone())?;
    let model = settings
        .llm_model
        .clone()
        .unwrap_or_else(|| default_model(provider));
    let base_url = resolve_base_url(provider, settings.llm_base_url.clone());

    let history = collect_metric_history(&state.store);

    crate::llm::explain(
        provider,
        &api_key,
        &model,
        base_url.as_deref(),
        &scan_result,
        Some(&history),
    )
    .await
    .map_err(|e| e.to_string())
}

/// Ask the configured LLM to enumerate radio-specific issues and suggestions
/// for the latest scan. Returns raw JSON text: `{ "items": [...] }` (see
/// `llm::build_radio_prompt` for schema). The frontend parses + renders.
#[tauri::command]
pub async fn radio_insights(
    state: State<'_, AppState>,
    scan_result: ScanResult,
) -> Result<String, String> {
    let settings = Settings::load(&state.settings_path).map_err(|e| e.to_string())?;

    let provider = settings.llm_provider.as_deref().unwrap_or("openai");
    let api_key = resolve_api_key(provider, settings.llm_api_key.clone())?;
    let model = settings
        .llm_model
        .clone()
        .unwrap_or_else(|| default_model(provider));
    let base_url = resolve_base_url(provider, settings.llm_base_url.clone());

    crate::llm::radio_insights(
        provider,
        &api_key,
        &model,
        base_url.as_deref(),
        &scan_result,
    )
    .await
    .map_err(|e| e.to_string())
}

/// A user/assistant message for the chat history sent from the frontend.
#[derive(serde::Deserialize)]
pub struct FrontendChatMessage {
    pub role: String,
    pub content: String,
}

/// Snapshot the latest AV-over-IP diagnostics for LLM grounding, folding in
/// any on-demand deep-probe results (PTP / IGMP / DSCP / LLDP / SAP) captured
/// separately so the assistant sees the complete AV picture — not just the
/// base Dante/multicast scan. Returns `None` only when neither an AV scan nor
/// a deep probe has been run this session.
fn av_context_snapshot(state: &AppState) -> Option<AvDiagnosticsResult> {
    let mut av = state.last_av_diagnostics.lock().clone();
    let deep = state.last_deep_probe.lock().clone();
    match av.as_mut() {
        Some(av) if av.deep_probe.is_none() => av.deep_probe = deep,
        Some(_) => {}
        None if deep.is_some() => {
            av = Some(AvDiagnosticsResult {
                generated_at: chrono::Utc::now(),
                dante_devices: Vec::new(),
                ddm_seen: false,
                aes67_seen: false,
                multicast: Vec::new(),
                warnings: Vec::new(),
                deep_probe: deep,
            });
        }
        None => {}
    }
    av
}

#[tauri::command]
pub async fn chat_query(
    state: State<'_, AppState>,
    scan_result: ScanResult,
    history: Vec<FrontendChatMessage>,
    question: String,
) -> Result<String, String> {
    let settings = Settings::load(&state.settings_path).map_err(|e| e.to_string())?;

    let provider = settings.llm_provider.as_deref().unwrap_or("openai");
    let api_key = resolve_api_key(provider, settings.llm_api_key.clone())?;
    let model = settings
        .llm_model
        .clone()
        .unwrap_or_else(|| default_model(provider));
    let base_url = resolve_base_url(provider, settings.llm_base_url.clone());

    let llm_history: Vec<crate::llm::ChatMessage> = history
        .into_iter()
        .map(|m| crate::llm::ChatMessage {
            role: m.role,
            content: m.content,
        })
        .collect();

    let metric_history = collect_metric_history(&state.store);
    let av_diag = av_context_snapshot(&state);

    crate::llm::chat_query(
        provider,
        &api_key,
        &model,
        base_url.as_deref(),
        &scan_result,
        Some(&metric_history),
        av_diag.as_ref(),
        llm_history,
        &question,
    )
    .await
    .map_err(|e| e.to_string())
}

/// Maximum number of LLM round-trips in one agentic chat turn. Each
/// iteration may execute one or more tool calls before the model is asked
/// again. Bounds runaway loops and slow CPU-bound local generation.
const CHAT_AGENT_MAX_ITERS: usize = 6;

/// Agentic chat: like [`chat_query`] but exposes the `device_exec` tool so a
/// tool-capable model (e.g. `qwen2.5`) can run real SSH/HTTPS diagnostics on
/// configured hosts, gated by the existing approval modal. Falls back to the
/// plain narrator chat when the provider lacks tool support or no hosts are
/// configured.
#[tauri::command]
pub async fn chat_agent(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
    scan_result: ScanResult,
    history: Vec<FrontendChatMessage>,
    question: String,
) -> Result<String, String> {
    use tauri::Emitter;

    let settings = Settings::load(&state.settings_path).map_err(|e| e.to_string())?;
    let provider = settings
        .llm_provider
        .as_deref()
        .unwrap_or("openai")
        .to_string();
    let api_key = resolve_api_key(&provider, settings.llm_api_key.clone())?;
    let model = settings
        .llm_model
        .clone()
        .unwrap_or_else(|| default_model(&provider));
    let base_url = resolve_base_url(&provider, settings.llm_base_url.clone());

    let hosts = state.inventory.lock().hosts.clone();

    // Tool-calling is only available on OpenAI-compatible providers and only
    // makes sense when there are devices to act on. Otherwise answer with the
    // plain narrator chat so the assistant still responds.
    let tools_supported = matches!(provider.as_str(), "openai" | "ollama");
    if !tools_supported || hosts.is_empty() {
        let llm_history: Vec<crate::llm::ChatMessage> = history
            .into_iter()
            .map(|m| crate::llm::ChatMessage {
                role: m.role,
                content: m.content,
            })
            .collect();
        let metric_history = collect_metric_history(&state.store);
        let av_diag = av_context_snapshot(&state);
        return crate::llm::chat_query(
            &provider,
            &api_key,
            &model,
            base_url.as_deref(),
            &scan_result,
            Some(&metric_history),
            av_diag.as_ref(),
            llm_history,
            &question,
        )
        .await
        .map_err(|e| e.to_string());
    }

    // device_exec tool schema. The host enum constrains the model to known
    // inventory ids; the catalog in the system prompt enumerates valid cmds.
    let host_ids: Vec<serde_json::Value> = hosts
        .iter()
        .map(|h| serde_json::Value::String(h.id.clone()))
        .collect();
    let tools = serde_json::json!([{
        "type": "function",
        "function": {
            "name": "device_exec",
            "description": "Run one allowlisted diagnostic command from a configured network device's skill pack over SSH/HTTPS. Only host+command pairs from the DEVICE CATALOG are valid. Read commands run immediately; mutate/dangerous commands require operator approval and may be denied. Returns parsed JSON output.",
            "parameters": {
                "type": "object",
                "properties": {
                    "host": { "type": "string", "description": "Configured host id to target.", "enum": host_ids },
                    "cmd": { "type": "string", "description": "Skill-pack command id to run on that host (see DEVICE CATALOG)." },
                    "args": { "type": "object", "description": "Optional command arguments as key/value pairs, e.g. {\"iface\":\"Gi1/0/24\"}. Keys must match the command's declared args." }
                },
                "required": ["host", "cmd"]
            }
        }
    }]);

    // System prompt: diagnostic context + device catalog + tool guidance.
    let metric_history = collect_metric_history(&state.store);
    let av_diag = av_context_snapshot(&state);
    let mut system =
        crate::llm::chat_system_prompt(&scan_result, Some(&metric_history), av_diag.as_ref());
    system.push_str(
        "\n\n# DEVICE CATALOG\nYou can run diagnostics on these configured network \
         devices by calling the `device_exec` tool. Use ONLY these host ids and \
         command ids.\n\n",
    );
    system.push_str(&build_device_catalog(&hosts, &state.packs));
    system.push_str(
        "\n\nGuidance: When the user asks you to inspect, diagnose, or check a \
         switch/AP/controller, call `device_exec` to gather real data before \
         answering. Prefer read commands. Chain multiple calls if needed. When you \
         have enough information, give a concise final answer that cites the \
         findings. If no configured device fits the request, say so plainly.",
    );

    let mut messages: Vec<serde_json::Value> = Vec::new();
    messages.push(serde_json::json!({ "role": "system", "content": system }));
    for m in &history {
        messages.push(serde_json::json!({ "role": m.role, "content": m.content }));
    }
    messages.push(serde_json::json!({ "role": "user", "content": question }));

    // Device tool + approval event pump. Reusing the runbook approval event
    // ("runbook-event") means the existing always-on ApprovalModal handles
    // mutate/dangerous gating during chat with no extra frontend wiring.
    let device_tool = crate::device::exec_tool::DeviceExecTool::new(
        state.inventory.clone(),
        state.packs.clone(),
        state.audit.clone(),
        state.approval.clone(),
        model.clone(),
    );
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<crate::runbook::RunbookEvent>();
    let app_pump = app.clone();
    let pump = tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            let _ = app_pump.emit("runbook-event", &ev);
        }
    });
    let ctx = crate::runbook::tools::ToolContext {
        pinned_iface: None,
        timeout: Duration::from_secs(90),
        event_tx: Some(tx),
    };

    let mut final_answer = String::new();
    for _ in 0..CHAT_AGENT_MAX_ITERS {
        let msg = match crate::llm::chat_completion_raw(
            &provider,
            &api_key,
            &model,
            base_url.as_deref(),
            messages.clone(),
            Some(tools.clone()),
        )
        .await
        {
            Ok(m) => m,
            Err(e) => {
                drop(ctx);
                let _ = pump.await;
                return Err(e.to_string());
            }
        };

        // Record the assistant turn verbatim so tool_call ids line up.
        messages.push(msg.clone());

        let tool_calls = msg
            .get("tool_calls")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        if tool_calls.is_empty() {
            final_answer = msg
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            break;
        }

        for call in tool_calls {
            let call_id = call
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let fname = call
                .get("function")
                .and_then(|f| f.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let raw_args = call
                .get("function")
                .and_then(|f| f.get("arguments"))
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let parsed_args: serde_json::Value = match raw_args {
                serde_json::Value::String(s) => {
                    serde_json::from_str(&s).unwrap_or_else(|_| serde_json::json!({}))
                }
                obj @ serde_json::Value::Object(_) => obj,
                _ => serde_json::json!({}),
            };

            let result = if fname == "device_exec" {
                run_device_exec_call(&device_tool, &ctx, &parsed_args).await
            } else {
                serde_json::json!({ "error": format!("unknown tool `{fname}`") })
            };

            // Surface a transcript step to the UI.
            let _ = app.emit(
                "chat-agent-step",
                &serde_json::json!({
                    "tool": fname,
                    "host": parsed_args.get("host").cloned().unwrap_or(serde_json::Value::Null),
                    "cmd": parsed_args.get("cmd").cloned().unwrap_or(serde_json::Value::Null),
                    "result": result.clone(),
                }),
            );

            messages.push(serde_json::json!({
                "role": "tool",
                "tool_call_id": call_id,
                "content": result.to_string(),
            }));
        }
    }

    drop(ctx);
    let _ = pump.await;

    if final_answer.trim().is_empty() {
        final_answer = "I gathered device data but couldn't compose a final answer \
                        within the step limit. Please ask a more specific question."
            .to_string();
    }
    Ok(final_answer)
}

/// Run a single `device_exec` tool call from the chat agent. Maps the LLM's
/// `{host, cmd, args}` shape into the flat arg map `DeviceExecTool` expects
/// and converts tool errors into a JSON object the model can read and act on.
async fn run_device_exec_call(
    tool: &crate::device::exec_tool::DeviceExecTool,
    ctx: &crate::runbook::tools::ToolContext,
    args: &serde_json::Value,
) -> serde_json::Value {
    use crate::runbook::tools::Tool;
    let host = args.get("host").and_then(|v| v.as_str()).unwrap_or("");
    let cmd = args.get("cmd").and_then(|v| v.as_str()).unwrap_or("");
    if host.is_empty() || cmd.is_empty() {
        return serde_json::json!({ "error": "device_exec requires both `host` and `cmd`." });
    }
    let mut exec_args = serde_json::json!({ "host": host, "cmd": cmd });
    if let (Some(obj), Some(map)) = (
        args.get("args").and_then(|v| v.as_object()),
        exec_args.as_object_mut(),
    ) {
        for (k, v) in obj {
            map.insert(k.clone(), v.clone());
        }
    }
    match tool.run(exec_args, ctx).await {
        Ok(v) => v,
        Err(e) => serde_json::json!({ "error": e.to_string() }),
    }
}

/// Render the device catalog shown to the model in the system prompt: one
/// block per configured host listing its allowlisted skill-pack commands.
fn build_device_catalog(
    hosts: &[crate::device::inventory::HostEntry],
    packs: &crate::device::pack::PackRegistry,
) -> String {
    let mut out = String::new();
    for h in hosts {
        out.push_str(&format!(
            "- host `{}` (\"{}\") — skill {}, transport {:?}, hostname {}",
            h.id, h.alias, h.skill, h.transport, h.hostname
        ));
        if !h.roles.is_empty() {
            out.push_str(&format!(", roles [{}]", h.roles.join(", ")));
        }
        out.push('\n');
        match packs.get(&h.skill) {
            Some(pack) => {
                for c in &pack.commands {
                    let args_desc = if c.args.is_empty() {
                        String::new()
                    } else {
                        let names: Vec<String> = c
                            .args
                            .iter()
                            .map(|a| {
                                let req = if a.required { ", required" } else { "" };
                                format!("{}({}{})", a.name, a.kind, req)
                            })
                            .collect();
                        format!(" — args: {}", names.join(", "))
                    };
                    out.push_str(&format!(
                        "    * {} [{}]: {}{}\n",
                        c.id,
                        c.risk.as_str(),
                        c.purpose,
                        args_desc
                    ));
                }
            }
            None => out.push_str("    (skill pack not found — no commands available)\n"),
        }
    }
    out
}

// ═══════════════════════════════════════════════════════════════════════
// IP Scanner — active subnet sweep.
// ═══════════════════════════════════════════════════════════════════════

/// Resolve the IPv4 of the NIC the scanner should sweep from (the global
/// pinned interface, else the kernel default).
fn scanner_iface_ipv4(state: &State<'_, AppState>) -> Option<String> {
    let name = resolved_iface(state, None).or_else(crate::probes::iface::default_interface)?;
    crate::probes::iface::find_by_name(&name).and_then(|i| i.ipv4)
}

/// Suggest a default `/24` CIDR derived from the active interface so the UI can
/// pre-fill the scan range.
#[tauri::command]
pub async fn default_scan_cidr(state: State<'_, AppState>) -> Result<String, String> {
    let ipv4 = scanner_iface_ipv4(&state).unwrap_or_default();
    Ok(crate::discovery::ipscan::default_cidr_for(&ipv4))
}

/// Actively sweep a subnet for live hosts. When `cidr` is omitted/blank the
/// range is derived from the active interface (`/24`).
#[tauri::command]
pub async fn scan_subnet(
    state: State<'_, AppState>,
    cidr: Option<String>,
) -> Result<crate::discovery::ipscan::IpScanResult, String> {
    let iface = resolved_iface(&state, None);
    let cidr = match cidr {
        Some(c) if !c.trim().is_empty() => c,
        _ => {
            let ipv4 = scanner_iface_ipv4(&state).unwrap_or_default();
            crate::discovery::ipscan::default_cidr_for(&ipv4)
        }
    };
    crate::discovery::ipscan::scan_subnet(&cidr, iface).await
}

/// Validate a host/username token so it can be embedded in a shell/AppleScript
/// command without injection risk. Allows the characters that legitimately
/// appear in IPv4/IPv6 literals, DNS names, and POSIX usernames.
fn is_safe_token(s: &str, allow_colon: bool) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '.' | '-' | '_')
                || (allow_colon && c == ':')
        })
}

/// Open a native terminal window with an interactive `ssh` session to `host`.
/// The host is one the operator picked from the IP-scanner table, so this is
/// a convenience launcher — credentials/known-hosts are handled by the user's
/// own ssh client, not Atlas.
#[tauri::command]
pub async fn open_ssh_terminal(
    host: String,
    port: Option<u16>,
    username: Option<String>,
) -> Result<(), String> {
    let host = host.trim().to_string();
    if !is_safe_token(&host, true) {
        return Err(format!("invalid host `{host}`"));
    }
    let port = port.unwrap_or(22);
    let target = match username.as_deref().map(str::trim) {
        Some(u) if !u.is_empty() => {
            if !is_safe_token(u, false) {
                return Err(format!("invalid username `{u}`"));
            }
            format!("{u}@{host}")
        }
        _ => host.clone(),
    };
    // Bare `ssh` command line — every token is charset-validated above.
    let ssh_cmd = format!("ssh -p {port} {target}");

    #[cfg(target_os = "macos")]
    {
        // Drive Terminal.app via AppleScript so the session opens in a real,
        // interactive window the operator can type into.
        let script = format!(
            "tell application \"Terminal\"\nactivate\ndo script \"{ssh_cmd}\"\nend tell"
        );
        std::process::Command::new("osascript")
            .arg("-e")
            .arg(&script)
            .spawn()
            .map_err(|e| format!("failed to launch Terminal: {e}"))?;
        Ok(())
    }

    #[cfg(target_os = "windows")]
    {
        // `start` opens a new console window running ssh; `cmd /k` keeps it
        // open after the session ends so errors stay visible.
        std::process::Command::new("cmd")
            .args(["/C", "start", "", "cmd", "/k", &ssh_cmd])
            .spawn()
            .map_err(|e| format!("failed to launch terminal: {e}"))?;
        Ok(())
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        // Try a sequence of common terminal emulators, holding the window open
        // with a trailing shell so the session and any errors remain visible.
        let hold = format!("{ssh_cmd}; exec $SHELL");
        let candidates: &[(&str, &[&str])] = &[
            ("x-terminal-emulator", &["-e", "sh", "-c"]),
            ("gnome-terminal", &["--", "sh", "-c"]),
            ("konsole", &["-e", "sh", "-c"]),
            ("xterm", &["-e", "sh", "-c"]),
        ];
        for (bin, pre) in candidates {
            let mut cmd = std::process::Command::new(bin);
            cmd.args(*pre).arg(&hold);
            if cmd.spawn().is_ok() {
                return Ok(());
            }
        }
        Err("no supported terminal emulator found (tried gnome-terminal, konsole, xterm)".into())
    }
}


fn collect_metric_history(store: &Store) -> crate::llm::MetricHistory {
    const METRICS: &[(&str, &str)] = &[
        ("link.rssi_dbm", "RSSI (dBm)"),
        ("link.snr_db", "SNR (dB)"),
        ("link.tx_rate_mbps", "Tx rate (Mbps)"),
        ("reach.gateway_latency_ms", "Gateway latency (ms)"),
        ("reach.internet_latency_ms", "Internet latency (ms)"),
        ("reach.packet_loss_pct", "Packet loss (%)"),
    ];
    METRICS
        .iter()
        .map(|(metric, label)| {
            let samples = store.recent_metric_samples(metric, 60).unwrap_or_default();
            (label.to_string(), samples)
        })
        .collect()
}

#[tauri::command]
pub fn get_payload_preview(scan_result: ScanResult) -> String {
    crate::llm::preview_payload(&scan_result)
}

fn default_model(provider: &str) -> String {
    match provider {
        "anthropic" => "claude-3-haiku-20240307".to_string(),
        "ollama" => "llama3".to_string(),
        _ => "gpt-4o-mini".to_string(),
    }
}

/// Local providers (Ollama) don't need an API key; remote providers do.
fn resolve_api_key(provider: &str, configured: Option<String>) -> Result<String, String> {
    match provider {
        "ollama" => Ok(configured.unwrap_or_default()),
        _ => configured.ok_or_else(|| {
            "No LLM API key configured. Add one in Settings, or switch to Ollama (local)."
                .to_string()
        }),
    }
}

/// Default Ollama to 127.0.0.1 when no base URL is set so users don't have to fill
/// it in. We use the IPv4 literal (not "localhost") because Ollama binds only to
/// 127.0.0.1 and "localhost" can resolve to IPv6 ::1, which Ollama refuses.
fn resolve_base_url(provider: &str, configured: Option<String>) -> Option<String> {
    match (provider, configured) {
        ("ollama", None) => Some("http://127.0.0.1:11434".to_string()),
        ("ollama", Some(s)) if s.trim().is_empty() => Some("http://127.0.0.1:11434".to_string()),
        (_, other) => other,
    }
}

// ── Metric history + export ───────────────────────────────────────────────────

#[tauri::command]
pub async fn get_metric_history(
    state: State<'_, AppState>,
    metric: String,
    limit: Option<usize>,
) -> Result<Vec<MetricSample>, String> {
    state
        .store
        .recent_metric_samples(&metric, limit.unwrap_or(50))
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_roaming_history(
    state: State<'_, AppState>,
    hours: Option<i64>,
) -> Result<Vec<crate::types::RoamingEvent>, String> {
    let since = Utc::now() - chrono::Duration::hours(hours.unwrap_or(24));
    state
        .store
        .roaming_events_since(since)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn export_report(state: State<'_, AppState>, run_id: String) -> Result<String, String> {
    let scan = state
        .store
        .get_scan_full(&run_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("Run '{run_id}' not found or predates report storage"))?;

    // Pull live telemetry / events / narratives so the printed report can
    // tell a fuller story than the scan snapshot alone.
    let samples: Vec<crate::types::LiveSample> = state
        .sampler_handle
        .lock()
        .as_ref()
        .map(|h| h.ring.read().iter().cloned().collect())
        .unwrap_or_default();
    let wifi_events: Vec<crate::types::WifiEvent> = state
        .wifi_events_handle
        .lock()
        .as_ref()
        .map(|h| h.ring.read().iter().cloned().collect())
        .unwrap_or_default();
    let narratives: Vec<crate::types::Narrative> = state
        .narrator_handle
        .lock()
        .as_ref()
        .map(|h| h.ring.read().iter().cloned().collect())
        .unwrap_or_default();

    // Optional on-demand context the operator may have captured via the
    // AV / Stress tabs. These are cached in AppState by the corresponding
    // commands and survive into the printed report without requiring the
    // frontend to re-pass them.
    let av_diag: Option<AvDiagnosticsResult> = state.last_av_diagnostics.lock().clone();
    let deep_probe: Option<DeepProbeResult> = state.last_deep_probe.lock().clone();
    let stress_results: Vec<StressTestResult> = state.recent_stress_results.lock().clone();

    Ok(render_html_report(
        &scan,
        &samples,
        &wifi_events,
        &narratives,
        av_diag.as_ref(),
        deep_probe.as_ref(),
        &stress_results,
    ))
}

/// Render a small SVG sparkline of `pick(sample)` values over the supplied
/// window. Returns an empty string when fewer than 2 points are available
/// (a single point can't draw a line).
fn render_sparkline(
    samples: &[crate::types::LiveSample],
    pick: impl Fn(&crate::types::LiveSample) -> Option<f64>,
    color: &str,
    unit: &str,
) -> String {
    let pts: Vec<f64> = samples.iter().filter_map(&pick).collect();
    if pts.len() < 2 {
        return "<span style='color:#475569;font-size:12px'>insufficient data</span>".into();
    }
    let (mut lo, mut hi) = (f64::INFINITY, f64::NEG_INFINITY);
    for &v in &pts {
        if v < lo {
            lo = v;
        }
        if v > hi {
            hi = v;
        }
    }
    if (hi - lo).abs() < f64::EPSILON {
        hi = lo + 1.0;
    }
    let w = 220.0_f64;
    let h = 40.0_f64;
    let step = w / ((pts.len() - 1) as f64);
    let poly: String = pts
        .iter()
        .enumerate()
        .map(|(i, &v)| {
            let x = (i as f64) * step;
            let y = h - ((v - lo) / (hi - lo)) * h;
            format!("{x:.1},{y:.1}")
        })
        .collect::<Vec<_>>()
        .join(" ");
    let last = pts.last().copied().unwrap_or(0.0);
    format!(
        r#"<span style="display:inline-flex;align-items:center;gap:8px">
<svg viewBox="0 0 {w:.0} {h:.0}" width="{w:.0}" height="{h:.0}" style="background:#0a0a14;border-radius:4px">
  <polyline fill="none" stroke="{color}" stroke-width="1.5" points="{poly}" />
</svg>
<span style="font-family:monospace;color:#cbd5e1;font-size:12px">{last:.0} {unit} (range {lo:.0}–{hi:.0})</span>
</span>"#,
    )
}

fn render_html_report(
    scan: &ScanResult,
    samples: &[crate::types::LiveSample],
    wifi_events: &[crate::types::WifiEvent],
    narratives: &[crate::types::Narrative],
    av_diag: Option<&AvDiagnosticsResult>,
    deep_probe: Option<&DeepProbeResult>,
    stress_results: &[StressTestResult],
) -> String {
    // ── Helper: a simple definition-list table for "key: value" panels.
    // Used by every "details panel" section below so they share styling
    // and so we get consistent print rendering.
    fn dl_table(rows: &[(&str, String)]) -> String {
        if rows.iter().all(|(_, v)| v.is_empty()) {
            return String::new();
        }
        let body: String = rows
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, v)| {
                format!(
                    "<tr><th style=\"width:34%;text-align:left;color:#94a3b8;font-weight:500\">{}</th><td>{}</td></tr>",
                    html_escape(k),
                    v
                )
            })
            .collect();
        format!("<table>{body}</table>")
    }
    fn opt_str<T: std::fmt::Display>(v: &Option<T>) -> String {
        match v {
            Some(x) => html_escape(&x.to_string()),
            None => String::new(),
        }
    }
    fn opt_fmt<T, F: Fn(&T) -> String>(v: &Option<T>, f: F) -> String {
        v.as_ref()
            .map(f)
            .map(|s| html_escape(&s))
            .unwrap_or_default()
    }

    let severity_color = |s: &crate::types::Severity| match s {
        crate::types::Severity::Critical => "#ef4444",
        crate::types::Severity::High => "#f97316",
        crate::types::Severity::Medium => "#eab308",
        crate::types::Severity::Low => "#3b82f6",
        crate::types::Severity::Info => "#6b7280",
    };

    let recs_html: String = if scan.recommendations.is_empty() {
        String::new()
    } else {
        scan.recommendations
            .iter()
            .map(|r| {
                let steps = r
                    .steps
                    .iter()
                    .map(|s| format!("<li>{}</li>", html_escape(s)))
                    .collect::<String>();
                let links = if r.links.is_empty() {
                    String::new()
                } else {
                    let chips: String = r
                        .links
                        .iter()
                        .map(|l| {
                            format!(
                                "<a href=\"{}\" style=\"display:inline-block;margin:2px 6px 0 0;padding:2px 8px;background:#1e293b;color:#93c5fd;border-radius:4px;text-decoration:none;font-size:12px\">🔗 {}</a>",
                                html_escape(&l.url),
                                html_escape(&l.label),
                            )
                        })
                        .collect();
                    format!("<div style=\"margin-top:6px\">{chips}</div>")
                };
                let auto = if r.auto_fix_available {
                    "<span style=\"display:inline-block;margin-left:8px;padding:1px 6px;background:#065f46;color:#a7f3d0;border-radius:3px;font-size:11px\">auto-fix available</span>"
                } else {
                    ""
                };
                format!(
                    r#"<div style="margin:8px 0;padding:8px 12px;background:#1a1a2e;border-radius:6px">
  <strong>{title}</strong>{auto}<br><span style="color:#aaa">{summary}</span>
  <ol style="margin:4px 0 0 16px;color:#ccc">{steps}</ol>
  {links}
</div>"#,
                    title = html_escape(&r.title),
                    summary = html_escape(&r.summary),
                    steps = steps,
                    links = links,
                    auto = auto,
                )
            })
            .collect()
    };

    // Findings re-rendered with confidence + affected devices + observed_at.
    let findings_html: String = if scan.findings.is_empty() {
        "<p style='color:#6b7280'>No findings — network looks healthy.</p>".into()
    } else {
        scan.findings
            .iter()
            .map(|f| {
                let color = severity_color(&f.severity);
                let evidence = f
                    .evidence
                    .iter()
                    .map(|e| format!("<li>{}</li>", html_escape(e)))
                    .collect::<String>();
                let affected = if f.affected_devices.is_empty() {
                    String::new()
                } else {
                    let chips: String = f
                        .affected_devices
                        .iter()
                        .map(|d| {
                            format!(
                                "<code style=\"background:#0f172a;color:#cbd5e1;padding:1px 6px;border-radius:3px;font-size:11px;margin-right:4px\">{}</code>",
                                html_escape(d)
                            )
                        })
                        .collect();
                    format!("<p style=\"margin:4px 0 0;color:#94a3b8;font-size:12px\"><strong>Affected:</strong> {chips}</p>")
                };
                format!(
                    r#"<div style="border-left:4px solid {color};padding:8px 12px;margin:8px 0;background:#1a1a2e">
  <div style="display:flex;justify-content:space-between;gap:12px">
    <span><strong style="color:{color}">[{sev}]</strong> {title}</span>
    <span style="color:#64748b;font-family:monospace;font-size:11px">conf {conf:.0}% · {at} · rule {rule}</span>
  </div>
  <ul style="margin:4px 0 0 16px;color:#aaa">{evidence}</ul>
  {affected}
</div>"#,
                    color = color,
                    sev = f.severity.as_str().to_uppercase(),
                    title = html_escape(&f.title),
                    evidence = evidence,
                    affected = affected,
                    conf = (f.confidence * 100.0).round(),
                    at = f.observed_at.format("%H:%M:%S"),
                    rule = html_escape(&f.rule_id),
                )
            })
            .collect()
    };

    let devices_html: String = scan
        .devices
        .iter()
        .map(|d| {
            let status = if d.online { "🟢" } else { "🔴" };
            let latency = d
                .latency_ms
                .map(|ms| format!("{ms:.0} ms"))
                .unwrap_or_else(|| "—".into());
            let services = if d.services.is_empty() {
                String::new()
            } else {
                d.services
                    .iter()
                    .map(|s| {
                        format!(
                            "<code style=\"background:#0f172a;color:#93c5fd;padding:1px 5px;border-radius:3px;font-size:11px;margin-right:3px\">{}</code>",
                            html_escape(s)
                        )
                    })
                    .collect()
            };
            format!(
                "<tr><td>{status}</td>\
                 <td style='font-family:monospace'>{mac}</td>\
                 <td style='font-family:monospace;color:#cbd5e1'>{ip}</td>\
                 <td>{host}</td>\
                 <td>{class:?}</td>\
                 <td style='color:#94a3b8'>{vendor}</td>\
                 <td>{latency}</td>\
                 <td>{services}</td></tr>",
                status = status,
                mac = html_escape(&d.mac),
                ip = html_escape(d.ip.as_deref().unwrap_or("—")),
                host = html_escape(d.hostname.as_deref().unwrap_or("—")),
                class = d.class,
                vendor = html_escape(d.vendor.as_deref().unwrap_or("—")),
                latency = latency,
                services = services,
            )
        })
        .collect();

    let service_html: String = if scan.service_reachability.is_empty() {
        String::new()
    } else {
        let rows: String = scan
            .service_reachability
            .iter()
            .map(|p| {
                let status = if p.reachable { "🟢" } else { "🔴" };
                let latency = p
                    .latency_ms
                    .map(|ms| format!("{ms:.0} ms"))
                    .unwrap_or_else(|| "—".into());
                format!(
                    "<tr><td>{status}</td><td style='font-family:monospace'>{target}</td>\
                     <td>{latency}</td><td>{err}</td></tr>",
                    target = html_escape(&p.target),
                    latency = latency,
                    err = html_escape(p.error.as_deref().unwrap_or("")),
                )
            })
            .collect();
        format!(
            r#"<h2>Service reachability</h2>
<table border="1" style="border-collapse:collapse;width:100%">
<tr><th>Status</th><th>Target</th><th>Latency</th><th>Error</th></tr>
{rows}</table>"#
        )
    };

    let portal_badge = if scan.captive_portal {
        "<span style='background:#eab308;color:#000;padding:2px 8px;border-radius:4px'>⚠ Captive portal detected</span> "
    } else {
        ""
    };

    // ── Telemetry sparklines ──────────────────────────────────────────────
    let telemetry_html: String = if samples.is_empty() {
        String::new()
    } else {
        let rssi_spark =
            render_sparkline(samples, |s| s.rssi_dbm.map(|v| v as f64), "#60a5fa", "dBm");
        let gw_spark =
            render_sparkline(samples, |s| s.gateway_ms.map(|v| v as f64), "#34d399", "ms");
        let net_spark = render_sparkline(
            samples,
            |s| s.internet_ms.map(|v| v as f64),
            "#fbbf24",
            "ms",
        );
        let dns_spark = render_sparkline(samples, |s| s.dns_ms.map(|v| v as f64), "#a78bfa", "ms");
        format!(
            r#"<h2>Live telemetry (last {n} samples)</h2>
<table style="width:auto"><tr>
<td style="padding:8px 14px"><strong>RSSI</strong><br>{rssi}</td>
<td style="padding:8px 14px"><strong>Gateway latency</strong><br>{gw}</td>
</tr><tr>
<td style="padding:8px 14px"><strong>Internet latency</strong><br>{net}</td>
<td style="padding:8px 14px"><strong>DNS latency</strong><br>{dns}</td>
</tr></table>"#,
            n = samples.len(),
            rssi = rssi_spark,
            gw = gw_spark,
            net = net_spark,
            dns = dns_spark,
        )
    };

    // ── Narratives ────────────────────────────────────────────────────────
    let narratives_html: String = if narratives.is_empty() {
        String::new()
    } else {
        let cards: String = narratives
            .iter()
            .rev()
            .take(20)
            .map(|n| {
                let color = match n.severity.as_str() {
                    "critical" => "#ef4444",
                    "warn" | "warning" => "#f97316",
                    "info" => "#3b82f6",
                    _ => "#6b7280",
                };
                let llm = n
                    .llm_summary
                    .as_deref()
                    .filter(|s| !s.trim().is_empty())
                    .map(|s| {
                        format!(
                            "<p style=\"margin:6px 0 0;color:#cbd5e1;font-style:italic\">🤖 {}</p>",
                            html_escape(s),
                        )
                    })
                    .unwrap_or_default();
                let try_list: String = n
                    .what_to_try
                    .iter()
                    .map(|t| format!("<li>{}</li>", html_escape(t)))
                    .collect();
                format!(
                    r#"<div style="border-left:4px solid {color};padding:10px 14px;margin:10px 0;background:#1a1a2e;border-radius:0 6px 6px 0">
  <div style="display:flex;justify-content:space-between;gap:12px">
    <strong style="color:{color}">{headline}</strong>
    <span style="color:#64748b;font-family:monospace;font-size:12px">{at}</span>
  </div>
  <p style="margin:6px 0 0;color:#cbd5e1"><strong>What happened:</strong> {what}</p>
  <p style="margin:4px 0 0;color:#cbd5e1"><strong>Likely cause:</strong> {cause}</p>
  <p style="margin:6px 0 2px;color:#94a3b8"><strong>What to try:</strong></p>
  <ol style="margin:0 0 0 18px;color:#cbd5e1">{try_list}</ol>
  {llm}
</div>"#,
                    color = color,
                    headline = html_escape(&n.headline),
                    at = n.at.format("%H:%M:%S"),
                    what = html_escape(&n.what_happened),
                    cause = html_escape(&n.likely_cause),
                    try_list = try_list,
                    llm = llm,
                )
            })
            .collect();
        format!(
            "<h2>Causal narratives ({n})</h2>{cards}",
            n = narratives.len()
        )
    };

    // ── Wi-Fi system events ───────────────────────────────────────────────
    let wifi_events_html: String = if wifi_events.is_empty() {
        String::new()
    } else {
        let rows: String = wifi_events
            .iter()
            .rev()
            .take(50)
            .map(|e| {
                format!(
                    "<tr><td style='font-family:monospace;font-size:11px'>{ts}</td>\
                     <td><span style='background:#1e293b;padding:2px 6px;border-radius:3px;font-size:11px'>{kind}</span></td>\
                     <td style='font-family:monospace;font-size:11px;color:#94a3b8'>{proc}</td>\
                     <td style='color:#cbd5e1'>{msg}</td></tr>",
                    ts = e.ts.format("%H:%M:%S"),
                    kind = html_escape(&e.kind),
                    proc = html_escape(e.process.as_deref().unwrap_or("—")),
                    msg = html_escape(&e.message),
                )
            })
            .collect();
        format!(
            r#"<h2>Wi-Fi system events ({n})</h2>
<table>
<tr><th>Time</th><th>Kind</th><th>Process</th><th>Message</th></tr>
{rows}</table>"#,
            n = wifi_events.len()
        )
    };

    // ── Link details panel (every field on LinkStats) ─────────────────────
    let link = &scan.link;
    let link_html: String = {
        let rows = [
            ("SSID", opt_str(&link.ssid)),
            ("BSSID", opt_str(&link.bssid)),
            ("Vendor (OUI)", opt_str(&link.vendor)),
            ("Band", opt_str(&link.band)),
            ("Channel", opt_str(&link.channel)),
            (
                "Channel width",
                opt_fmt(&link.channel_width_mhz, |v| format!("{v} MHz")),
            ),
            ("RSSI", opt_fmt(&link.rssi_dbm, |v| format!("{v} dBm"))),
            ("Noise", opt_fmt(&link.noise_dbm, |v| format!("{v} dBm"))),
            ("SNR", opt_fmt(&link.snr_db, |v| format!("{v} dB"))),
            (
                "TX rate",
                opt_fmt(&link.tx_rate_mbps, |v| format!("{v:.1} Mb/s")),
            ),
            (
                "RX rate",
                opt_fmt(&link.rx_rate_mbps, |v| format!("{v:.1} Mb/s")),
            ),
            ("Security", opt_str(&link.security)),
            ("PHY mode", opt_str(&link.phy_mode)),
            ("Wi-Fi generation", opt_str(&link.wifi_generation)),
        ];
        let body = dl_table(&rows);
        if body.is_empty() {
            String::new()
        } else {
            format!("<h2>Link details</h2>{body}")
        }
    };

    // ── Reachability panel (every field on ReachabilityStats) ─────────────
    let reach = &scan.reachability;
    let reach_html: String = {
        let rows = [
            ("Gateway IP", opt_str(&reach.gateway_ip)),
            (
                "Gateway latency",
                opt_fmt(&reach.gateway_latency_ms, |v| format!("{v:.1} ms")),
            ),
            (
                "Internet latency",
                opt_fmt(&reach.internet_latency_ms, |v| format!("{v:.1} ms")),
            ),
            (
                "DNS latency",
                opt_fmt(&reach.dns_latency_ms, |v| format!("{v:.1} ms")),
            ),
            (
                "Packet loss",
                opt_fmt(&reach.packet_loss_pct, |v| format!("{v:.1}%")),
            ),
        ];
        let body = dl_table(&rows);
        if body.is_empty() {
            String::new()
        } else {
            format!("<h2>Reachability</h2>{body}")
        }
    };

    // ── Connection extras (DNS leak, MTU, speed) ──────────────────────────
    let extras_html: String = {
        let rows = [
            (
                "DNS leak",
                if scan.dns_leak {
                    "<span style=\"color:#ef4444\">⚠ detected</span>".to_string()
                } else {
                    "—".to_string()
                },
            ),
            (
                "Path MTU",
                opt_fmt(&scan.mtu_bytes, |v| format!("{v} bytes")),
            ),
            (
                "Throughput",
                opt_fmt(&scan.speed_mbps, |v| format!("{v:.1} Mb/s")),
            ),
        ];
        let body = dl_table(&rows);
        if body.is_empty() {
            String::new()
        } else {
            format!("<h2>Connection extras</h2>{body}")
        }
    };

    // ── WAN / ISP ─────────────────────────────────────────────────────────
    let wan_html: String = match &scan.wan {
        None => String::new(),
        Some(w) => {
            let rows = [
                ("Public IPv4", opt_str(&w.public_ipv4)),
                ("Public IPv6", opt_str(&w.public_ipv6)),
                (
                    "Dual-stack",
                    if w.dual_stack {
                        "yes".into()
                    } else {
                        "no".into()
                    },
                ),
                ("ASN", opt_fmt(&w.asn, |v| format!("AS{v}"))),
                ("ISP", opt_str(&w.isp)),
                ("Country", opt_str(&w.country)),
                ("Region", opt_str(&w.region)),
            ];
            let body = dl_table(&rows);
            if body.is_empty() {
                String::new()
            } else {
                format!("<h2>WAN / ISP</h2>{body}")
            }
        }
    };

    // ── Quality / bufferbloat ─────────────────────────────────────────────
    let quality_html: String = match &scan.quality {
        None => String::new(),
        Some(q) => {
            let rows = [
                (
                    "Downlink throughput",
                    opt_fmt(&q.dl_throughput_mbps, |v| format!("{v:.1} Mb/s")),
                ),
                (
                    "Uplink throughput",
                    opt_fmt(&q.ul_throughput_mbps, |v| format!("{v:.1} Mb/s")),
                ),
                (
                    "Responsiveness",
                    opt_fmt(&q.responsiveness_rpm, |v| format!("{v} RPM")),
                ),
                ("Responsiveness label", opt_str(&q.responsiveness_label)),
                (
                    "Idle latency",
                    opt_fmt(&q.idle_latency_ms, |v| format!("{v:.1} ms")),
                ),
            ];
            let body = dl_table(&rows);
            if body.is_empty() {
                String::new()
            } else {
                format!("<h2>Quality / bufferbloat</h2>{body}")
            }
        }
    };

    // ── Interference / channel scoring ────────────────────────────────────
    let interference_html: String = match &scan.interference {
        None => String::new(),
        Some(ir) => {
            let rec_24 = ir
                .recommended_24
                .map(|v| v.to_string())
                .unwrap_or_else(|| "—".into());
            let rec_5 = ir
                .recommended_5
                .map(|v| v.to_string())
                .unwrap_or_else(|| "—".into());
            let cur = ir
                .current_channel_score
                .map(|v| format!("{v:.0}"))
                .unwrap_or_else(|| "—".into());
            let rows: String = ir
                .channels
                .iter()
                .take(20)
                .map(|c| {
                    let strongest = c
                        .strongest_interferer_dbm
                        .map(|v| format!("{v} dBm"))
                        .unwrap_or_else(|| "—".into());
                    format!(
                        "<tr><td>{ch}</td><td>{band}</td><td>{score:.0}</td><td>{co}</td><td>{adj}</td><td>{si}</td></tr>",
                        ch = c.channel,
                        band = html_escape(&c.band),
                        score = c.interference_score,
                        co = c.co_channel_count,
                        adj = c.adjacent_channel_count,
                        si = strongest,
                    )
                })
                .collect();
            format!(
                r#"<h2>Channel interference</h2>
<p style="color:#94a3b8;margin:0 0 6px">Recommended 2.4 GHz channel: <strong>{rec_24}</strong> · Recommended 5 GHz channel: <strong>{rec_5}</strong> · Current channel score: <strong>{cur}</strong> <span style="color:#64748b">(lower = quieter)</span></p>
<table>
<tr><th>Channel</th><th>Band</th><th>Score</th><th>Co-channel</th><th>Adjacent</th><th>Strongest</th></tr>
{rows}</table>"#
            )
        }
    };

    // ── PHY efficiency ────────────────────────────────────────────────────
    let phy_html: String = match &scan.phy_efficiency {
        None => String::new(),
        Some(p) => {
            let pct = (p.efficiency * 100.0).round();
            let rows = [
                ("PHY mode", html_escape(&p.phy_mode)),
                (
                    "Theoretical max",
                    format!("{:.0} Mb/s", p.theoretical_max_mbps),
                ),
                ("Actual TX rate", format!("{:.0} Mb/s", p.actual_mbps)),
                ("Efficiency", format!("{pct:.0}%")),
                ("Grade", html_escape(&p.grade)),
                ("Diagnostic", html_escape(&p.diagnostic)),
            ]
            .map(|(k, v)| (k, v));
            let body = dl_table(&rows);
            format!("<h2>PHY-rate efficiency</h2>{body}")
        }
    };

    // ── Roaming ───────────────────────────────────────────────────────────
    let roaming_html: String = match &scan.roaming {
        None => String::new(),
        Some(r) => {
            let summary = format!(
                "<p style=\"color:#94a3b8\">Roams in last hour: <strong>{}</strong> · last 24h: <strong>{}</strong> · avg dwell: <strong>{}</strong>{}</p>",
                r.events_last_hour,
                r.events_last_24h,
                r.avg_dwell_secs.map(|v| format!("{v} s")).unwrap_or_else(|| "—".into()),
                if r.sticky_warning { " · <span style=\"color:#f97316\">⚠ sticky client</span>" } else { "" },
            );
            let events = if r.recent_events.is_empty() {
                String::new()
            } else {
                let rows: String = r
                    .recent_events
                    .iter()
                    .map(|e| {
                        format!(
                            "<tr><td style=\"font-family:monospace;font-size:11px\">{ts}</td><td>{ssid}</td><td style=\"font-family:monospace\">{from}</td><td style=\"font-family:monospace\">{to}</td><td>{rssi}</td></tr>",
                            ts = e.at.format("%H:%M:%S"),
                            ssid = html_escape(e.ssid.as_deref().unwrap_or("—")),
                            from = html_escape(e.from_bssid.as_deref().unwrap_or("—")),
                            to = html_escape(e.to_bssid.as_deref().unwrap_or("—")),
                            rssi = e.rssi_at_roam_dbm.map(|v| format!("{v} dBm")).unwrap_or_else(|| "—".into()),
                        )
                    })
                    .collect();
                format!(
                    r#"<table><tr><th>Time</th><th>SSID</th><th>From</th><th>To</th><th>RSSI</th></tr>{rows}</table>"#
                )
            };
            format!("<h2>Roaming</h2>{summary}{events}")
        }
    };

    // ── Rogue / evil-twin ─────────────────────────────────────────────────
    let rogue_html: String = if scan.rogue_aps.is_empty() {
        String::new()
    } else {
        let rows: String = scan
            .rogue_aps
            .iter()
            .map(|r| {
                let color = severity_color(&r.severity);
                let bssids = r
                    .bssids
                    .iter()
                    .map(|b| format!("<code style=\"background:#0f172a;color:#cbd5e1;padding:1px 5px;border-radius:3px;font-size:11px;margin-right:3px\">{}</code>", html_escape(b)))
                    .collect::<String>();
                let secs = r
                    .security_modes
                    .iter()
                    .map(|s| html_escape(s))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(
                    "<tr><td style=\"color:{color}\">[{sev}]</td><td>{ssid}</td><td>{bssids}</td><td>{secs}</td><td>{reason}</td></tr>",
                    color = color,
                    sev = r.severity.as_str().to_uppercase(),
                    ssid = html_escape(&r.ssid),
                    bssids = bssids,
                    secs = secs,
                    reason = html_escape(&r.reason),
                )
            })
            .collect();
        format!(
            r#"<h2>Rogue / evil-twin APs ({n})</h2>
<table><tr><th>Severity</th><th>SSID</th><th>BSSIDs</th><th>Security modes</th><th>Reason</th></tr>{rows}</table>"#,
            n = scan.rogue_aps.len()
        )
    };

    // ── Alternate AP suggestion ───────────────────────────────────────────
    let alt_html: String = match &scan.alternate_ap {
        None => String::new(),
        Some(a) => {
            format!(
                r#"<h2>Better AP available</h2>
<div style="padding:10px 14px;background:#1a1a2e;border-left:4px solid #34d399;border-radius:0 6px 6px 0">
  <p style="margin:0">Stronger AP on <strong>{ssid}</strong>: roam from <code>{cur_b}</code> @ {cur_r} dBm to <code>{alt_b}</code> @ {alt_r} dBm <strong style="color:#34d399">(+{imp} dB)</strong>{ch}{band}</p>
</div>"#,
                ssid = html_escape(&a.ssid),
                cur_b = html_escape(a.current_bssid.as_deref().unwrap_or("—")),
                cur_r = a.current_rssi_dbm,
                alt_b = html_escape(&a.alternate_bssid),
                alt_r = a.alternate_rssi_dbm,
                imp = a.improvement_db,
                ch = a
                    .alternate_channel
                    .map(|v| format!(" · ch {v}"))
                    .unwrap_or_default(),
                band = a
                    .alternate_band
                    .as_deref()
                    .map(|b| format!(" · {}", html_escape(b)))
                    .unwrap_or_default(),
            )
        }
    };

    // ── Nearby APs ────────────────────────────────────────────────────────
    let nearby_html: String = if scan.nearby_aps.is_empty() {
        String::new()
    } else {
        let rows: String = scan
            .nearby_aps
            .iter()
            .map(|ap| {
                let ssid_label = match (ap.ssid.as_deref(), ap.name_redacted) {
                    (Some(s), true) => format!("{} <span style=\"color:#64748b;font-size:11px\">(hidden)</span>", html_escape(s)),
                    (Some(s), false) => html_escape(s),
                    (None, _) => "—".into(),
                };
                format!(
                    "<tr><td>{ssid}</td><td style=\"font-family:monospace\">{bssid}</td><td>{band}</td><td>{ch}</td><td>{width}</td><td>{rssi}</td><td>{sec}</td><td>{phy}</td><td>{vendor}</td></tr>",
                    ssid = ssid_label,
                    bssid = html_escape(ap.bssid.as_deref().unwrap_or("—")),
                    band = html_escape(ap.band.as_deref().unwrap_or("—")),
                    ch = ap.channel.map(|v| v.to_string()).unwrap_or_else(|| "—".into()),
                    width = ap.width_mhz.map(|v| format!("{v} MHz")).unwrap_or_else(|| "—".into()),
                    rssi = ap.rssi_dbm.map(|v| format!("{v} dBm")).unwrap_or_else(|| "—".into()),
                    sec = html_escape(ap.security.as_deref().unwrap_or("—")),
                    phy = html_escape(ap.phy_mode.as_deref().unwrap_or("—")),
                    vendor = html_escape(ap.vendor.as_deref().unwrap_or("—")),
                )
            })
            .collect();
        format!(
            r#"<h2>Nearby access points ({n})</h2>
<table><tr><th>SSID</th><th>BSSID</th><th>Band</th><th>Ch</th><th>Width</th><th>RSSI</th><th>Security</th><th>PHY</th><th>Vendor</th></tr>{rows}</table>"#,
            n = scan.nearby_aps.len(),
        )
    };

    // ── Trends ────────────────────────────────────────────────────────────
    let trends_html: String = match &scan.trends {
        None => String::new(),
        Some(t) => {
            if t.deltas.is_empty() {
                String::new()
            } else {
                let rows: String = t
                    .deltas
                    .iter()
                    .map(|d| {
                        let color = match d.direction.as_str() {
                            "improved" => "#34d399",
                            "degraded" => "#ef4444",
                            _ => "#94a3b8",
                        };
                        format!(
                            "<tr><td>{label}</td><td>{cur:.2}</td><td>{prev:.2}</td><td style=\"color:{color}\">{delta:+.2}</td><td style=\"color:{color}\">{dir}</td></tr>",
                            label = html_escape(&d.label),
                            cur = d.current,
                            prev = d.prev_hour_avg,
                            delta = d.delta,
                            color = color,
                            dir = html_escape(&d.direction),
                        )
                    })
                    .collect();
                format!(
                    r#"<h2>Trends (hour-over-hour, {n} samples)</h2>
<table><tr><th>Metric</th><th>Current</th><th>Prev-hour avg</th><th>Δ</th><th>Direction</th></tr>{rows}</table>"#,
                    n = t.samples_considered
                )
            }
        }
    };

    // ── AV-over-IP diagnostics ────────────────────────────────────────────
    let av_html: String = match av_diag {
        None => String::new(),
        Some(av) => {
            let warnings = if av.warnings.is_empty() {
                String::new()
            } else {
                let rows: String = av
                    .warnings
                    .iter()
                    .map(|w| {
                        let color = match w.severity.as_str() {
                            "critical" => "#ef4444",
                            "warn" | "warning" => "#f97316",
                            _ => "#3b82f6",
                        };
                        format!(
                            "<tr><td style=\"color:{color}\">[{sev}]</td><td>{cat}</td><td>{msg}</td></tr>",
                            color = color,
                            sev = html_escape(&w.severity).to_uppercase(),
                            cat = html_escape(&w.category),
                            msg = html_escape(&w.message),
                        )
                    })
                    .collect();
                format!(
                    "<h3>AV warnings</h3><table><tr><th>Severity</th><th>Category</th><th>Message</th></tr>{rows}</table>"
                )
            };
            let dante = if av.dante_devices.is_empty() {
                String::new()
            } else {
                let rows: String = av
                    .dante_devices
                    .iter()
                    .map(|d| {
                        let ports = d
                            .control_ports_open
                            .iter()
                            .map(|p| p.to_string())
                            .collect::<Vec<_>>()
                            .join(", ");
                        format!(
                            "<tr><td style=\"font-family:monospace\">{ip}</td><td>{host}</td><td>{model}</td><td>{mfr}</td><td>{tx}/{rx}</td><td>{sr}</td><td>{lat}</td><td>{red}</td><td>{wifi}</td><td>{ports}</td></tr>",
                            ip = html_escape(&d.ip),
                            host = html_escape(d.hostname.as_deref().unwrap_or("—")),
                            model = html_escape(d.model.as_deref().unwrap_or("—")),
                            mfr = html_escape(d.manufacturer.as_deref().unwrap_or("—")),
                            tx = d.tx_channels.map(|v| v.to_string()).unwrap_or_else(|| "—".into()),
                            rx = d.rx_channels.map(|v| v.to_string()).unwrap_or_else(|| "—".into()),
                            sr = d.sample_rate_hz.map(|v| format!("{v} Hz")).unwrap_or_else(|| "—".into()),
                            lat = d.latency_profile_ms.map(|v| format!("{v} ms")).unwrap_or_else(|| "—".into()),
                            red = html_escape(&d.redundancy),
                            wifi = if d.on_wifi { "<span style=\"color:#ef4444\">⚠ Wi-Fi</span>" } else { "wired" },
                            ports = ports,
                        )
                    })
                    .collect();
                format!(
                    "<h3>Dante / AES67 endpoints ({n})</h3><table><tr><th>IP</th><th>Host</th><th>Model</th><th>Mfr</th><th>TX/RX ch</th><th>SR</th><th>Lat</th><th>Redundancy</th><th>Transport</th><th>Ctrl ports</th></tr>{rows}</table>",
                    n = av.dante_devices.len(),
                )
            };
            let multicast = if av.multicast.is_empty() {
                String::new()
            } else {
                let rows: String = av
                    .multicast
                    .iter()
                    .map(|im| {
                        let groups: String = im
                            .groups
                            .iter()
                            .map(|g| {
                                format!(
                                    "<code style=\"background:#0f172a;color:#cbd5e1;padding:1px 5px;border-radius:3px;font-size:11px;margin:1px 3px 1px 0;display:inline-block\">{}<span style=\"color:#64748b\"> · {}</span></code>",
                                    html_escape(&g.group),
                                    html_escape(&g.purpose),
                                )
                            })
                            .collect();
                        format!(
                            "<tr><td style=\"font-family:monospace\">{iface}</td><td>{n}</td><td>{dante}</td><td>{ptp}</td><td>{groups}</td></tr>",
                            iface = html_escape(&im.iface),
                            n = im.group_count,
                            dante = im.dante_audio_groups,
                            ptp = im.ptp_groups,
                            groups = groups,
                        )
                    })
                    .collect();
                format!(
                    "<h3>Multicast groups</h3><table><tr><th>Interface</th><th>Groups</th><th>Dante audio</th><th>PTP</th><th>All</th></tr>{rows}</table>"
                )
            };
            let banner = format!(
                "<p style=\"color:#94a3b8\">Captured {ts} · DDM seen: <strong>{ddm}</strong> · AES67 seen: <strong>{aes}</strong></p>",
                ts = av.generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
                ddm = if av.ddm_seen { "yes" } else { "no" },
                aes = if av.aes67_seen { "yes" } else { "no" },
            );
            format!("<h2>AV-over-IP diagnostics</h2>{banner}{warnings}{dante}{multicast}")
        }
    };

    // ── Deep probes (IGMP / PTP / DSCP / LLDP / link audit / SAP) ─────────
    let deep_html: String = match deep_probe {
        None => String::new(),
        Some(dp) => {
            let mut sections: Vec<String> = Vec::new();
            if let Some(i) = &dp.igmp {
                let queriers = if i.queriers_seen.is_empty() {
                    "<em>none observed</em>".to_string()
                } else {
                    i.queriers_seen
                        .iter()
                        .map(|q| {
                            format!(
                                "<li>from <code>{from}</code> v{ver} group <code>{grp}</code> (MRT {mrt} ds)</li>",
                                from = html_escape(&q.from),
                                ver = q.version,
                                grp = html_escape(&q.group),
                                mrt = q.max_resp_ds,
                            )
                        })
                        .collect::<String>()
                };
                sections.push(format!(
                    "<h3>IGMP listen ({secs}s on {iface})</h3><p>Verdict: <strong>{verdict}</strong> · reports {rep} · leaves {lv}{err}</p><ul>{queriers}</ul>",
                    iface = html_escape(&i.iface),
                    secs = i.listen_secs,
                    verdict = html_escape(&i.verdict),
                    rep = i.reports_seen,
                    lv = i.leaves_seen,
                    err = i.error.as_deref().map(|e| format!(" · error: {}", html_escape(e))).unwrap_or_default(),
                    queriers = queriers,
                ));
            }
            if let Some(p) = &dp.ptp {
                let domains: String = p
                    .domains
                    .iter()
                    .map(|d| {
                        let gms: String = d
                            .grandmasters
                            .iter()
                            .map(|gm| {
                                format!(
                                    "<li><code>{cid}</code> · class {cc} · acc {ca} · priority1 {p1} · src {src} · {seen} announces</li>",
                                    cid = html_escape(&gm.clock_identity),
                                    cc = gm.clock_class,
                                    ca = gm.clock_accuracy,
                                    p1 = gm.priority1,
                                    src = html_escape(&gm.source_ip),
                                    seen = gm.announces_seen,
                                )
                            })
                            .collect();
                        format!(
                            "<li>Domain {dn} v{v} · profile {pr} · transport {tr} · announce log2 {al} · sync log2 {sl} · {sa} syncs{jit}<ul>{gms}</ul></li>",
                            dn = d.domain_number,
                            v = d.version,
                            pr = html_escape(&d.profile),
                            tr = html_escape(&d.transport),
                            al = d.announce_interval_log2,
                            sl = d.sync_interval_log2,
                            sa = d.sync_arrivals,
                            jit = d.sync_jitter_us.map(|v| format!(" · jitter {v:.1} µs")).unwrap_or_default(),
                            gms = gms,
                        )
                    })
                    .collect();
                sections.push(format!(
                    "<h3>PTP listen ({secs}s on {iface})</h3><p>Verdict: <strong>{verdict}</strong> · {gms} grandmaster(s){comp}{err}</p><ul>{domains}</ul>",
                    iface = html_escape(&p.iface),
                    secs = p.listen_secs,
                    verdict = html_escape(&p.verdict),
                    gms = p.grandmaster_count,
                    comp = if p.competing_gm_observed { " · <span style=\"color:#ef4444\">⚠ competing GMs</span>" } else { "" },
                    err = p.error.as_deref().map(|e| format!(" · error: {}", html_escape(e))).unwrap_or_default(),
                    domains = domains,
                ));
            }
            if let Some(d) = &dp.dscp {
                let obs: String = d
                    .observations
                    .iter()
                    .map(|o| {
                        format!(
                            "<tr><td>{kind}</td><td style=\"font-family:monospace\">{grp}</td><td>{n}</td><td>{med}</td><td>{exp}</td><td>{ttl_med} / {ttl_min}</td></tr>",
                            kind = html_escape(&o.stream_kind),
                            grp = html_escape(&o.dst_group),
                            n = o.packets,
                            med = o.dscp_median,
                            exp = o.dscp_expected,
                            ttl_med = o.ttl_median,
                            ttl_min = o.ttl_min,
                        )
                    })
                    .collect();
                sections.push(format!(
                    "<h3>DSCP / TTL audit ({secs}s on {iface})</h3><p>Verdict: <strong>{verdict}</strong>{err}</p><table><tr><th>Stream</th><th>Group</th><th>Pkts</th><th>DSCP median</th><th>Expected</th><th>TTL med/min</th></tr>{obs}</table>",
                    iface = html_escape(&d.iface),
                    secs = d.listen_secs,
                    verdict = html_escape(&d.verdict),
                    err = d.error.as_deref().map(|e| format!(" · error: {}", html_escape(e))).unwrap_or_default(),
                    obs = obs,
                ));
            }
            if let Some(l) = &dp.lldp {
                let nb: String = l
                    .neighbors
                    .iter()
                    .map(|n| {
                        let caps = n.capabilities.iter().map(|c| html_escape(c)).collect::<Vec<_>>().join(", ");
                        format!(
                            "<tr><td>{via}</td><td style=\"font-family:monospace\">{mac}</td><td>{ip}</td><td>{name}</td><td>{port}</td><td>{vlan}</td><td>{vendor}</td><td>{caps}</td></tr>",
                            via = html_escape(&n.via),
                            mac = html_escape(&n.source_mac),
                            ip = html_escape(n.source_ip.as_deref().unwrap_or("—")),
                            name = html_escape(n.system_name.as_deref().unwrap_or("—")),
                            port = html_escape(n.port_id.as_deref().unwrap_or("—")),
                            vlan = n.vlan_id.map(|v| v.to_string()).unwrap_or_else(|| "—".into()),
                            vendor = html_escape(n.oui_vendor.as_deref().unwrap_or("—")),
                            caps = caps,
                        )
                    })
                    .collect();
                sections.push(format!(
                    "<h3>LLDP / CDP / ARP ({secs}s on {iface}, via {mech})</h3><p>Verdict: <strong>{verdict}</strong>{err}</p><table><tr><th>Via</th><th>MAC</th><th>IP</th><th>System</th><th>Port</th><th>VLAN</th><th>Vendor</th><th>Capabilities</th></tr>{nb}</table>",
                    iface = html_escape(&l.iface),
                    secs = l.listen_secs,
                    mech = html_escape(&l.mechanism),
                    verdict = html_escape(&l.verdict),
                    err = l.error.as_deref().map(|e| format!(" · error: {}", html_escape(e))).unwrap_or_default(),
                    nb = nb,
                ));
            }
            if let Some(la) = &dp.link_audit {
                let issues = if la.issues.is_empty() {
                    String::new()
                } else {
                    let items: String = la
                        .issues
                        .iter()
                        .map(|i| format!("<li>{}</li>", html_escape(i)))
                        .collect();
                    format!("<p style=\"margin:4px 0\">Issues:</p><ul>{items}</ul>")
                };
                let rows = [
                    (
                        "Link speed",
                        opt_fmt(&la.link_speed_mbps, |v| format!("{v} Mb/s")),
                    ),
                    ("Duplex", opt_str(&la.duplex)),
                    (
                        "EEE enabled",
                        opt_fmt(
                            &la.eee_enabled,
                            |v| if *v { "yes".into() } else { "no".into() },
                        ),
                    ),
                    (
                        "Flow control RX",
                        opt_fmt(&la.flow_control_rx, |v| {
                            if *v {
                                "yes".into()
                            } else {
                                "no".into()
                            }
                        }),
                    ),
                    (
                        "Flow control TX",
                        opt_fmt(&la.flow_control_tx, |v| {
                            if *v {
                                "yes".into()
                            } else {
                                "no".into()
                            }
                        }),
                    ),
                    ("MTU", opt_fmt(&la.mtu, |v| format!("{v} bytes"))),
                ];
                let body = dl_table(&rows);
                sections.push(format!(
                    "<h3>Link audit ({iface})</h3><p>Verdict: <strong>{verdict}</strong>{err}</p>{body}{issues}",
                    iface = html_escape(&la.iface),
                    verdict = html_escape(&la.verdict),
                    err = la.error.as_deref().map(|e| format!(" · error: {}", html_escape(e))).unwrap_or_default(),
                    body = body,
                    issues = issues,
                ));
            }
            if let Some(s) = &dp.sap {
                let streams: String = s
                    .streams
                    .iter()
                    .map(|st| {
                        format!(
                            "<tr><td>{name}</td><td>{origin}</td><td style=\"font-family:monospace\">{src}</td><td style=\"font-family:monospace\">{grp}</td><td>{port}</td><td>{sr}</td><td>{ch}</td><td>{pt}</td></tr>",
                            name = html_escape(&st.session_name),
                            origin = html_escape(&st.origin),
                            src = html_escape(&st.source_ip),
                            grp = html_escape(st.multicast_group.as_deref().unwrap_or("—")),
                            port = st.port.map(|v| v.to_string()).unwrap_or_else(|| "—".into()),
                            sr = st.sample_rate_hz.map(|v| format!("{v} Hz")).unwrap_or_else(|| "—".into()),
                            ch = st.channels.map(|v| v.to_string()).unwrap_or_else(|| "—".into()),
                            pt = st.ptime_ms.map(|v| format!("{v:.2} ms")).unwrap_or_else(|| "—".into()),
                        )
                    })
                    .collect();
                sections.push(format!(
                    "<h3>SAP / SDP listen ({secs}s on {iface})</h3><p>Verdict: <strong>{verdict}</strong>{err}</p><table><tr><th>Session</th><th>Origin</th><th>Source IP</th><th>Group</th><th>Port</th><th>SR</th><th>Ch</th><th>ptime</th></tr>{streams}</table>",
                    iface = html_escape(&s.iface),
                    secs = s.listen_secs,
                    verdict = html_escape(&s.verdict),
                    err = s.error.as_deref().map(|e| format!(" · error: {}", html_escape(e))).unwrap_or_default(),
                    streams = streams,
                ));
            }
            if sections.is_empty() {
                String::new()
            } else {
                format!(
                    "<h2>Deep probes</h2><p style=\"color:#94a3b8\">Captured {ran}</p>{body}",
                    ran = html_escape(&dp.ran_at),
                    body = sections.join("")
                )
            }
        }
    };

    // ── Stress tests ──────────────────────────────────────────────────────
    let stress_html: String = if stress_results.is_empty() {
        String::new()
    } else {
        let cards: String = stress_results
            .iter()
            .map(|s| {
                let color = if s.success { "#34d399" } else { "#ef4444" };
                let st = &s.stats;
                let stats_row = format!(
                    "attempts {a} · ok {ok} · fail {fail} · min {min} · avg {avg} · p95 {p95} · max {max} · jitter {jit} · loss {loss}",
                    a = st.attempted,
                    ok = st.succeeded,
                    fail = st.failed,
                    min = st.min_ms.map(|v| format!("{v:.1} ms")).unwrap_or_else(|| "—".into()),
                    avg = st.avg_ms.map(|v| format!("{v:.1} ms")).unwrap_or_else(|| "—".into()),
                    p95 = st.p95_ms.map(|v| format!("{v:.1} ms")).unwrap_or_else(|| "—".into()),
                    max = st.max_ms.map(|v| format!("{v:.1} ms")).unwrap_or_else(|| "—".into()),
                    jit = st.jitter_ms.map(|v| format!("{v:.1} ms")).unwrap_or_else(|| "—".into()),
                    loss = st.loss_pct.map(|v| format!("{v:.1}%")).unwrap_or_else(|| "—".into()),
                );
                let details: String = s
                    .details
                    .iter()
                    .map(|d| format!("<li>{}</li>", html_escape(d)))
                    .collect();
                format!(
                    r#"<div style="border-left:4px solid {color};padding:8px 12px;margin:8px 0;background:#1a1a2e;border-radius:0 6px 6px 0">
  <div style="display:flex;justify-content:space-between;gap:12px">
    <strong>{label}</strong>
    <span style="color:#64748b;font-family:monospace;font-size:11px">{kind} · {dur} ms · {ts}</span>
  </div>
  <p style="margin:6px 0 4px;color:#cbd5e1">{headline}</p>
  <p style="margin:0 0 4px;color:#94a3b8;font-size:12px;font-family:monospace">{stats}</p>
  <ul style="margin:0 0 0 18px;color:#cbd5e1">{details}</ul>
</div>"#,
                    color = color,
                    label = html_escape(&s.label),
                    kind = html_escape(&s.kind),
                    dur = s.duration_ms,
                    ts = s.started_at.format("%H:%M:%S"),
                    headline = html_escape(&s.headline),
                    stats = stats_row,
                    details = details,
                )
            })
            .collect();
        format!(
            "<h2>Active stress tests ({n})</h2>{cards}",
            n = stress_results.len()
        )
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>WiFi Diagnostic Report — {started}</title>
<style>
  body {{ font-family: system-ui, sans-serif; background: #0f0f1a; color: #e2e8f0;
         max-width: 900px; margin: 0 auto; padding: 24px; }}
  h1 {{ color: #818cf8; }} h2 {{ color: #94a3b8; border-bottom: 1px solid #334155; padding-bottom: 4px; margin-top: 28px; }}
  table {{ border-collapse: collapse; width: 100%; }} th, td {{ padding: 6px 10px; text-align: left; border: 1px solid #334155; }}
  th {{ background: #1e293b; }} tr:nth-child(even) {{ background: #141428; }}
  .toolbar {{ position: sticky; top: 0; background: #0f0f1a; padding: 8px 0;
              border-bottom: 1px solid #1e293b; margin: -8px 0 16px;
              display: flex; gap: 8px; align-items: center; }}
  .toolbar button {{ background: #4f46e5; color: white; border: 0;
                     padding: 8px 16px; border-radius: 6px; cursor: pointer;
                     font-size: 14px; font-weight: 500; }}
  .toolbar button:hover {{ background: #6366f1; }}
  @media print {{
    body {{ background: white; color: #111; max-width: none; padding: 12mm; }}
    h1, h2 {{ color: #1e293b; }}
    h2 {{ border-bottom-color: #cbd5e1; page-break-after: avoid; }}
    table {{ page-break-inside: auto; }}
    tr {{ page-break-inside: avoid; page-break-after: auto; }}
    th {{ background: #f1f5f9; color: #0f172a; }}
    td {{ background: white !important; color: #0f172a !important; }}
    div[style*="background:#1a1a2e"] {{ background: #f8fafc !important; color: #0f172a !important; }}
    div[style*="background:#1a1a2e"] * {{ color: #0f172a !important; }}
    .toolbar {{ display: none !important; }}
    svg {{ background: white !important; }}
    footer {{ color: #475569 !important; }}
  }}
</style>
</head>
<body>
<div class="toolbar">
  <button onclick="window.print()">🖨 Print / Save as PDF</button>
  <span style="color:#64748b;font-size:13px">— Use your browser's print dialog to save as PDF</span>
</div>
<h1>📡 WiFi Diagnostic Report</h1>
<p>{portal}<strong>Scan:</strong> {started} → {finished}<br>
<strong>SSID:</strong> {ssid} &nbsp; <strong>RSSI:</strong> {rssi} dBm &nbsp;
<strong>Gateway latency:</strong> {gw_ms} &nbsp; <strong>Loss:</strong> {loss}{badges}</p>

{link}

{reach}

{extras}

{wan}

{quality}

{phy}

{interference}

{alt}

{roaming}

{rogue}

{nearby}

{trends}

{telemetry}

{narratives}

<h2>Findings ({n_findings})</h2>
{findings}

{recs_section}

{wifi_events}

{av}

{deep}

{stress}

<h2>Devices ({n_devices})</h2>
<table>
<tr><th></th><th>MAC</th><th>IP</th><th>Hostname</th><th>Class</th><th>Vendor</th><th>Latency</th><th>Services</th></tr>
{devices}
</table>

{services}

<footer style="margin-top:32px;color:#475569;font-size:12px">
  Generated by Atlas · {generated}
</footer>
</body></html>"#,
        started = scan.started_at.format("%Y-%m-%d %H:%M:%S UTC"),
        finished = scan.finished_at.format("%H:%M:%S UTC"),
        portal = portal_badge,
        ssid = html_escape(scan.link.ssid.as_deref().unwrap_or("—")),
        rssi = scan
            .link
            .rssi_dbm
            .map(|v| v.to_string())
            .unwrap_or_else(|| "—".into()),
        gw_ms = scan
            .reachability
            .gateway_latency_ms
            .map(|v| format!("{v:.0} ms"))
            .unwrap_or_else(|| "—".into()),
        loss = scan
            .reachability
            .packet_loss_pct
            .map(|v| format!("{v:.0}%"))
            .unwrap_or_else(|| "—".into()),
        badges = {
            let mut b = String::new();
            if scan.dns_leak {
                b.push_str(" &nbsp; <span style='background:#ef4444;color:#fff;padding:2px 8px;border-radius:4px'>⚠ DNS leak</span>");
            }
            if let Some(mtu) = scan.mtu_bytes {
                b.push_str(&format!(" &nbsp; <span style='background:#1e293b;color:#cbd5e1;padding:2px 8px;border-radius:4px'>MTU {mtu}</span>"));
            }
            if let Some(spd) = scan.speed_mbps {
                b.push_str(&format!(" &nbsp; <span style='background:#065f46;color:#a7f3d0;padding:2px 8px;border-radius:4px'>{spd:.0} Mb/s</span>"));
            }
            b
        },
        link = link_html,
        reach = reach_html,
        extras = extras_html,
        wan = wan_html,
        quality = quality_html,
        phy = phy_html,
        interference = interference_html,
        alt = alt_html,
        roaming = roaming_html,
        rogue = rogue_html,
        nearby = nearby_html,
        trends = trends_html,
        telemetry = telemetry_html,
        narratives = narratives_html,
        n_findings = scan.findings.len(),
        findings = findings_html,
        recs_section = if scan.recommendations.is_empty() {
            String::new()
        } else {
            format!(
                "<h2>Recommendations ({})</h2>{}",
                scan.recommendations.len(),
                recs_html
            )
        },
        wifi_events = wifi_events_html,
        av = av_html,
        deep = deep_html,
        stress = stress_html,
        n_devices = scan.devices.len(),
        devices = devices_html,
        services = service_html,
        generated = Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ── Update check ──────────────────────────────────────────────────────────────

/// Check if an application update is available.
/// NOTE: Requires the updater plugin to be configured with a valid pubkey for release builds.
/// In dev mode this always returns available: false.
#[tauri::command]
pub async fn check_for_update(_app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    // The tauri-plugin-updater requires both (a) `.plugin(updater::Builder::new().build())`
    // wired into the tauri::Builder chain AND (b) a release signing pubkey
    // baked into tauri.conf.json. Neither is configured yet, and calling
    // `app.updater()` without the plugin panics with "state() called before
    // manage() for UpdaterState" — which crashes a tokio worker and can take
    // sibling background tasks (sampler, monitor) with it. Until a signing
    // keypair is generated, this is a hard-coded no-op.
    Ok(serde_json::json!({ "available": false }))
}

// ── Demo data ─────────────────────────────────────────────────────────────────

pub fn demo_devices() -> Vec<DeviceInfo> {
    let now = Utc::now();
    vec![
        DeviceInfo {
            mac: "a4:2b:b0:11:22:33".into(),
            ip: Some("192.168.1.1".into()),
            hostname: Some("router".into()),
            vendor: Some("Ubiquiti".into()),
            class: DeviceClass::RouterAp,
            first_seen: now,
            last_seen: now,
            online: true,
            latency_ms: Some(1.8),
            services: vec![],
        },
        DeviceInfo {
            mac: "00:1a:7d:da:71:11".into(),
            ip: Some("192.168.1.42".into()),
            hostname: Some("Clover-Mini-01".into()),
            vendor: Some("Clover Network".into()),
            class: DeviceClass::PosTerminal,
            first_seen: now,
            last_seen: now,
            online: false,
            latency_ms: None,
            services: vec![],
        },
        DeviceInfo {
            mac: "b8:27:eb:00:00:aa".into(),
            ip: Some("192.168.1.84".into()),
            hostname: Some("kitchen-printer".into()),
            vendor: Some("Epson".into()),
            class: DeviceClass::Printer,
            first_seen: now,
            last_seen: now,
            online: true,
            latency_ms: Some(6.4),
            services: vec!["_ipp._tcp".into(), "_ipps._tcp".into()],
        },
        DeviceInfo {
            mac: "ec:fa:bc:55:66:77".into(),
            ip: Some("192.168.1.121".into()),
            hostname: Some("front-camera".into()),
            vendor: Some("Reolink".into()),
            class: DeviceClass::IpCamera,
            first_seen: now,
            last_seen: now,
            online: false,
            latency_ms: None,
            services: vec![],
        },
        DeviceInfo {
            mac: "d8:f1:5b:aa:bb:cc".into(),
            ip: Some("192.168.1.150".into()),
            hostname: Some("smart-bulb-1".into()),
            vendor: Some("TP-Link".into()),
            class: DeviceClass::SmartHome,
            first_seen: now,
            last_seen: now,
            online: true,
            latency_ms: Some(38.1),
            services: vec![],
        },
    ]
}

// =========================================================================
// AV-over-IP diagnostics commands (Tier 1 + Tier 2 + Tier 3 scaffold)
// =========================================================================

/// Run the unprivileged AV-over-IP diagnostic sweep: Dante / AES67 mDNS
/// browse, per-interface multicast snapshot, TCP reachability check, and
/// heuristic warning generation. Takes the most recent scan (if any) so we
/// can cross-reference Dante endpoints against the host's Wi-Fi subnet.
///
/// `iface` pins every probe to a specific NIC (e.g. `"en4"`). When the
/// frontend passes `None` we fall back to `Settings.preferred_interface`;
/// when that's also empty the probes use the kernel-default routing (the
/// previous behaviour).
#[tauri::command]
pub async fn run_av_diagnostics(
    state: State<'_, AppState>,
    last_scan: Option<ScanResult>,
    iface: Option<String>,
) -> Result<AvDiagnosticsResult, String> {
    let resolved = resolved_iface(&state, iface.as_deref());
    let result = crate::probes::av::collect(last_scan.as_ref(), resolved.as_deref()).await;
    // Stash the result so `export_report` can include it without the
    // frontend having to re-pass it on every call.
    *state.last_av_diagnostics.lock() = Some(result.clone());
    Ok(result)
}

/// List every network interface the host kernel currently exposes, so the
/// settings UI can render a picker for `preferred_interface`. Loopback
/// and admin-down interfaces are returned too — the frontend filters
/// them out so the same list can be reused by future diagnostics.
#[tauri::command]
pub async fn list_network_interfaces(
) -> Result<Vec<crate::probes::iface::NetworkInterfaceInfo>, String> {
    Ok(crate::probes::iface::list_interfaces())
}

/// Resolve the active NIC for any iface-aware probe: explicit argument
/// wins, then the persisted global pin (`Settings.preferred_interface`),
/// then `None` (kernel default). Empty / "auto" strings normalise to
/// `None`. Shared by AV diagnostics, the deep probes, and traceroute so
/// every iface-pinned subsystem sees the same NIC the user picked in
/// the global header.
pub(crate) fn resolved_iface(
    state: &State<'_, AppState>,
    explicit: Option<&str>,
) -> Option<String> {
    let normalise = |s: &str| {
        let t = s.trim();
        if t.is_empty() || t.eq_ignore_ascii_case("auto") {
            None
        } else {
            Some(t.to_string())
        }
    };
    if let Some(v) = explicit.and_then(normalise) {
        return Some(v);
    }
    Settings::load(&state.settings_path)
        .ok()
        .and_then(|s| normalise(&s.preferred_interface))
}

/// Run a privileged deep probe (currently only `igmp-listen` is wired) by
/// re-execing the current binary as an elevated child:
///   - **macOS** — `osascript ... with administrator privileges`. The
///     elevated helper writes the JSON `IgmpProbeResult` to stdout.
///   - **Windows** — `powershell.exe Start-Process -Verb RunAs` (triggers
///     a UAC prompt). Stdout cannot cross an elevation boundary cleanly,
///     so the helper writes JSON to a `--probe-out <path>` temp file
///     which the parent reads after `-Wait`.
///   - **Linux** — `pkexec` (falls back to `sudo -A` if pkexec is
///     missing). The elevated helper writes JSON to a temp file because
///     pkexec's environment scrubbing and the askpass agent's stdio
///     handling are unreliable for binary capture.
#[tauri::command]
pub async fn run_deep_probes(
    state: State<'_, AppState>,
    kind: String,
    iface: Option<String>,
) -> Result<DeepProbeResult, String> {
    let iface = resolved_iface(&state, iface.as_deref()).unwrap_or_else(|| "en0".to_string());
    let exe = std::env::current_exe()
        .map_err(|e| format!("locate current exe: {e}"))?
        .to_string_lossy()
        .to_string();
    let ran_at = chrono::Utc::now().to_rfc3339();
    let mut out = DeepProbeResult {
        ran_at: ran_at.clone(),
        ..Default::default()
    };

    match kind.as_str() {
        "igmp-listen" => {
            // 260s (~2x the RFC-3376 125s General Query interval) reliably
            // catches a healthy querier even when the listen starts just
            // after a query. A shorter ~130s window has a meaningful chance
            // of missing the query and producing a false "no querier"
            // verdict on a perfectly healthy network.
            let json = elevate_and_run_probe(&exe, "igmp-listen", &iface, 260).await?;
            let igmp: IgmpProbeResult = serde_json::from_str(json.trim())
                .map_err(|e| format!("parse IgmpProbeResult: {e}; raw={json:?}"))?;
            out.igmp = Some(igmp);
        }
        "ptp-listen" => {
            // PTP-over-UDP (L3) binds unprivileged, but PTP-over-Ethernet
            // (L2, ethertype 0x88F7 — SMPTE 2110 / AVB gPTP) needs a BPF
            // capture that requires root. On macOS we therefore run the
            // probe elevated so it observes BOTH transports; elsewhere L2
            // capture isn't implemented, so we stay unprivileged.
            #[cfg(target_os = "macos")]
            {
                let json = elevate_and_run_probe(&exe, "ptp-listen", &iface, 12).await?;
                let ptp: PtpProbeResult = serde_json::from_str(json.trim())
                    .map_err(|e| format!("parse PtpProbeResult: {e}; raw={json:?}"))?;
                out.ptp = Some(ptp);
            }
            #[cfg(not(target_os = "macos"))]
            {
                let i = iface.clone();
                let ptp =
                    tokio::task::spawn_blocking(move || crate::probes::ptp::run_blocking(&i, 12))
                        .await
                        .map_err(|e| format!("ptp join: {e}"))?;
                out.ptp = Some(ptp);
            }
        }
        "dscp-audit" => {
            #[cfg(unix)]
            {
                let i = iface.clone();
                let dscp =
                    tokio::task::spawn_blocking(move || crate::probes::dscp::run_blocking(&i, 12))
                        .await
                        .map_err(|e| format!("dscp join: {e}"))?;
                out.dscp = Some(dscp);
            }
            #[cfg(windows)]
            {
                let json = elevate_and_run_probe(&exe, "dscp-audit", &iface, 12).await?;
                let dscp: crate::types::DscpProbeResult = serde_json::from_str(json.trim())
                    .map_err(|e| format!("parse DscpProbeResult: {e}; raw={json:?}"))?;
                out.dscp = Some(dscp);
            }
        }
        "lldp-listen" => {
            // ARP+OUI fallback runs unprivileged on every platform.
            let i = iface.clone();
            let lldp =
                tokio::task::spawn_blocking(move || crate::probes::lldp::run_blocking(&i, 12))
                    .await
                    .map_err(|e| format!("lldp join: {e}"))?;
            out.lldp = Some(lldp);
        }
        "link-audit" => {
            let i = iface.clone();
            let link =
                tokio::task::spawn_blocking(move || crate::probes::linkaudit::run_blocking(&i))
                    .await
                    .map_err(|e| format!("linkaudit join: {e}"))?;
            out.link_audit = Some(link);
        }
        "sap-listen" => {
            let i = iface.clone();
            let sap = tokio::task::spawn_blocking(move || crate::probes::sap::run_blocking(&i, 8))
                .await
                .map_err(|e| format!("sap join: {e}"))?;
            out.sap = Some(sap);
        }
        "all" => {
            // Spawn every unprivileged probe in parallel and combine
            // all privileged probes into a single elevated dispatch so
            // the operator sees at most ONE auth prompt.
            let i = iface.clone();
            let ptp_h =
                tokio::task::spawn_blocking(move || crate::probes::ptp::run_blocking(&i, 12));
            let i = iface.clone();
            let sap_h =
                tokio::task::spawn_blocking(move || crate::probes::sap::run_blocking(&i, 8));
            let i = iface.clone();
            let link_h =
                tokio::task::spawn_blocking(move || crate::probes::linkaudit::run_blocking(&i));
            let i = iface.clone();
            let lldp_h =
                tokio::task::spawn_blocking(move || crate::probes::lldp::run_blocking(&i, 12));
            #[cfg(unix)]
            let dscp_h = {
                let i = iface.clone();
                Some(tokio::task::spawn_blocking(move || {
                    crate::probes::dscp::run_blocking(&i, 12)
                }))
            };
            #[cfg(windows)]
            let dscp_h: Option<tokio::task::JoinHandle<crate::types::DscpProbeResult>> = None;

            // Single elevated dispatch covering everything that needs root.
            // On Unix that's just IGMP. On Windows we'd also bundle DSCP
            // here, but for v1 DSCP on Windows runs separately as part
            // of its own kind invocation if requested. The `all` mode
            // here therefore only elevates for IGMP.
            //
            // 260s (~2x the RFC-3376 125s General Query interval) reliably
            // catches a healthy querier even when the listen starts just
            // after a query. MUST match the standalone igmp-listen branch
            // above or "Run all" results will look misleadingly silent
            // vs. "Test IGMP".
            const IGMP_LISTEN_SECS: u32 = 260;
            let igmp_fut = elevate_and_run_probe(&exe, "igmp-listen", &iface, IGMP_LISTEN_SECS);

            let (ptp_r, sap_r, link_r, lldp_r, igmp_json) =
                tokio::join!(ptp_h, sap_h, link_h, lldp_h, igmp_fut);

            out.ptp = ptp_r.ok();
            out.sap = sap_r.ok();
            out.link_audit = link_r.ok();
            out.lldp = lldp_r.ok();
            match igmp_json {
                Ok(json) => match serde_json::from_str::<IgmpProbeResult>(json.trim()) {
                    Ok(v) => out.igmp = Some(v),
                    Err(e) => {
                        out.igmp = Some(IgmpProbeResult {
                            iface: iface.clone(),
                            listen_secs: IGMP_LISTEN_SECS,
                            queriers_seen: Vec::new(),
                            reports_seen: 0,
                            leaves_seen: 0,
                            verdict: "error".to_string(),
                            detail: None,
                            error: Some(format!("parse IgmpProbeResult: {e}")),
                        });
                    }
                },
                Err(e) => {
                    out.igmp = Some(IgmpProbeResult {
                        iface: iface.clone(),
                        listen_secs: IGMP_LISTEN_SECS,
                        queriers_seen: Vec::new(),
                        reports_seen: 0,
                        leaves_seen: 0,
                        verdict: "error".to_string(),
                        detail: None,
                        error: Some(e),
                    });
                }
            }
            if let Some(h) = dscp_h {
                if let Ok(d) = h.await {
                    out.dscp = Some(d);
                }
            }
        }
        other => return Err(format!("unsupported deep probe kind: {other}")),
    }

    // Merge `out` into the AppState cache so the printable report can
    // include every probe the operator has ever run during this session.
    // Each invocation typically populates exactly one of the optional
    // fields; we keep prior fields untouched so a "sap-listen" run
    // doesn't blow away an earlier "lldp-listen" result.
    {
        let mut guard = state.last_deep_probe.lock();
        let merged = match guard.take() {
            Some(prev) => DeepProbeResult {
                ran_at: out.ran_at.clone(),
                igmp: out.igmp.clone().or(prev.igmp),
                ptp: out.ptp.clone().or(prev.ptp),
                dscp: out.dscp.clone().or(prev.dscp),
                lldp: out.lldp.clone().or(prev.lldp),
                link_audit: out.link_audit.clone().or(prev.link_audit),
                sap: out.sap.clone().or(prev.sap),
            },
            None => out.clone(),
        };
        *guard = Some(merged);
    }

    Ok(out)
}

use crate::probes::elevate::elevate_and_run_probe;

/// Ask the configured LLM for AV-over-IP issues + suggestions. Returns
/// raw JSON text (`{ "items": [...] }`) for the frontend to parse.
#[tauri::command]
pub async fn av_insights(
    state: State<'_, AppState>,
    av: AvDiagnosticsResult,
    scan_result: Option<ScanResult>,
) -> Result<String, String> {
    let settings = Settings::load(&state.settings_path).map_err(|e| e.to_string())?;
    let provider = settings.llm_provider.as_deref().unwrap_or("openai");
    let api_key = resolve_api_key(provider, settings.llm_api_key.clone())?;
    let model = settings
        .llm_model
        .clone()
        .unwrap_or_else(|| default_model(provider));
    let base_url = resolve_base_url(provider, settings.llm_base_url.clone());

    crate::llm::av_insights(
        provider,
        &api_key,
        &model,
        base_url.as_deref(),
        &av,
        scan_result.as_ref(),
    )
    .await
    .map_err(|e| e.to_string())
}

// ── Runbook engine commands ──────────────────────────────────────────────────

/// Brief shape returned to the UI so the operator can pick a runbook
/// without having to load every step body.
#[derive(serde::Serialize, Clone, Debug)]
pub struct RunbookSummary {
    pub id: String,
    pub name: String,
    pub category: String,
    pub description: String,
    pub applies_to: Vec<String>,
    pub symptoms: Vec<String>,
    pub step_count: usize,
}

fn summarise(rb: &crate::runbook::Runbook) -> RunbookSummary {
    RunbookSummary {
        id: rb.id.clone(),
        name: rb.name.clone(),
        category: rb.category.clone(),
        description: rb.description.clone(),
        applies_to: rb.applies_to.clone(),
        symptoms: rb.symptoms.clone(),
        step_count: rb.steps.len(),
    }
}

/// List every bundled runbook (no engine instance required — the library
/// is parsed at startup inside `Engine::new`).
#[tauri::command]
pub async fn list_runbooks(state: State<'_, AppState>) -> Result<Vec<RunbookSummary>, String> {
    let engine =
        crate::runbook::engine::Engine::new(None).with_user_runbooks(&state.user_runbooks_dir);
    Ok(engine.list_runbooks().into_iter().map(summarise).collect())
}

/// Heuristic best-match runbook for a free-form symptom string. Falls back
/// to the LLM picker when no heuristic match is good enough AND the LLM
/// is configured.
#[tauri::command]
pub async fn pick_runbook(
    state: State<'_, AppState>,
    symptom: String,
) -> Result<Option<RunbookSummary>, String> {
    let engine =
        crate::runbook::engine::Engine::new(None).with_user_runbooks(&state.user_runbooks_dir);
    let books = engine.list_runbooks();

    // Deterministic token-overlap match first (same matcher that powers the
    // AV "Diagnose with…" suggestions). This handles clear natural-language
    // symptoms like "I'm getting Dante audio dropouts" offline and instantly,
    // weighting declared symptoms / tags over name over description.
    let query = runbook_tokens(&symptom);
    if !query.is_empty() {
        let mut best: Option<(i32, i32, &crate::runbook::Runbook)> = None;
        for rb in &books {
            let (score, strong) = score_runbook(rb, &query);
            if score < 6 || strong < 2 {
                continue;
            }
            let replace = match best {
                None => true,
                Some((bs, bst, brb)) => {
                    score > bs
                        || (score == bs && strong > bst)
                        || (score == bs && strong == bst && rb.id < brb.id)
                }
            };
            if replace {
                best = Some((score, strong, rb));
            }
        }
        if let Some((_, _, rb)) = best {
            return Ok(Some(summarise(rb)));
        }
    }

    // LLM fallback (best-effort) — lets the model interpret looser or more
    // ambiguous descriptions the deterministic matcher couldn't place.
    let settings = Settings::load(&state.settings_path).map_err(|e| e.to_string())?;
    let provider = settings.llm_provider.as_deref().unwrap_or("ollama");
    let key = match resolve_api_key(provider, settings.llm_api_key.clone()) {
        Ok(k) => k,
        Err(_) => return Ok(None),
    };
    let model = settings
        .llm_model
        .clone()
        .unwrap_or_else(|| default_model(provider));
    let base_url = resolve_base_url(provider, settings.llm_base_url.clone());
    let catalog: String = books
        .iter()
        .map(|rb| format!("- {}: {} ({})", rb.id, rb.name, rb.symptoms.join("; ")))
        .collect::<Vec<_>>()
        .join("\n");
    let prompt = format!(
        "Pick the SINGLE most relevant runbook id for the user's symptom. \
         Reply with only the id, nothing else. If nothing fits, reply `none`.\n\n\
         Symptom: {symptom}\n\nCatalog:\n{catalog}\n"
    );
    let messages = vec![crate::llm::ChatMessage {
        role: "user".into(),
        content: prompt,
    }];
    let reply =
        match crate::llm::dispatch_public(provider, &key, &model, base_url.as_deref(), &messages)
            .await
        {
            Ok(r) => r.trim().to_lowercase(),
            Err(_) => return Ok(None),
        };
    Ok(books
        .iter()
        .find(|rb| reply.contains(&rb.id))
        .map(|rb| summarise(rb)))
}

/// Tokenise free-form text into a set of lowercase, de-noised words for
/// overlap scoring. Drops punctuation, short tokens, and a small list of
/// generic stop-words so the score reflects domain terms (igmp, querier,
/// dante, ptp, …) rather than filler.
fn runbook_tokens(text: &str) -> std::collections::HashSet<String> {
    const STOP: &[&str] = &[
        "the", "and", "for", "are", "not", "with", "this", "that", "your", "from", "was", "will",
        "any", "all", "can", "has", "have", "but", "you", "its", "per", "via", "out", "see", "run",
        "one", "two", "other", "into", "than", "then", "they", "them", "their", "there", "here",
        "when", "what", "which", "while", "after", "before", "over", "under", "some", "most", "more",
        "less", "each", "both", "also", "only", "like", "such", "very", "still", "likely", "cannot",
        "does", "did", "had", "his", "her", "our", "off", "yet", "may", "might", "must", "should",
        "would", "could", "about", "between", "during", "because", "another", "across",
    ];
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() >= 3 && !STOP.contains(t))
        .map(|t| t.to_string())
        .collect()
}

/// Score how well a runbook matches a symptom token set. Weights domain
/// signals highest: declared symptoms and `applies_to`/category tags (3),
/// then the runbook name (2), then the description (1). Returns the total
/// score and how many *distinct* strong (weight ≥ 2) tokens matched — the
/// caller uses both to decide whether a match is confident enough to show.
fn score_runbook(rb: &crate::runbook::Runbook, query: &std::collections::HashSet<String>) -> (i32, i32) {
    let symptom_tokens: std::collections::HashSet<String> =
        rb.symptoms.iter().flat_map(|s| runbook_tokens(s)).collect();
    let tag_tokens: std::collections::HashSet<String> = rb
        .applies_to
        .iter()
        .chain(std::iter::once(&rb.category))
        .flat_map(|s| runbook_tokens(s))
        .collect();
    let name_tokens = runbook_tokens(&rb.name);
    let desc_tokens = runbook_tokens(&rb.description);

    let mut score = 0i32;
    let mut strong = 0i32;
    for tok in query {
        let w = if symptom_tokens.contains(tok) || tag_tokens.contains(tok) {
            3
        } else if name_tokens.contains(tok) {
            2
        } else if desc_tokens.contains(tok) {
            1
        } else {
            0
        };
        score += w;
        if w >= 2 {
            strong += 1;
        }
    }
    (score, strong)
}

/// Deterministic, LLM-free runbook suggestion for a batch of free-form
/// symptom strings (e.g. the AV diagnostics warnings). Returns, aligned to
/// the input order, the single best-matching runbook for each symptom — or
/// `None` when nothing clears the confidence bar (score ≥ 6 with at least
/// two distinct strong-token matches). This powers the one-click
/// "Diagnose with <runbook>" affordance without a model round-trip.
#[tauri::command]
pub async fn suggest_runbooks(
    state: State<'_, AppState>,
    symptoms: Vec<String>,
) -> Result<Vec<Option<RunbookSummary>>, String> {
    let engine =
        crate::runbook::engine::Engine::new(None).with_user_runbooks(&state.user_runbooks_dir);
    let books = engine.list_runbooks();

    let suggestions = symptoms
        .iter()
        .map(|symptom| {
            let query = runbook_tokens(symptom);
            if query.is_empty() {
                return None;
            }
            let mut best: Option<(i32, i32, &crate::runbook::Runbook)> = None;
            for rb in &books {
                let (score, strong) = score_runbook(rb, &query);
                if score < 6 || strong < 2 {
                    continue;
                }
                let replace = match best {
                    None => true,
                    Some((bs, bst, brb)) => {
                        score > bs
                            || (score == bs && strong > bst)
                            || (score == bs && strong == bst && rb.id < brb.id)
                    }
                };
                if replace {
                    best = Some((score, strong, rb));
                }
            }
            best.map(|(_, _, rb)| summarise(rb))
        })
        .collect();

    Ok(suggestions)
}

/// Execute a runbook end-to-end. Emits `runbook-event` events through the
/// app handle for live transcript rendering; returns the full execution
/// when complete.
#[tauri::command]
pub async fn run_runbook(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
    runbook_id: String,
    iface: Option<String>,
) -> Result<crate::runbook::RunbookExecution, String> {
    use tauri::Emitter;

    let settings = Settings::load(&state.settings_path).map_err(|e| e.to_string())?;
    let provider = settings.llm_provider.as_deref().unwrap_or("ollama");
    // Narration is best-effort — fall back to None when no key is set.
    let llm_cfg = match resolve_api_key(provider, settings.llm_api_key.clone()) {
        Ok(api_key) => {
            let model = settings
                .llm_model
                .clone()
                .unwrap_or_else(|| default_model(provider));
            let base_url = resolve_base_url(provider, settings.llm_base_url.clone());
            Some(crate::runbook::engine::LlmConfig {
                provider: provider.into(),
                api_key,
                model,
                base_url,
            })
        }
        Err(_) => None,
    };

    // Runbook probes that pin to a NIC (PTP / IGMP / SAP / DSCP /
    // multicast / link audit) need a concrete interface name — unlike the
    // scan collectors, they can't fall back to the kernel's per-probe
    // routing. So when the NIC is "auto" (no explicit arg and no pinned
    // setting), resolve a sensible default interface here rather than
    // leaving `pinned_iface = None`, which made every iface-pinned step
    // fail with "no NIC pinned".
    let pinned = resolved_iface(&state, iface.as_deref())
        .or_else(crate::probes::iface::default_interface);
    let inputs = crate::runbook::engine::ExecutionInputs {
        pinned_iface: pinned,
        variables: std::collections::BTreeMap::new(),
    };

    let engine = crate::runbook::engine::Engine::new(llm_cfg)
        .with_user_runbooks(&state.user_runbooks_dir)
        .with_device(
            state.inventory.clone(),
            state.packs.clone(),
            state.audit.clone(),
            state.approval.clone(),
            settings.llm_model.clone().unwrap_or_default(),
        );
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<crate::runbook::RunbookEvent>();

    // Fan-out the channel to Tauri events on a background task.
    let app2 = app.clone();
    let pump = tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            let _ = app2.emit("runbook-event", &ev);
        }
    });

    let result = engine.run(&runbook_id, inputs, Some(tx)).await;
    // Closing tx by dropping it (engine.run consumed it) lets pump drain and exit.
    let _ = pump.await;
    result
}

// ═══════════════════════════════════════════════════════════════════════
// Phase 2-6: device-execution Tauri commands.
// ═══════════════════════════════════════════════════════════════════════

#[tauri::command]
pub async fn list_hosts(
    state: State<'_, AppState>,
) -> Result<Vec<crate::device::inventory::HostEntry>, String> {
    Ok(state.inventory.lock().hosts.clone())
}

#[tauri::command]
pub async fn upsert_host(
    state: State<'_, AppState>,
    entry: crate::device::inventory::HostEntry,
) -> Result<crate::device::inventory::HostEntry, String> {
    let mut inv = state.inventory.lock();
    inv.upsert(entry.clone());
    inv.save(&state.inventory_path).map_err(|e| e.to_string())?;
    Ok(entry)
}

#[tauri::command]
pub async fn delete_host(state: State<'_, AppState>, host_id: String) -> Result<(), String> {
    let mut inv = state.inventory.lock();
    inv.remove(&host_id);
    inv.save(&state.inventory_path).map_err(|e| e.to_string())?;
    // Best-effort: also drop the keychain entry.
    let _ = crate::device::keychain::delete(&host_id);
    Ok(())
}

#[tauri::command]
pub async fn set_host_password(
    state: State<'_, AppState>,
    host_id: String,
    password: String,
) -> Result<(), String> {
    if state.inventory.lock().get(&host_id).is_none() {
        return Err(format!("unknown host `{host_id}`"));
    }
    crate::device::keychain::set(&host_id, &password).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn test_host(state: State<'_, AppState>, host_id: String) -> Result<String, String> {
    use crate::device::Transport as _;
    let host = state
        .inventory
        .lock()
        .get(&host_id)
        .cloned()
        .ok_or_else(|| format!("unknown host `{host_id}`"))?;
    let result = match host.transport {
        crate::device::inventory::TransportKind::Ssh => {
            let t = crate::device::ssh::SshTransport::new();
            t.test(&host).await
        }
        crate::device::inventory::TransportKind::Https
        | crate::device::inventory::TransportKind::Http => {
            let t = crate::device::https::HttpsTransport::new(state.packs.clone());
            t.test(&host).await
        }
    };
    result
        .map(|_| format!("OK: {} ({:?})", host.hostname, host.transport))
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn list_audit(
    state: State<'_, AppState>,
    last_n: Option<usize>,
) -> Result<Vec<crate::device::audit::AuditEntry>, String> {
    state
        .audit
        .tail(last_n.unwrap_or(200))
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn clear_audit(state: State<'_, AppState>) -> Result<(), String> {
    state.audit.clear().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn list_skill_packs(
    state: State<'_, AppState>,
) -> Result<Vec<crate::device::pack::SkillPack>, String> {
    Ok(state.packs.all().into_iter().cloned().collect())
}

#[tauri::command]
pub async fn list_pending_approvals(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    Ok(state.approval.pending())
}

#[tauri::command]
pub async fn approve_runbook_step(
    state: State<'_, AppState>,
    request_id: String,
) -> Result<bool, String> {
    Ok(state
        .approval
        .resolve(&request_id, crate::device::approval::Verdict::Approve))
}

#[tauri::command]
pub async fn deny_runbook_step(
    state: State<'_, AppState>,
    request_id: String,
) -> Result<bool, String> {
    Ok(state
        .approval
        .resolve(&request_id, crate::device::approval::Verdict::Deny))
}

#[derive(serde::Serialize)]
pub struct UserRunbookEntry {
    pub id: String,
    pub name: String,
    pub path: String,
    pub bytes: u64,
}

#[tauri::command]
pub async fn list_user_runbooks(
    state: State<'_, AppState>,
) -> Result<Vec<UserRunbookEntry>, String> {
    let read = match std::fs::read_dir(&state.user_runbooks_dir) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e.to_string()),
    };
    let mut out = Vec::new();
    for entry in read.flatten() {
        let path = entry.path();
        let is_yaml = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("yaml") || e.eq_ignore_ascii_case("yml"))
            .unwrap_or(false);
        if !is_yaml {
            continue;
        }
        let bytes = entry.metadata().map(|m| m.len()).unwrap_or(0);
        let src = std::fs::read_to_string(&path).unwrap_or_default();
        // Best-effort parse for id / name display; if it doesn't parse,
        // surface the filename as both so the operator can still delete it.
        let (id, name) = match serde_yaml_ng::from_str::<crate::runbook::Runbook>(&src) {
            Ok(rb) => (rb.id, rb.name),
            Err(_) => {
                let stem = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("(unknown)")
                    .to_string();
                (stem.clone(), stem)
            }
        };
        out.push(UserRunbookEntry {
            id,
            name,
            path: path.display().to_string(),
            bytes,
        });
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

#[tauri::command]
pub async fn save_user_runbook(
    state: State<'_, AppState>,
    id: String,
    yaml: String,
) -> Result<(), String> {
    // Validate before writing — caller should see the parse error in the
    // editor rather than the engine logging it on the next list refresh.
    let parsed: crate::runbook::Runbook =
        serde_yaml_ng::from_str(&yaml).map_err(|e| format!("YAML parse: {e}"))?;
    if parsed.id != id {
        return Err(format!(
            "id mismatch: file says `{}`, request says `{id}`",
            parsed.id
        ));
    }
    // Refuse path-traversal in the id; we use it as the file name.
    if id.contains('/') || id.contains('\\') || id.starts_with('.') || id.is_empty() {
        return Err(format!("illegal runbook id `{id}`"));
    }
    let _ = std::fs::create_dir_all(&state.user_runbooks_dir);
    let path = state.user_runbooks_dir.join(format!("{id}.yaml"));
    std::fs::write(&path, yaml).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn delete_user_runbook(state: State<'_, AppState>, id: String) -> Result<(), String> {
    if id.contains('/') || id.contains('\\') || id.starts_with('.') || id.is_empty() {
        return Err(format!("illegal runbook id `{id}`"));
    }
    let path = state.user_runbooks_dir.join(format!("{id}.yaml"));
    match std::fs::remove_file(&path) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}
