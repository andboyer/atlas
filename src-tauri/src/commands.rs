use crate::collectors::default_collector;
use crate::detect::{self, AnomalySignal, Context};
use crate::settings::Settings;
use crate::store::{DeviceEvent, IncidentCorrelation, MetricSample, ScanSummary, Store};
use crate::types::{AvDiagnosticsResult, DeepProbeResult, DeviceClass, DeviceInfo, IgmpProbeResult, ScanResult};
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
        let reach = timed("reachability", collector.reachability())
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
            timed("services", crate::probes::services::probe_services(&targets)),
            timed("captive", crate::probes::captive::is_captive_portal()),
            timed("dns_leak", crate::probes::dns_leak::is_dns_leak()),
            timed("mtu", crate::probes::mtu::discover_mtu()),
            timed("channel_scan", crate::probes::channel_scan::scan_nearby()),
            timed("speed_test", crate::probes::speed_test::measure_download_mbps()),
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
        link.wifi_generation = crate::wifi_gen::wifi_generation(
            link.phy_mode.as_deref(),
            link.band.as_deref(),
        );

        if devices.is_empty() {
            devices = demo_devices();
        }

        // Anomaly detection reads from persisted samples (empty on first scan).
        let anomalies: Vec<AnomalySignal> =
            detect::anomaly::compute_anomalies(&state.store);

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
pub async fn update_settings(
    state: State<'_, AppState>,
    settings: Settings,
) -> Result<(), String> {
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
    let sampler = crate::sampler::start_sampler(app.clone());
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
    kind: String,
) -> Result<crate::types::StressTestResult, String> {
    crate::stress::run(app, &kind).await
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
        .map(|m| crate::llm::ChatMessage { role: m.role, content: m.content })
        .collect();

    let metric_history = collect_metric_history(&state.store);

    crate::llm::chat_query(
        provider,
        &api_key,
        &model,
        base_url.as_deref(),
        &scan_result,
        Some(&metric_history),
        llm_history,
        &question,
    )
    .await
    .map_err(|e| e.to_string())
}

/// Pull the most useful time-series for the LLM context — about an hour of
/// each headline metric. Errors are swallowed (empty list) so a transient
/// store hiccup doesn't break the LLM flow.
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

/// Default Ollama to localhost when no base URL is set so users don't have to fill it in.
fn resolve_base_url(provider: &str, configured: Option<String>) -> Option<String> {
    match (provider, configured) {
        ("ollama", None) => Some("http://localhost:11434".to_string()),
        ("ollama", Some(s)) if s.trim().is_empty() => Some("http://localhost:11434".to_string()),
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
pub async fn export_report(
    state: State<'_, AppState>,
    run_id: String,
) -> Result<String, String> {
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

    Ok(render_html_report(
        &scan,
        &samples,
        &wifi_events,
        &narratives,
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
) -> String {
    let severity_color = |s: &crate::types::Severity| match s {
        crate::types::Severity::Critical => "#ef4444",
        crate::types::Severity::High => "#f97316",
        crate::types::Severity::Medium => "#eab308",
        crate::types::Severity::Low => "#3b82f6",
        crate::types::Severity::Info => "#6b7280",
    };

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
                format!(
                    r#"<div style="border-left:4px solid {color};padding:8px 12px;margin:8px 0;background:#1a1a2e">
  <strong style="color:{color}">[{sev}]</strong> {title}
  <ul style="margin:4px 0 0 16px;color:#aaa">{evidence}</ul>
</div>"#,
                    color = color,
                    sev = f.severity.as_str().to_uppercase(),
                    title = html_escape(&f.title),
                    evidence = evidence,
                )
            })
            .collect()
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
                format!(
                    r#"<div style="margin:8px 0;padding:8px 12px;background:#1a1a2e;border-radius:6px">
  <strong>{title}</strong><br><span style="color:#aaa">{summary}</span>
  <ol style="margin:4px 0 0 16px;color:#ccc">{steps}</ol>
</div>"#,
                    title = html_escape(&r.title),
                    summary = html_escape(&r.summary),
                    steps = steps,
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
            format!(
                "<tr><td>{status}</td><td style='font-family:monospace'>{mac}</td>\
                 <td>{host}</td><td>{class:?}</td><td>{latency}</td></tr>",
                status = status,
                mac = html_escape(&d.mac),
                host = html_escape(d.hostname.as_deref().unwrap_or("—")),
                class = d.class,
                latency = latency,
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
        let rssi_spark = render_sparkline(
            samples,
            |s| s.rssi_dbm.map(|v| v as f64),
            "#60a5fa",
            "dBm",
        );
        let gw_spark = render_sparkline(samples, |s| s.gateway_ms.map(|v| v as f64), "#34d399", "ms");
        let net_spark = render_sparkline(samples, |s| s.internet_ms.map(|v| v as f64), "#fbbf24", "ms");
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
        format!("<h2>Causal narratives ({n})</h2>{cards}", n = narratives.len())
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
<strong>Gateway latency:</strong> {gw_ms} &nbsp; <strong>Loss:</strong> {loss}</p>

{telemetry}

{narratives}

<h2>Findings ({n_findings})</h2>
{findings}

{recs_section}

{wifi_events}

<h2>Devices ({n_devices})</h2>
<table>
<tr><th></th><th>MAC</th><th>Hostname</th><th>Class</th><th>Latency</th></tr>
{devices}
</table>

{services}

<footer style="margin-top:32px;color:#475569;font-size:12px">
  Generated by WiFi Troubleshooter · {generated}
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
        telemetry = telemetry_html,
        narratives = narratives_html,
        n_findings = scan.findings.len(),
        findings = findings_html,
        recs_section = if scan.recommendations.is_empty() {
            String::new()
        } else {
            format!("<h2>Recommendations ({})</h2>{}", scan.recommendations.len(), recs_html)
        },
        wifi_events = wifi_events_html,
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
#[tauri::command]
pub async fn run_av_diagnostics(
    last_scan: Option<ScanResult>,
) -> Result<AvDiagnosticsResult, String> {
    Ok(crate::probes::av::collect(last_scan.as_ref()).await)
}

/// Run a privileged deep probe (currently only `igmp-listen` is wired) by
/// re-execing the current binary as an elevated child:
///   - **macOS** — `osascript ... with administrator privileges`. The
///     elevated helper writes the JSON `IgmpProbeResult` to stdout.
///   - **Windows** — `powershell.exe Start-Process -Verb RunAs` (triggers
///     a UAC prompt). Stdout cannot cross an elevation boundary cleanly,
///     so the helper writes JSON to a `--probe-out <path>` temp file
///     which the parent reads after `-Wait`.
///   - **Linux** — not supported yet (would need `pkexec` / `sudo -A`).
#[tauri::command]
pub async fn run_deep_probes(kind: String) -> Result<DeepProbeResult, String> {
    if kind != "igmp-listen" {
        return Err(format!("unsupported deep probe kind: {kind}"));
    }
    let exe = std::env::current_exe()
        .map_err(|e| format!("locate current exe: {e}"))?
        .to_string_lossy()
        .to_string();
    let json = elevate_and_run_igmp(&exe).await?;
    let igmp: IgmpProbeResult = serde_json::from_str(json.trim())
        .map_err(|e| format!("parse IgmpProbeResult: {e}; raw={json:?}"))?;
    Ok(DeepProbeResult {
        ran_at: chrono::Utc::now().to_rfc3339(),
        igmp: Some(igmp),
    })
}

#[cfg(target_os = "macos")]
async fn elevate_and_run_igmp(exe: &str) -> Result<String, String> {
    // Quote the binary path for osascript's nested shell; backslash-escape
    // any embedded quotes.
    let escaped = exe.replace('\\', "\\\\").replace('"', "\\\"");
    let shell_cmd = format!("\"{escaped}\" --probe igmp-listen --iface en0 --secs 12");
    let apple_script = format!(
        "do shell script \"{}\" with administrator privileges",
        shell_cmd.replace('\\', "\\\\").replace('"', "\\\"")
    );
    let output = tokio::process::Command::new("osascript")
        .arg("-e")
        .arg(&apple_script)
        .output()
        .await
        .map_err(|e| format!("spawn osascript: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("User canceled") || stderr.contains("canceled.") {
            return Err("Administrator authorisation was cancelled.".into());
        }
        return Err(format!(
            "Privileged helper failed (status {:?}): {}",
            output.status.code(),
            stderr.trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(target_os = "windows")]
async fn elevate_and_run_igmp(exe: &str) -> Result<String, String> {
    // Stdout can't cross an elevation boundary in Win32, so route the
    // helper's JSON through a unique temp file we read after -Wait.
    let out_path = std::env::temp_dir().join(format!(
        "wifi-troubleshooter-probe-{}.json",
        uuid::Uuid::new_v4()
    ));
    let out_path_str = out_path.to_string_lossy().into_owned();
    let ps_quote = |s: &str| s.replace('\'', "''");
    let arg_list = [
        "--probe",
        "igmp-listen",
        "--iface",
        "0.0.0.0",
        "--secs",
        "12",
        "--probe-out",
        &out_path_str,
    ]
    .iter()
    .map(|a| format!("'{}'", ps_quote(a)))
    .collect::<Vec<_>>()
    .join(",");
    let ps_cmd = format!(
        "$ErrorActionPreference='Stop'; \
         try {{ \
           Start-Process -FilePath '{exe}' -ArgumentList {args} -Verb RunAs -Wait -WindowStyle Hidden \
         }} catch {{ \
           if ($_.Exception.Message -match 'cancelled|canceled') {{ \
             Write-Error 'USER_CANCELLED'; exit 2 \
           }} else {{ \
             Write-Error $_.Exception.Message; exit 3 \
           }} \
         }}",
        exe = ps_quote(exe),
        args = arg_list,
    );
    let output = tokio::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps_cmd])
        .output()
        .await
        .map_err(|e| format!("spawn powershell: {e}"))?;
    if !output.status.success() {
        let _ = tokio::fs::remove_file(&out_path).await;
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("USER_CANCELLED") || stderr.contains("cancelled") {
            return Err("Administrator authorisation was cancelled.".into());
        }
        return Err(format!(
            "Privileged helper failed (status {:?}): {}",
            output.status.code(),
            stderr.trim()
        ));
    }
    let json = tokio::fs::read_to_string(&out_path)
        .await
        .map_err(|e| format!("read probe output {out_path_str}: {e}"))?;
    let _ = tokio::fs::remove_file(&out_path).await;
    Ok(json)
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
async fn elevate_and_run_igmp(_exe: &str) -> Result<String, String> {
    Err("Privileged probes are only wired for macOS and Windows in this release.".into())
}

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
