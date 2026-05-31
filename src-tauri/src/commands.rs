use crate::collectors::default_collector;
use crate::detect::{self, Context};
use crate::settings::Settings;
use crate::store::{DeviceEvent, IncidentCorrelation, ScanSummary, Store};
use crate::types::{DeviceClass, DeviceInfo, ScanResult};
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::State;
use uuid::Uuid;

pub struct AppState {
    pub store: Store,
    pub settings_path: PathBuf,
    /// Stop signal for the active monitoring task (None if not running).
    pub monitor_handle: Mutex<Option<Arc<AtomicBool>>>,
}

#[tauri::command]
pub async fn run_quick_scan(state: State<'_, AppState>) -> Result<ScanResult, String> {
    let started_at = Utc::now();
    let collector = default_collector();
    let link = collector.link_stats().await.map_err(|e| e.to_string())?;
    let reach = collector.reachability().await.map_err(|e| e.to_string())?;

    // Load settings to drive profile-specific behaviour.
    let settings = Settings::load(&state.settings_path).unwrap_or_default();
    let profile = profile_hints_from(&settings);
    let targets = effective_targets(&settings);

    // LAN discovery + SaaS probes can run concurrently.
    let (mut devices, services) = tokio::join!(
        crate::discovery::scan::discover_and_probe(),
        crate::probes::services::probe_services(&targets),
    );
    if devices.is_empty() {
        devices = demo_devices();
    }

    let findings = detect::evaluate(&Context {
        link: &link,
        reach: &reach,
        devices: &devices,
        services: &services,
        profile,
    });
    let recommendations = detect::collect_recommendations(&findings);

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
    };

    if let Err(e) = state.store.record_scan(&result) {
        eprintln!("warning: failed to persist scan: {e:#}");
    }

    Ok(result)
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

    let handle = crate::monitor::start_monitoring(app, interval);
    *state.monitor_handle.lock() = Some(handle);
    Ok(())
}

#[tauri::command]
pub async fn stop_monitoring(state: State<'_, AppState>) -> Result<(), String> {
    if let Some(handle) = state.monitor_handle.lock().take() {
        handle.store(false, Ordering::Relaxed);
    }
    Ok(())
}

// ── LLM ──────────────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn explain_findings(
    state: State<'_, AppState>,
    scan_result: ScanResult,
) -> Result<String, String> {
    let settings = Settings::load(&state.settings_path).map_err(|e| e.to_string())?;

    let provider = settings.llm_provider.as_deref().unwrap_or("openai");
    let api_key = settings
        .llm_api_key
        .clone()
        .ok_or_else(|| "No LLM API key configured. Add one in Settings.".to_string())?;
    let model = settings
        .llm_model
        .clone()
        .unwrap_or_else(|| default_model(provider));
    let base_url = settings.llm_base_url.clone();

    crate::llm::explain(provider, &api_key, &model, base_url.as_deref(), &scan_result)
        .await
        .map_err(|e| e.to_string())
}

fn default_model(provider: &str) -> String {
    match provider {
        "anthropic" => "claude-3-haiku-20240307".to_string(),
        "ollama" => "llama3".to_string(),
        _ => "gpt-4o-mini".to_string(),
    }
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
