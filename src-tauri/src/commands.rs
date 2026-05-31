use crate::collectors::default_collector;
use crate::detect::{self, AnomalySignal, Context};
use crate::settings::Settings;
use crate::store::{DeviceEvent, IncidentCorrelation, MetricSample, ScanSummary, Store};
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

    // LAN discovery + SaaS probes + captive-portal + DNS leak + MTU probes run concurrently.
    let (mut devices, services, captive_portal, dns_leak, mtu_bytes) = tokio::join!(
        crate::discovery::scan::discover_and_probe(),
        crate::probes::services::probe_services(&targets),
        crate::probes::captive::is_captive_portal(),
        crate::probes::dns_leak::is_dns_leak(),
        crate::probes::mtu::discover_mtu(),
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
        captive_portal,
        dns_leak,
        mtu_bytes,
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
pub async fn export_report(
    state: State<'_, AppState>,
    run_id: String,
) -> Result<String, String> {
    let scan = state
        .store
        .get_scan_full(&run_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("Run '{run_id}' not found or predates report storage"))?;
    Ok(render_html_report(&scan))
}

fn render_html_report(scan: &ScanResult) -> String {
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

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>WiFi Diagnostic Report — {started}</title>
<style>
  body {{ font-family: system-ui, sans-serif; background: #0f0f1a; color: #e2e8f0;
         max-width: 900px; margin: 0 auto; padding: 24px; }}
  h1 {{ color: #818cf8; }} h2 {{ color: #94a3b8; border-bottom: 1px solid #334155; padding-bottom: 4px; }}
  table {{ border-collapse: collapse; width: 100%; }} th, td {{ padding: 6px 10px; text-align: left; border: 1px solid #334155; }}
  th {{ background: #1e293b; }} tr:nth-child(even) {{ background: #141428; }}
</style>
</head>
<body>
<h1>📡 WiFi Diagnostic Report</h1>
<p>{portal}<strong>Scan:</strong> {started} → {finished}<br>
<strong>SSID:</strong> {ssid} &nbsp; <strong>RSSI:</strong> {rssi} dBm &nbsp;
<strong>Gateway latency:</strong> {gw_ms} &nbsp; <strong>Loss:</strong> {loss}</p>

<h2>Findings ({n_findings})</h2>
{findings}

{recs_section}

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
        n_findings = scan.findings.len(),
        findings = findings_html,
        recs_section = if scan.recommendations.is_empty() {
            String::new()
        } else {
            format!("<h2>Recommendations ({})</h2>{}", scan.recommendations.len(), recs_html)
        },
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
