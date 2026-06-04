use crate::commands::AppState;
use crate::detect::{self, AnomalySignal, Context};
use crate::settings::{severity_order, Settings};
use crate::types::ScanResult;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};

/// Starts the background monitoring task.  Only one monitor should run at a
/// time; call `stop_monitoring` before calling `start_monitoring` again.
///
/// Returns a stop-signal handle. Drop it or call `store(false, …)` to cancel.
pub fn start_monitoring(app: AppHandle, interval_secs: u64) -> Arc<AtomicBool> {
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = Arc::clone(&running);

    tokio::spawn(async move {
        tracing::info!("background monitor started (interval={}s)", interval_secs);
        loop {
            if !running_clone.load(Ordering::Relaxed) {
                tracing::info!("background monitor stopping");
                break;
            }

            // Run a full scan using the same pipeline as run_quick_scan.
            if let Some(result) = run_scan(&app).await {
                // Emit event so the frontend can refresh without polling.
                let _ = app.emit("scan:completed", &result);

                // Fire OS notification if findings meet threshold.
                maybe_notify(&app, &result);
            }

            // Wait for next interval, checking stop flag every second.
            for _ in 0..interval_secs {
                if !running_clone.load(Ordering::Relaxed) {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    });

    running
}

/// Run a quick scan and persist it; returns None on any hard error.
async fn run_scan(app: &AppHandle) -> Option<ScanResult> {
    use crate::collectors::default_collector;
    use chrono::Utc;
    use uuid::Uuid;

    let state = app.state::<AppState>();
    let collector = default_collector();

    let started_at = Utc::now();
    let mut link = collector.link_stats().await.ok()?;
    // Pin reachability to the global NIC selection so the background
    // monitor surfaces gateway / latency from the operator-chosen NIC,
    // not whichever default route wins right now.
    let pinned_iface = crate::commands::resolved_iface(&state, None);
    let reach = collector
        .reachability(pinned_iface.as_deref())
        .await
        .ok()?;

    let settings = Settings::load(&state.settings_path).unwrap_or_default();
    let profile = crate::commands::profile_hints_from(&settings);
    let targets = crate::commands::effective_targets(&settings);

    let (
        mut devices,
        services,
        captive_portal,
        dns_leak,
        mtu_bytes,
        nearby_aps,
        speed_mbps,
        wan,
    ) = tokio::join!(
        crate::discovery::scan::discover_and_probe(),
        crate::probes::services::probe_services(&targets),
        crate::probes::captive::is_captive_portal(),
        crate::probes::dns_leak::is_dns_leak(),
        crate::probes::mtu::discover_mtu(),
        crate::probes::channel_scan::scan_nearby(),
        crate::probes::speed_test::measure_download_mbps(),
        crate::probes::wan::probe_wan(),
    );
    // Bufferbloat / networkQuality is on-demand only (see run_quality_test);
    // it takes 40-50 s and would dominate the monitor interval.
    let quality: Option<crate::types::QualityStats> = None;
    if devices.is_empty() {
        devices = crate::commands::demo_devices();
    }
    let mut nearby_aps = nearby_aps;
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

    let interference = Some(crate::probes::interference::build_report(
        &nearby_aps,
        link.channel,
    ));
    let phy_efficiency = crate::probes::phy_efficiency::evaluate(&link);
    let rogue_aps = crate::probes::rogue::detect(&nearby_aps);

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
                    tracing::warn!("monitor: failed to persist roaming event: {e:#}");
                }
            }
        }
    }

    let roaming = {
        let day_ago = Utc::now() - chrono::Duration::hours(24);
        match state.store.roaming_events_since(day_ago) {
            Ok(events) => Some(crate::probes::roaming::summarise(&events, &link)),
            Err(e) => {
                tracing::warn!("monitor: failed to load roaming history: {e:#}");
                None
            }
        }
    };

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
        tracing::warn!("monitor: failed to persist scan: {e:#}");
    }

    Some(result)
}

/// Send an OS notification if any finding meets the severity threshold.
fn maybe_notify(app: &AppHandle, result: &ScanResult) {
    use tauri_plugin_notification::NotificationExt;

    // Load current settings to check thresholds.
    let settings_path = {
        let state = app.state::<AppState>();
        state.settings_path.clone()
    };
    let settings = Settings::load(&settings_path).unwrap_or_default();

    if !settings.notifications_enabled {
        return;
    }

    let threshold = severity_order(&settings.notification_min_severity);
    let worst = result
        .findings
        .iter()
        .filter(|f| severity_order(f.severity.as_str()) >= threshold)
        .max_by_key(|f| severity_order(f.severity.as_str()));

    if let Some(finding) = worst {
        let body = if result.findings.len() == 1 {
            finding.title.clone()
        } else {
            format!("{} and {} other issue(s)", finding.title, result.findings.len() - 1)
        };

        if let Err(e) = app
            .notification()
            .builder()
            .title("Atlas")
            .body(&body)
            .show()
        {
            tracing::warn!("notification failed: {e}");
        }
    }
}
