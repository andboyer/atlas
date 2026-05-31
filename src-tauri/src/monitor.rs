use crate::commands::AppState;
use crate::detect::{self, Context};
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
    let link = collector.link_stats().await.ok()?;
    let reach = collector.reachability().await.ok()?;

    let mut devices = crate::discovery::scan::discover_and_probe().await;
    if devices.is_empty() {
        devices = crate::commands::demo_devices();
    }

    let findings = detect::evaluate(&Context {
        link: &link,
        reach: &reach,
        devices: &devices,
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
            .title("WiFi Troubleshooter")
            .body(&body)
            .show()
        {
            tracing::warn!("notification failed: {e}");
        }
    }
}
