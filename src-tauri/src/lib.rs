pub mod collectors;
mod commands;
pub mod detect;
pub mod discovery;
pub mod llm;
mod monitor;
mod narrator;
pub mod oui;
pub mod probes;
pub mod profiles;
mod recommend;
mod sampler;
pub mod settings;
mod store;
mod stress;
pub mod types;
pub mod wifi_events;
pub mod wifi_gen;

use commands::AppState;
use parking_lot::Mutex;
use settings::Settings;
use store::Store;
use tauri::Manager;

/// Dispatch the `--probe <kind>` privileged-helper modes. Called from
/// `main.rs` BEFORE Tauri initialises. Returns `Some(exit_code)` when a
/// probe ran (the binary should then exit immediately) and `None` for the
/// normal GUI launch path.
pub fn try_handle_probe_args(args: &[String]) -> Option<i32> {
    probes::deep::try_dispatch(args)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_process::init())
        .setup(|app| {
            let app_dir = app.path().app_data_dir().expect("app data dir resolvable");
            let db_path = app_dir.join("wifi-troubleshooter.sqlite");
            let settings_path = Settings::path_for(&app_dir);
            let store = Store::open(db_path).expect("open store");
            app.manage(AppState {
                store,
                settings_path,
                monitor_handle: Mutex::new(None),
                sampler_handle: Mutex::new(None),
                wifi_events_handle: Mutex::new(None),
                narrator_handle: Mutex::new(None),
            });
            // Auto-start is driven from the frontend on first launch via
            // `bootstrapMonitor()` in the Zustand store: settings default to
            // `monitoring_enabled = true` so the live scan kicks off as soon
            // as the SPA mounts. We cannot start it here because Tauri's
            // setup() runs before the tokio runtime is initialised — calling
            // `tokio::spawn` panics with "no reactor running".
            // Bring the window to the foreground (needed on macOS when launched from terminal)
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_focus();
                let _ = window.show();
            }
            // On macOS, request CoreLocation authorization from the parent
            // app process so SSIDs come back populated in CoreWLAN scans.
            // TCC keys Location grants by binary cdhash — a child helper
            // cannot inherit the parent's grant, so the request MUST be
            // made from the main app binary. First call shows the system
            // prompt; subsequent calls are no-ops once granted.
            #[cfg(target_os = "macos")]
            {
                probes::macos_corewlan::request_location_auth();
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::run_quick_scan,
            commands::get_recent_scans,
            commands::get_device_events,
            commands::get_recent_device_events,
            commands::get_incident_correlation,
            commands::get_settings,
            commands::update_settings,
            commands::start_monitoring,
            commands::stop_monitoring,
            commands::get_monitor_status,
            commands::get_live_metrics,
            commands::get_wifi_events,
            commands::run_stress_test,
            commands::list_stress_tests,
            commands::get_narratives,
            commands::run_quality_test,
            commands::explain_findings,
            commands::radio_insights,
            commands::run_av_diagnostics,
            commands::run_deep_probes,
            commands::av_insights,
            commands::chat_query,
            commands::get_payload_preview,
            commands::get_metric_history,
            commands::get_roaming_history,
            commands::export_report,
            commands::check_for_update,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
