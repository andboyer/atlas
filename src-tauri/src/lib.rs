pub mod collectors;
mod commands;
pub mod detect;
pub mod discovery;
pub mod llm;
mod monitor;
pub mod probes;
mod recommend;
pub mod settings;
mod store;
pub mod types;

use commands::AppState;
use parking_lot::Mutex;
use settings::Settings;
use store::Store;
use tauri::Manager;

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
        .setup(|app| {
            let app_dir = app.path().app_data_dir().expect("app data dir resolvable");
            let db_path = app_dir.join("wifi-troubleshooter.sqlite");
            let settings_path = Settings::path_for(&app_dir);
            let store = Store::open(db_path).expect("open store");
            app.manage(AppState {
                store,
                settings_path,
                monitor_handle: Mutex::new(None),
            });
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
            commands::explain_findings,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
