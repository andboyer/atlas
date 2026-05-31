mod collectors;
mod commands;
mod detect;
mod recommend;
mod store;
mod types;

use commands::AppState;
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
        .setup(|app| {
            let app_dir = app.path().app_data_dir().expect("app data dir resolvable");
            let db_path = app_dir.join("wifi-troubleshooter.sqlite");
            let store = Store::open(db_path).expect("open store");
            app.manage(AppState { store });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![commands::run_quick_scan])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
