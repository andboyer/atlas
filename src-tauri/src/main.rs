// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // When invoked as a privileged helper (e.g. via
    // `osascript ... administrator privileges`) with `--probe <kind>` args,
    // run the probe, print JSON to stdout, and exit BEFORE the Tauri GUI
    // is initialised. The GUI side parses our stdout into a DeepProbeResult.
    let args: Vec<String> = std::env::args().collect();
    if let Some(code) = atlas_lib::try_handle_probe_args(&args) {
        std::process::exit(code);
    }
    atlas_lib::run()
}
