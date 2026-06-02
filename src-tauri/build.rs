use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // The macOS CoreWLAN scan + CoreLocation auth request both run
    // in-process now (see `src/probes/macos_corewlan.rs`). The Swift
    // sidecar helper (`swift/nearby_scan.swift`) has been retired —
    // shipping a separate binary inside `Contents/Resources/` caused two
    // problems: (1) TCC keys Location grants by the calling binary's
    // cdhash, so a helper signed with the parent's bundle id still got
    // a SECOND `_*.nearby-scan`-style entry in System Settings → Privacy
    // & Security → Location Services that the user had to grant
    // separately, and (2) locationd's per-bundle-id identity cache
    // never forgot the duplicate even after the helper was removed from
    // disk. Doing both scans in-process gives us exactly one identity
    // and one user-visible Location toggle.
    //
    // The Swift source files are kept around for reference only and are
    // not compiled or bundled.
    //
    // Silence unused-import warnings on every target.
    let _ = (env::var("CARGO_MANIFEST_DIR"), PathBuf::new(), Command::new("true"));

    tauri_build::build()
}
