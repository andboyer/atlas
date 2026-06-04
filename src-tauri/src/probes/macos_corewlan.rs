//! Native macOS CoreWLAN scan + CoreLocation auth helpers.
//!
//! Running CoreWLAN and CoreLocation from the parent Rust process — rather
//! than from a child Swift helper binary — is required for the SSIDs to
//! actually come back populated. TCC keys Location Services grants by the
//! calling binary's cdhash, so a child binary inside `Contents/Resources/`
//! cannot inherit the parent app's grant even when signed with the same
//! bundle identifier. Doing the scan in-process means CoreWLAN sees the
//! parent app's TCC posture (the one the user actually toggled on in
//! System Settings → Privacy & Security → Location Services).

#![cfg(target_os = "macos")]

use crate::types::NearbyAp;
use anyhow::Result;
use objc2::rc::Retained;
use objc2_core_location::CLLocationManager;
use objc2_core_wlan::{CWChannel, CWChannelBand, CWChannelWidth, CWInterface, CWWiFiClient};
use objc2_foundation::NSString;

/// Request `WhenInUseAuthorization` from CoreLocation. Safe to call multiple
/// times — once granted, subsequent calls are no-ops. The first call from
/// an un-prompted process triggers the system dialog.
///
/// The `CLLocationManager` instance is intentionally leaked (held in a
/// process-lifetime static via `std::mem::forget`) so that its retain count
/// stays at +1 forever. If the manager is dropped immediately after
/// `requestWhenInUseAuthorization()` returns, macOS interprets the dealloc
/// as the client withdrawing — the system Location Services prompt never
/// appears AND the user-visible toggle in System Settings → Privacy &
/// Security → Location Services flips itself OFF moments after the user
/// flips it ON (the OS sees no live client claiming the grant). Keeping
/// the manager alive is the canonical Apple-documented pattern for any
/// process that wants to keep its Location authorization.
pub fn request_location_auth() {
    use std::sync::OnceLock;
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        // SAFETY: CLLocationManager is a standard Objective-C class; `new`
        // and `requestWhenInUseAuthorization` have no thread-unsafe side
        // effects and are documented to be callable from any thread that
        // has a runloop. We call this from Tauri's main thread (which runs
        // an NSApplication runloop), so the prompt UI is delivered
        // correctly. `std::mem::forget` is required — see the doc comment
        // on this function for why dropping the manager breaks the prompt.
        unsafe {
            let manager = CLLocationManager::new();
            manager.requestWhenInUseAuthorization();
            std::mem::forget(manager);
        }
    });
}

/// Perform a CoreWLAN scan from this process. Returns the same shape as the
/// system_profiler / Swift helper paths so the caller can substitute freely.
///
/// This is blocking (CoreWLAN's scan API is synchronous). Callers should run
/// it on a blocking-friendly executor (`tokio::task::spawn_blocking`).
pub fn scan_blocking() -> Result<Vec<NearbyAp>> {
    // SAFETY: All calls below are standard Objective-C dispatches with
    // no documented threading constraints beyond "do not call from a
    // signal handler". CoreWLAN scan returns an NSSet<CWNetwork> on
    // success; we read scalar accessors only.
    unsafe {
        let client = CWWiFiClient::sharedWiFiClient();
        let Some(iface): Option<Retained<CWInterface>> = client.interface() else {
            anyhow::bail!("no Wi-Fi interface available");
        };

        let networks = iface
            .scanForNetworksWithName_error(None)
            .map_err(|e| anyhow::anyhow!("CoreWLAN scan failed: {e:?}"))?;

        let mut out: Vec<NearbyAp> = Vec::new();
        let mut redacted_seq: u32 = 0;
        for net in networks.iter() {
            let ssid_raw: Option<Retained<NSString>> = net.ssid();
            let bssid_raw: Option<Retained<NSString>> = net.bssid();
            let channel_obj: Option<Retained<CWChannel>> = net.wlanChannel();
            let rssi = net.rssiValue() as i32;

            let (ssid, name_redacted) = match ssid_raw.map(|s| s.to_string()) {
                Some(s) if !s.is_empty() => (Some(s), false),
                _ => {
                    redacted_seq += 1;
                    (Some(format!("Network {redacted_seq}")), true)
                }
            };

            let bssid = bssid_raw.map(|s| s.to_string()).filter(|s| !s.is_empty());

            let (channel, band, width_mhz) = match channel_obj {
                Some(c) => {
                    let ch_num = c.channelNumber() as u32;
                    let band_str = match c.channelBand() {
                        CWChannelBand::Band2GHz => Some("2.4".to_string()),
                        CWChannelBand::Band5GHz => Some("5".to_string()),
                        CWChannelBand::Band6GHz => Some("6".to_string()),
                        _ => None,
                    };
                    let width = match c.channelWidth() {
                        CWChannelWidth::Width20MHz => Some(20u32),
                        CWChannelWidth::Width40MHz => Some(40),
                        CWChannelWidth::Width80MHz => Some(80),
                        CWChannelWidth::Width160MHz => Some(160),
                        _ => None,
                    };
                    (Some(ch_num), band_str, width)
                }
                None => (None, None, None),
            };

            // CoreWLAN returns 0 dBm as a sentinel for "no measurement";
            // drop it so the chart doesn't render a spurious 0-line.
            let rssi_dbm = if rssi == 0 { None } else { Some(rssi) };

            out.push(NearbyAp {
                ssid,
                bssid,
                channel,
                band,
                rssi_dbm,
                security: None,
                phy_mode: None,
                width_mhz,
                vendor: None,
                name_redacted,
            });
        }
        Ok(out)
    }
}
