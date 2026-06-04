/// Channel interference scanner.
///
/// Scans for nearby access points and detects co-channel and adjacent-channel
/// interference on 2.4 GHz (channels 1–14) and 5 GHz (channels 36–177).
///
/// Platform implementations:
///   macOS  — native CoreWLAN via objc2 (see `macos_corewlan.rs`), falling
///            back to `system_profiler SPAirPortDataType` if CoreWLAN is
///            unavailable. The legacy `airport -s` binary was removed in
///            macOS 14.4 and modern `system_profiler` no longer emits per-AP
///            RSSI for nearby networks, so CoreWLAN is the preferred path.
///   Linux  — `iw dev <iface> scan` (requires root or CAP_NET_RAW; silently empty if unavailable)
///   Windows — `netsh wlan show networks mode=bssid`
use crate::process_util::NoConsoleExt;
use crate::types::NearbyAp;
use anyhow::Result;
use tokio::process::Command;
use tokio::time::{timeout, Duration};

/// Returns a list of nearby APs visible from this device.
pub async fn scan_nearby() -> Vec<NearbyAp> {
    scan_platform().await.unwrap_or_default()
}

#[cfg(target_os = "macos")]
async fn scan_platform() -> Result<Vec<NearbyAp>> {
    // Prefer the native in-process CoreWLAN scan. Modern macOS (Sonoma+)
    // no longer emits `Signal / Noise:` lines for nearby APs in
    // `system_profiler`, so RSSI would otherwise be null for every entry
    // and the spectrum chart would render every AP at the floor (flat
    // -100 dBm baseline). We must call CoreWLAN from the parent process
    // (not a child helper) so the scan inherits the parent app's
    // Location Services grant — TCC keys grants by binary cdhash and a
    // child helper cannot share the parent's grant.
    match tokio::task::spawn_blocking(crate::probes::macos_corewlan::scan_blocking).await {
        Ok(Ok(aps)) if !aps.is_empty() => return Ok(aps),
        Ok(Ok(_)) => {
            // CoreWLAN returned zero networks — fall through to
            // system_profiler in case the scan ran too soon after wake.
        }
        Ok(Err(e)) => {
            tracing::debug!("native CoreWLAN scan failed, falling back to system_profiler: {e}");
        }
        Err(join_err) => {
            tracing::debug!("native CoreWLAN task panicked: {join_err}");
        }
    }

    let out = timeout(
        Duration::from_secs(20),
        Command::new("system_profiler")
            .no_console()
            .arg("SPAirPortDataType")
            .output(),
    )
    .await??;
    Ok(parse_system_profiler_networks(&String::from_utf8_lossy(
        &out.stdout,
    )))
}

#[cfg(target_os = "linux")]
async fn scan_platform() -> Result<Vec<NearbyAp>> {
    use tokio::time::{timeout, Duration};
    // Detect the wireless interface.
    let iface_out = Command::new("iw").no_console().arg("dev").output().await?;
    let iface_text = String::from_utf8_lossy(&iface_out.stdout).into_owned();
    let iface = iface_text
        .lines()
        .find_map(|l| l.trim().strip_prefix("Interface "))
        .unwrap_or("wlan0")
        .to_string();

    let out = timeout(
        Duration::from_secs(15),
        Command::new("iw")
            .no_console()
            .args(["dev", &iface, "scan"])
            .output(),
    )
    .await??;
    Ok(parse_iw_scan(&String::from_utf8_lossy(&out.stdout)))
}

#[cfg(target_os = "windows")]
async fn scan_platform() -> Result<Vec<NearbyAp>> {
    let out = Command::new("netsh")
        .no_console()
        .args(["wlan", "show", "networks", "mode=bssid"])
        .output()
        .await?;
    Ok(parse_netsh_scan(&String::from_utf8_lossy(&out.stdout)))
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
async fn scan_platform() -> Result<Vec<NearbyAp>> {
    Ok(vec![])
}

// ─── Parser: macOS system_profiler SPAirPortDataType ─────────────────────────
//
// The "Other Local Wi-Fi Networks:" subsection of `system_profiler
// SPAirPortDataType` lists every visible AP with indented `Field: Value` pairs:
//
//   Other Local Wi-Fi Networks:
//     CafeFi:
//       PHY Mode: 802.11n
//       Channel: 11 (2GHz, 20MHz)
//       Network Type: Infrastructure
//       Security: WPA2 Personal
//       Signal / Noise: -71 dBm / -94 dBm
//     NeighborNet:
//       Channel: 6 (2GHz, 20MHz)
//       ...
//
// system_profiler never exposes BSSIDs (Apple privacy), so `bssid` is always None.

#[cfg(target_os = "macos")]
fn parse_system_profiler_networks(s: &str) -> Vec<NearbyAp> {
    let mut aps: Vec<NearbyAp> = Vec::new();
    let mut current: Option<NearbyAp> = None;
    let mut in_others = false;
    let mut ssid_indent: usize = 0;
    let mut redacted_seq: u32 = 0;

    for raw in s.lines() {
        let indent = raw.chars().take_while(|c| c.is_whitespace()).count();
        let trimmed = raw.trim();

        if trimmed.starts_with("Other Local Wi-Fi Networks:") {
            if let Some(ap) = current.take() {
                aps.push(ap);
            }
            in_others = true;
            ssid_indent = 0;
            continue;
        }
        if !in_others {
            continue;
        }
        // A new top-level section (less or equal indent than the "Other Local..."
        // header itself, which is typically 8 spaces) ends the block. We approximate
        // this by exiting when we see a non-indented unrelated section header.
        // In practice system_profiler emits one section per data type, and the
        // SPAirPortDataType output ends with the networks block, so this is safe.
        if trimmed.is_empty() {
            continue;
        }

        // SSID line: ends with ':' and contains no other ':' field separator pattern.
        // e.g. "  CafeFi:" — but skip things like "Network Type:" (those have a value).
        if trimmed.ends_with(':') && !trimmed.contains(": ") {
            if let Some(ap) = current.take() {
                aps.push(ap);
            }
            let name = trimmed.trim_end_matches(':').to_string();
            // macOS hides SSIDs as "<redacted>" when the calling process lacks
            // Location Services permission (the Wi-Fi privacy gate introduced
            // in macOS Sonoma). Synthesize a stable label so the AP is still
            // distinguishable in the spectrum chart and the table, and flag it.
            let (ssid, name_redacted) = if name == "<redacted>" {
                redacted_seq += 1;
                (Some(format!("Network {redacted_seq}")), true)
            } else {
                (Some(name), false)
            };
            current = Some(NearbyAp {
                ssid,
                bssid: None,
                channel: None,
                band: None,
                rssi_dbm: None,
                security: None,
                phy_mode: None,
                width_mhz: None,
                vendor: None,
                name_redacted,
            });
            ssid_indent = indent;
            continue;
        }

        // Field line under an SSID — must be more indented than the SSID itself.
        if let Some(ref mut ap) = current {
            if indent <= ssid_indent {
                // Same- or lower-indent line that isn't an SSID → we've left this AP.
                aps.push(current.take().unwrap());
                continue;
            }
            if let Some(v) = trimmed.strip_prefix("Channel: ") {
                // e.g. "11 (2GHz, 20MHz)" or "157 (5GHz, 80MHz)"
                let (num, rest) = v.split_once(' ').unwrap_or((v, ""));
                ap.channel = num.parse::<u32>().ok();
                if let Some(open) = rest.find('(') {
                    let inner = &rest[open + 1..rest.rfind(')').unwrap_or(rest.len())];
                    let mut parts = inner.split(',').map(|p| p.trim());
                    if let Some(band_str) = parts.next() {
                        ap.band = Some(match band_str {
                            "2GHz" | "2.4GHz" => "2.4".to_string(),
                            "5GHz" => "5".to_string(),
                            "6GHz" => "6".to_string(),
                            other => other.to_string(),
                        });
                    }
                    if let Some(width_str) = parts.next() {
                        ap.width_mhz = width_str.trim_end_matches("MHz").parse::<u32>().ok();
                    }
                }
                // Fallback band from channel number if the parens were missing.
                if ap.band.is_none() {
                    ap.band = ap.channel.map(|n| {
                        if n <= 14 {
                            "2.4".to_string()
                        } else {
                            "5".to_string()
                        }
                    });
                }
            } else if let Some(v) = trimmed.strip_prefix("Signal / Noise: ") {
                // e.g. "-71 dBm / -94 dBm"
                if let Some(rssi_part) = v.split('/').next() {
                    ap.rssi_dbm = rssi_part
                        .trim()
                        .trim_end_matches(" dBm")
                        .parse::<i32>()
                        .ok();
                }
            } else if let Some(v) = trimmed.strip_prefix("Security: ") {
                ap.security = Some(v.to_string());
            } else if let Some(v) = trimmed.strip_prefix("PHY Mode: ") {
                ap.phy_mode = Some(v.to_string());
            }
        }
    }

    if let Some(ap) = current.take() {
        aps.push(ap);
    }
    aps
}

// ─── Parser: Linux iw dev scan ───────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn parse_iw_scan(s: &str) -> Vec<NearbyAp> {
    let mut aps: Vec<NearbyAp> = Vec::new();
    let mut current: Option<NearbyAp> = None;

    for line in s.lines() {
        let t = line.trim();
        if t.starts_with("BSS ") {
            if let Some(ap) = current.take() {
                aps.push(ap);
            }
            let bssid = t
                .split_whitespace()
                .nth(1)
                .map(|b| b.trim_end_matches("(on").trim().to_string());
            current = Some(NearbyAp {
                ssid: None,
                bssid,
                channel: None,
                band: None,
                rssi_dbm: None,
                security: None,
                phy_mode: None,
                width_mhz: None,
                vendor: None,
                name_redacted: false,
            });
        } else if let Some(ref mut ap) = current {
            if let Some(v) = t.strip_prefix("SSID: ") {
                ap.ssid = Some(v.to_string());
            } else if t.starts_with("DS Parameter set: channel") {
                let ch = t
                    .split_whitespace()
                    .last()
                    .and_then(|v| v.parse::<u32>().ok());
                ap.channel = ch;
                ap.band = ch.map(|n| {
                    if n <= 14 {
                        "2.4".to_string()
                    } else {
                        "5".to_string()
                    }
                });
            } else if let Some(v) = t.strip_prefix("signal: ") {
                ap.rssi_dbm = v
                    .split_whitespace()
                    .next()
                    .and_then(|v| v.parse::<f32>().ok().map(|f| f as i32));
            }
        }
    }
    if let Some(ap) = current {
        aps.push(ap);
    }
    aps
}

// ─── Parser: Windows netsh wlan show networks mode=bssid ─────────────────────

#[cfg(target_os = "windows")]
fn parse_netsh_scan(s: &str) -> Vec<NearbyAp> {
    let mut aps: Vec<NearbyAp> = Vec::new();
    let mut current: Option<NearbyAp> = None;

    for line in s.lines() {
        let t = line.trim();
        if t.starts_with("SSID") && !t.starts_with("SSID ") {
            // "SSID 1 : MyNetwork" or "SSID  : MyNetwork"
            if let Some(ap) = current.take() {
                aps.push(ap);
            }
            let ssid = t.find(':').map(|i| t[i + 1..].trim().to_string());
            current = Some(NearbyAp {
                ssid,
                bssid: None,
                channel: None,
                band: None,
                rssi_dbm: None,
                security: None,
                phy_mode: None,
                width_mhz: None,
                vendor: None,
                name_redacted: false,
            });
        } else if let Some(ref mut ap) = current {
            if t.starts_with("BSSID") {
                ap.bssid = t.find(':').map(|i| t[i + 1..].trim().to_string());
            } else if t.starts_with("Signal") {
                let pct = t
                    .find(':')
                    .and_then(|i| t[i + 1..].trim().trim_end_matches('%').parse::<i32>().ok());
                ap.rssi_dbm = pct.map(|p| (p / 2) - 100);
            } else if t.starts_with("Channel") {
                let ch = t
                    .find(':')
                    .and_then(|i| t[i + 1..].trim().parse::<u32>().ok());
                ap.channel = ch;
                ap.band = ch.map(|n| {
                    if n <= 14 {
                        "2.4".to_string()
                    } else {
                        "5".to_string()
                    }
                });
            }
        }
    }
    if let Some(ap) = current {
        aps.push(ap);
    }
    aps
}

// ─── Interference analysis ───────────────────────────────────────────────────

/// Returns true if `other_channel` is on the same channel as `own_channel` (2.4 GHz).
pub fn is_co_channel_24(own: u32, other: u32) -> bool {
    own == other && own <= 14
}

/// Returns true if `other_channel` causes adjacent-channel interference to
/// `own_channel` on 2.4 GHz.  On 2.4 GHz, channels within 4 of each other
/// overlap; the only non-overlapping channels are 1, 6, and 11 (or 1, 5, 9, 13).
pub fn is_adjacent_channel_24(own: u32, other: u32) -> bool {
    if own > 14 || other > 14 || own == other {
        return false;
    }
    let diff = own.abs_diff(other);
    diff > 0 && diff < 5
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn co_channel_same_channel() {
        assert!(is_co_channel_24(6, 6));
        assert!(!is_co_channel_24(6, 1));
        assert!(!is_co_channel_24(36, 36)); // 5 GHz: not flagged here
    }

    #[test]
    fn adjacent_channel_24ghz() {
        assert!(is_adjacent_channel_24(6, 4)); // diff = 2 → overlap
        assert!(is_adjacent_channel_24(6, 8)); // diff = 2 → overlap
        assert!(is_adjacent_channel_24(1, 4)); // diff = 3 → overlap
        assert!(!is_adjacent_channel_24(1, 6)); // diff = 5 → non-overlapping
        assert!(!is_adjacent_channel_24(1, 11)); // diff = 10 → non-overlapping
        assert!(!is_adjacent_channel_24(6, 6)); // same → co-channel, not adjacent
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parses_system_profiler_networks() {
        let sample = concat!(
            "Wi-Fi:\n",
            "      Software Versions:\n",
            "        CoreWLAN: 16.0\n",
            "      Interfaces:\n",
            "        en0:\n",
            "          Status: Connected\n",
            "        Other Local Wi-Fi Networks:\n",
            "          HomeNet:\n",
            "            PHY Mode: 802.11n\n",
            "            Channel: 6 (2GHz, 20MHz)\n",
            "            Network Type: Infrastructure\n",
            "            Security: WPA2 Personal\n",
            "            Signal / Noise: -45 dBm / -94 dBm\n",
            "          OfficeAP:\n",
            "            PHY Mode: 802.11ac\n",
            "            Channel: 36 (5GHz, 80MHz)\n",
            "            Signal / Noise: -72 dBm / -94 dBm\n",
            "          <redacted>:\n",
            "            Channel: 11 (2GHz, 20MHz)\n",
            "            Signal / Noise: -80 dBm / -94 dBm\n",
        );
        let aps = parse_system_profiler_networks(sample);
        assert_eq!(aps.len(), 3, "expected 3 nearby APs, got {aps:?}");
        assert_eq!(aps[0].ssid.as_deref(), Some("HomeNet"));
        assert_eq!(aps[0].channel, Some(6));
        assert_eq!(aps[0].band.as_deref(), Some("2.4"));
        assert_eq!(aps[0].rssi_dbm, Some(-45));
        assert_eq!(aps[0].security.as_deref(), Some("WPA2 Personal"));
        assert_eq!(aps[0].phy_mode.as_deref(), Some("802.11n"));
        assert_eq!(aps[0].width_mhz, Some(20));
        assert_eq!(aps[1].ssid.as_deref(), Some("OfficeAP"));
        assert_eq!(aps[1].channel, Some(36));
        assert_eq!(aps[1].band.as_deref(), Some("5"));
        assert_eq!(aps[1].rssi_dbm, Some(-72));
        assert_eq!(aps[1].width_mhz, Some(80));
        assert_eq!(aps[1].phy_mode.as_deref(), Some("802.11ac"));
        assert!(
            !aps[0].name_redacted && !aps[1].name_redacted,
            "non-redacted entries should not be flagged"
        );
        assert_eq!(
            aps[2].ssid.as_deref(),
            Some("Network 1"),
            "redacted SSIDs get a synthesized label"
        );
        assert!(aps[2].name_redacted, "redacted SSIDs are flagged");
        assert_eq!(aps[2].channel, Some(11));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn redacted_ssids_get_distinct_labels() {
        let sample = concat!(
            "        Other Local Wi-Fi Networks:\n",
            "          <redacted>:\n",
            "            Channel: 1 (2GHz, 20MHz)\n",
            "            Signal / Noise: -60 dBm / -94 dBm\n",
            "          <redacted>:\n",
            "            Channel: 6 (2GHz, 20MHz)\n",
            "            Signal / Noise: -70 dBm / -94 dBm\n",
            "          <redacted>:\n",
            "            Channel: 149 (5GHz, 80MHz)\n",
            "            Signal / Noise: -55 dBm / -94 dBm\n",
        );
        let aps = parse_system_profiler_networks(sample);
        assert_eq!(aps.len(), 3);
        assert_eq!(aps[0].ssid.as_deref(), Some("Network 1"));
        assert_eq!(aps[1].ssid.as_deref(), Some("Network 2"));
        assert_eq!(aps[2].ssid.as_deref(), Some("Network 3"));
        assert!(aps.iter().all(|a| a.name_redacted));
    }
}
