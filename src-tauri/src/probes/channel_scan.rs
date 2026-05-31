/// Channel interference scanner.
///
/// Scans for nearby access points and detects co-channel and adjacent-channel
/// interference on 2.4 GHz (channels 1–14) and 5 GHz (channels 36–177).
///
/// Platform implementations:
///   macOS  — `/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s`
///   Linux  — `iw dev <iface> scan` (requires root or CAP_NET_RAW; silently empty if unavailable)
///   Windows — `netsh wlan show networks mode=bssid`
use crate::types::NearbyAp;
use anyhow::Result;
use tokio::process::Command;

/// Returns a list of nearby APs visible from this device.
pub async fn scan_nearby() -> Vec<NearbyAp> {
    scan_platform().await.unwrap_or_default()
}

#[cfg(target_os = "macos")]
async fn scan_platform() -> Result<Vec<NearbyAp>> {
    let out = Command::new(
        "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
    )
    .arg("-s")
    .output()
    .await?;
    Ok(parse_airport_scan(&String::from_utf8_lossy(&out.stdout)))
}

#[cfg(target_os = "linux")]
async fn scan_platform() -> Result<Vec<NearbyAp>> {
    use tokio::time::{timeout, Duration};
    // Detect the wireless interface.
    let iface_out = Command::new("iw").arg("dev").output().await?;
    let iface_text = String::from_utf8_lossy(&iface_out.stdout).into_owned();
    let iface = iface_text
        .lines()
        .find_map(|l| l.trim().strip_prefix("Interface "))
        .unwrap_or("wlan0")
        .to_string();

    let out = timeout(
        Duration::from_secs(15),
        Command::new("iw").args(["dev", &iface, "scan"]).output(),
    )
    .await??;
    Ok(parse_iw_scan(&String::from_utf8_lossy(&out.stdout)))
}

#[cfg(target_os = "windows")]
async fn scan_platform() -> Result<Vec<NearbyAp>> {
    let out = Command::new("netsh")
        .args(["wlan", "show", "networks", "mode=bssid"])
        .output()
        .await?;
    Ok(parse_netsh_scan(&String::from_utf8_lossy(&out.stdout)))
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
async fn scan_platform() -> Result<Vec<NearbyAp>> {
    Ok(vec![])
}

// ─── Parser: macOS airport -s ────────────────────────────────────────────────
//
// Header line:    SSID BSSID             RSSI CHANNEL HT CC SECURITY (auth/unicast/group)
// Example line:   MyNet a4:c3:f0:11:22:33  -57  6,+1    Y  US WPA2(PSK/AES/AES)

#[cfg(target_os = "macos")]
fn parse_airport_scan(s: &str) -> Vec<NearbyAp> {
    let mut aps = Vec::new();
    let mut in_data = false;
    for line in s.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("SSID") && trimmed.contains("BSSID") {
            in_data = true;
            continue;
        }
        if !in_data || trimmed.is_empty() {
            continue;
        }
        // airport -s output is fixed-width. The SSID occupies the first 32 chars,
        // BSSID is the next 18, RSSI is next, then channel.
        // Use whitespace splitting from the right to avoid SSID ambiguity.
        // Format (right-anchored after BSSID):  <bssid> <rssi> <channel> ...
        let parts = line.split_whitespace();
        // Collect tokens; last tokens are: CHANNEL HT CC SECURITY...
        // The BSSID token always matches xx:xx:xx:xx:xx:xx
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let bssid_idx = tokens.iter().position(|t| {
            t.len() == 17 && t.chars().filter(|&c| c == ':').count() == 5
        });
        let bssid_idx = match bssid_idx {
            Some(i) => i,
            None => continue,
        };

        let ssid_tokens = &tokens[..bssid_idx];
        let ssid = if ssid_tokens.is_empty() {
            None
        } else {
            Some(ssid_tokens.join(" "))
        };
        let bssid = Some(tokens[bssid_idx].to_string());

        let rssi: Option<i32> = tokens
            .get(bssid_idx + 1)
            .and_then(|v| v.parse().ok());

        // Channel field: "6", "6,+1", "36", "36,80"
        let (channel, band) = tokens
            .get(bssid_idx + 2)
            .map(|c| {
                let num_str = c.split(',').next().unwrap_or(c);
                let ch = num_str.parse::<u32>().ok();
                let band = ch.map(|n| {
                    if n <= 14 {
                        "2.4".to_string()
                    } else {
                        "5".to_string()
                    }
                });
                (ch, band)
            })
            .unwrap_or((None, None));

        // Fix the unused `parts` variable lint
        let _ = parts;

        aps.push(NearbyAp { ssid, bssid, channel, band, rssi_dbm: rssi });
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
            });
        } else if let Some(ref mut ap) = current {
            if let Some(v) = t.strip_prefix("SSID: ") {
                ap.ssid = Some(v.to_string());
            } else if t.starts_with("DS Parameter set: channel") {
                let ch = t.split_whitespace().last().and_then(|v| v.parse::<u32>().ok());
                ap.channel = ch;
                ap.band = ch.map(|n| if n <= 14 { "2.4".to_string() } else { "5".to_string() });
            } else if let Some(v) = t.strip_prefix("signal: ") {
                ap.rssi_dbm = v.split_whitespace().next().and_then(|v| {
                    v.parse::<f32>().ok().map(|f| f as i32)
                });
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
            });
        } else if let Some(ref mut ap) = current {
            if t.starts_with("BSSID") {
                ap.bssid = t.find(':').map(|i| t[i + 1..].trim().to_string());
            } else if t.starts_with("Signal") {
                let pct = t
                    .find(':')
                    .and_then(|i| {
                        t[i + 1..]
                            .trim()
                            .trim_end_matches('%')
                            .parse::<i32>()
                            .ok()
                    });
                ap.rssi_dbm = pct.map(|p| (p / 2) - 100);
            } else if t.starts_with("Channel") {
                let ch = t.find(':').and_then(|i| t[i + 1..].trim().parse::<u32>().ok());
                ap.channel = ch;
                ap.band = ch.map(|n| if n <= 14 { "2.4".to_string() } else { "5".to_string() });
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
        assert!(is_adjacent_channel_24(6, 4));  // diff = 2 → overlap
        assert!(is_adjacent_channel_24(6, 8));  // diff = 2 → overlap
        assert!(is_adjacent_channel_24(1, 4));  // diff = 3 → overlap
        assert!(!is_adjacent_channel_24(1, 6)); // diff = 5 → non-overlapping
        assert!(!is_adjacent_channel_24(1, 11));// diff = 10 → non-overlapping
        assert!(!is_adjacent_channel_24(6, 6)); // same → co-channel, not adjacent
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parses_airport_scan_output() {
        let sample = concat!(
            "                            SSID BSSID             RSSI CHANNEL HT CC SECURITY (auth/unicast/group)\n",
            "                        HomeNet a4:c3:f0:11:22:33  -45       6   Y  US WPA2(PSK/AES/AES)\n",
            "                        OfficeAP b4:e9:4a:44:55:66  -72      36,80  Y  US WPA2(PSK/AES/AES)\n",
        );
        let aps = parse_airport_scan(sample);
        assert_eq!(aps.len(), 2);
        assert_eq!(aps[0].ssid.as_deref(), Some("HomeNet"));
        assert_eq!(aps[0].channel, Some(6));
        assert_eq!(aps[0].band.as_deref(), Some("2.4"));
        assert_eq!(aps[0].rssi_dbm, Some(-45));
        assert_eq!(aps[1].channel, Some(36));
        assert_eq!(aps[1].band.as_deref(), Some("5"));
    }
}
