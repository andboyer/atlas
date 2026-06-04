use super::WifiCollector;
use crate::process_util::NoConsoleExt;
use crate::types::{LinkStats, ReachabilityStats};
use anyhow::Result;
use async_trait::async_trait;
use tokio::process::Command;

pub struct WindowsCollector;

#[async_trait]
impl WifiCollector for WindowsCollector {
    async fn link_stats(&self) -> Result<LinkStats> {
        let out = Command::new("netsh")
            .no_console()
            .args(["wlan", "show", "interfaces"])
            .output()
            .await?;
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        Ok(parse_netsh_interfaces(&stdout))
    }

    async fn reachability(&self, iface: Option<&str>) -> Result<ReachabilityStats> {
        crate::probes::reachability::collect(iface).await
    }
}

/// Extract the value from a `netsh` line of the form `    KEY    : value`.
/// Uses ` : ` as the separator so MAC addresses (containing `:`) are preserved.
fn field(s: &str, key: &str) -> Option<String> {
    s.lines()
        .find(|l| {
            let t = l.trim_start();
            t.starts_with(key) && t[key.len()..].trim_start().starts_with(':')
        })
        .and_then(|l| l.find(" : ").map(|i| l[i + 3..].trim().to_string()))
        .filter(|v| !v.is_empty())
}

fn parse_netsh_interfaces(s: &str) -> LinkStats {
    let ssid = field(s, "SSID");
    let bssid = field(s, "BSSID");
    let channel: Option<u32> = field(s, "Channel").and_then(|v| v.parse().ok());

    // Windows reports signal as a percentage; approximate dBm: (pct / 2) - 100
    let rssi_dbm = field(s, "Signal")
        .as_deref()
        .and_then(|v| v.trim_end_matches('%').parse::<i32>().ok())
        .map(|p| (p / 2) - 100);

    let tx_rate = field(s, "Transmit rate (Mbps)").and_then(|v| v.parse::<f32>().ok());
    let rx_rate = field(s, "Receive rate (Mbps)").and_then(|v| v.parse::<f32>().ok());
    let security = field(s, "Authentication");

    let band = field(s, "Band").map(|b| match b.as_str() {
        "2.4 GHz" => "2.4".to_string(),
        "5 GHz" => "5".to_string(),
        "6 GHz" => "6".to_string(),
        other => other.to_string(),
    });

    // `Radio type` is netsh's PHY mode column: "802.11ac" / "802.11ax" /
    // "802.11be" / "802.11n" etc. Normalise to a short suffix ("ac", "ax",
    // "be", "n") so it matches the macOS collector's convention.
    let phy_mode = field(s, "Radio type").map(|v| {
        v.trim()
            .strip_prefix("802.11")
            .map(|s| s.to_string())
            .unwrap_or(v)
    });

    let wifi_generation = derive_generation(phy_mode.as_deref(), band.as_deref());
    let vendor = bssid
        .as_deref()
        .and_then(crate::oui::lookup)
        .map(|s| s.to_string());

    LinkStats {
        ssid,
        bssid,
        band,
        channel,
        channel_width_mhz: None, // not exposed by netsh; would need WlanQueryInterface
        rssi_dbm,
        noise_dbm: None,
        snr_db: None,
        tx_rate_mbps: tx_rate,
        rx_rate_mbps: rx_rate,
        security,
        phy_mode,
        wifi_generation,
        vendor,
    }
}

/// Map (PHY mode, band) → marketing Wi-Fi generation. `phy_mode` is the
/// short suffix from `parse_netsh_interfaces` ("ax", "ac", "be", "n", "g",
/// "a"); `band` is "2.4" / "5" / "6".
fn derive_generation(phy_mode: Option<&str>, band: Option<&str>) -> Option<String> {
    let p = phy_mode?.to_lowercase();
    let p = p.trim();
    Some(match (p, band) {
        ("be", _) => "Wi-Fi 7".into(),
        ("ax", Some("6")) => "Wi-Fi 6E".into(),
        ("ax", _) => "Wi-Fi 6".into(),
        ("ac", _) => "Wi-Fi 5".into(),
        ("n", _) => "Wi-Fi 4".into(),
        ("g" | "a", _) => "Wi-Fi 3".into(),
        ("b", _) => "Wi-Fi 1".into(),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Sample output from `netsh wlan show interfaces` (CRLF line endings typical on Windows)
    const SAMPLE: &str = "\
\r\nThere is 1 interface on the system:\r\n\
\r\n    Name                   : Wi-Fi\r\n\
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz\r\n\
    GUID                   : abcdefab-cdef-abcd-efab-cdefabcdefab\r\n\
    Physical address       : a4:c3:f0:11:22:33\r\n\
    State                  : connected\r\n\
    SSID                   : MyNetwork\r\n\
    BSSID                  : 74:ac:b9:aa:bb:cc\r\n\
    Network type           : Infrastructure\r\n\
    Radio type             : 802.11ac\r\n\
    Authentication         : WPA2-Personal\r\n\
    Cipher                 : CCMP\r\n\
    Connection mode        : Auto Connect\r\n\
    Band                   : 5 GHz\r\n\
    Channel                : 36\r\n\
    Receive rate (Mbps)    : 400.0\r\n\
    Transmit rate (Mbps)   : 400.0\r\n\
    Signal                 : 72%\r\n\
    Profile                : MyNetwork\r\n";

    #[test]
    fn parses_all_fields() {
        let link = parse_netsh_interfaces(SAMPLE);
        assert_eq!(link.ssid.as_deref(), Some("MyNetwork"));
        assert_eq!(link.bssid.as_deref(), Some("74:ac:b9:aa:bb:cc"));
        assert_eq!(link.channel, Some(36));
        assert_eq!(link.band.as_deref(), Some("5"));
        assert_eq!(link.rssi_dbm, Some(-64)); // 72/2 - 100
        assert_eq!(link.tx_rate_mbps, Some(400.0));
        assert_eq!(link.rx_rate_mbps, Some(400.0));
        assert_eq!(link.security.as_deref(), Some("WPA2-Personal"));
    }

    #[test]
    fn ssid_does_not_bleed_into_bssid() {
        // "BSSID" starts_with "SSID" prefix check must not fire
        let link = parse_netsh_interfaces(SAMPLE);
        assert_ne!(link.ssid.as_deref(), Some("74:ac:b9:aa:bb:cc"));
        assert_ne!(link.bssid.as_deref(), Some("MyNetwork"));
    }

    #[test]
    fn derives_wifi5_phy_mode() {
        let link = parse_netsh_interfaces(SAMPLE);
        assert_eq!(link.phy_mode.as_deref(), Some("ac"));
        assert_eq!(link.wifi_generation.as_deref(), Some("Wi-Fi 5"));
    }

    #[test]
    fn derive_generation_table() {
        assert_eq!(
            derive_generation(Some("ax"), Some("6")).as_deref(),
            Some("Wi-Fi 6E")
        );
        assert_eq!(
            derive_generation(Some("ax"), Some("5")).as_deref(),
            Some("Wi-Fi 6")
        );
        assert_eq!(
            derive_generation(Some("be"), Some("6")).as_deref(),
            Some("Wi-Fi 7")
        );
        assert_eq!(
            derive_generation(Some("n"), Some("2.4")).as_deref(),
            Some("Wi-Fi 4")
        );
        assert_eq!(derive_generation(None, Some("5")), None);
    }
}
