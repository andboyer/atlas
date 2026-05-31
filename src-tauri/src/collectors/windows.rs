use super::WifiCollector;
use crate::types::{LinkStats, ReachabilityStats};
use anyhow::Result;
use async_trait::async_trait;
use tokio::process::Command;

pub struct WindowsCollector;

#[async_trait]
impl WifiCollector for WindowsCollector {
    async fn link_stats(&self) -> Result<LinkStats> {
        let out = Command::new("netsh")
            .args(["wlan", "show", "interfaces"])
            .output()
            .await?;
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        Ok(parse_netsh_interfaces(&stdout))
    }

    async fn reachability(&self) -> Result<ReachabilityStats> {
        crate::probes::reachability::collect().await
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

    LinkStats {
        ssid,
        bssid,
        band,
        channel,
        channel_width_mhz: None, // not exposed by netsh
        rssi_dbm,
        noise_dbm: None,
        snr_db: None,
        tx_rate_mbps: tx_rate,
        rx_rate_mbps: rx_rate,
        security,
    }
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
}
