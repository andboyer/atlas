use super::WifiCollector;
use crate::types::{LinkStats, ReachabilityStats};
use anyhow::Result;
use async_trait::async_trait;
use tokio::process::Command;

pub struct LinuxCollector;

#[async_trait]
impl WifiCollector for LinuxCollector {
    async fn link_stats(&self) -> Result<LinkStats> {
        let iface = find_wifi_interface()
            .await
            .unwrap_or_else(|| "wlan0".to_string());

        let (link_out, info_out) = tokio::join!(
            Command::new("iw").args(["dev", &iface, "link"]).output(),
            Command::new("iw").args(["dev", &iface, "info"]).output(),
        );

        let link_str = link_out
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        let info_str = info_out
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();

        Ok(parse_iw_output(&link_str, &info_str))
    }

    async fn reachability(&self, iface: Option<&str>) -> Result<ReachabilityStats> {
        crate::probes::reachability::collect(iface).await
    }
}

/// Returns the first wireless interface name found by `iw dev`.
async fn find_wifi_interface() -> Option<String> {
    let out = Command::new("iw").arg("dev").output().await.ok()?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    for line in stdout.lines() {
        if let Some(iface) = line.trim().strip_prefix("Interface ") {
            return Some(iface.to_string());
        }
    }
    None
}

fn iw_field<'a>(s: &'a str, key: &str) -> Option<&'a str> {
    s.lines()
        .find(|l| l.trim_start().starts_with(key))
        .and_then(|l| l.splitn(2, ':').nth(1))
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
}

fn parse_iw_output(link: &str, info: &str) -> LinkStats {
    // "Connected to 74:ac:b9:aa:bb:cc (on wlan0)"
    let bssid = link
        .lines()
        .find(|l| l.starts_with("Connected to"))
        .and_then(|l| l.split_whitespace().nth(2))
        .map(|s| s.to_string());

    let ssid = iw_field(link, "SSID").map(|s| s.to_string());

    // "signal: -55 dBm"  →  -55
    let rssi_dbm = iw_field(link, "signal")
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse::<i32>().ok());

    // "tx bitrate: 234.0 MBit/s ..."  →  234.0
    let tx_rate = link
        .lines()
        .find(|l| l.trim_start().starts_with("tx bitrate"))
        .and_then(|l| l.splitn(2, ':').nth(1))
        .and_then(|v| v.trim().split_whitespace().next())
        .and_then(|v| v.parse::<f32>().ok());

    let rx_rate = link
        .lines()
        .find(|l| l.trim_start().starts_with("rx bitrate"))
        .and_then(|l| l.splitn(2, ':').nth(1))
        .and_then(|v| v.trim().split_whitespace().next())
        .and_then(|v| v.parse::<f32>().ok());

    let (channel, channel_width_mhz, band) = parse_iw_channel(info);

    LinkStats {
        ssid,
        bssid,
        band,
        channel,
        channel_width_mhz,
        rssi_dbm,
        noise_dbm: None,
        snr_db: None,
        tx_rate_mbps: tx_rate,
        rx_rate_mbps: rx_rate,
        security: None, // `iw` does not expose security type; could query nmcli
        phy_mode: None,
        wifi_generation: None,
        vendor: None,
    }
}

/// Parse `iw dev <iface> info` for channel, width, and band.
///
/// Example line: `channel 36 (5180 MHz), width: 80 MHz, center1: 5210 MHz`
fn parse_iw_channel(info: &str) -> (Option<u32>, Option<u32>, Option<String>) {
    for line in info.lines() {
        let t = line.trim();
        if !t.starts_with("channel ") {
            continue;
        }
        // channel number
        let channel = t.split_whitespace().nth(1).and_then(|v| v.parse::<u32>().ok());

        // frequency in MHz — between '(' and ' MHz)'
        let freq_mhz: Option<u32> = t
            .find('(')
            .and_then(|i| {
                let after = &t[i + 1..];
                after.find(" MHz").map(|j| &after[..j])
            })
            .and_then(|v| v.parse().ok());

        let band = freq_mhz.map(|f| {
            if f < 3000 {
                "2.4".to_string()
            } else if f < 5945 {
                "5".to_string()
            } else {
                "6".to_string()
            }
        });

        // "width: 80 MHz"
        let width = t
            .find("width: ")
            .and_then(|i| t[i + 7..].split_whitespace().next())
            .and_then(|v| v.parse::<u32>().ok());

        return (channel, width, band);
    }
    (None, None, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    const IW_LINK: &str = "\
Connected to 74:ac:b9:aa:bb:cc (on wlan0)\n\
\tSSID: HomeNetwork\n\
\tfreq: 5180\n\
\tRX: 12345678 bytes (90123 packets)\n\
\tTX: 9876543 bytes (12345 packets)\n\
\tsignal: -55 dBm\n\
\trx bitrate: 300.0 MBit/s MCS 7 40MHz\n\
\ttx bitrate: 300.0 MBit/s MCS 7 40MHz\n";

    const IW_INFO: &str = "\
Interface wlan0\n\
\tifindex 3\n\
\twdev 0x1\n\
\taddr a4:c3:f0:11:22:33\n\
\tssid HomeNetwork\n\
\ttype managed\n\
\tchannel 36 (5180 MHz), width: 80 MHz, center1: 5210 MHz\n\
\ttxpower 22.00 dBm\n";

    #[test]
    fn parses_link_fields() {
        let link = parse_iw_output(IW_LINK, IW_INFO);
        assert_eq!(link.ssid.as_deref(), Some("HomeNetwork"));
        assert_eq!(link.bssid.as_deref(), Some("74:ac:b9:aa:bb:cc"));
        assert_eq!(link.rssi_dbm, Some(-55));
        assert_eq!(link.tx_rate_mbps, Some(300.0));
        assert_eq!(link.rx_rate_mbps, Some(300.0));
    }

    #[test]
    fn parses_channel_info() {
        let (ch, width, band) = parse_iw_channel(IW_INFO);
        assert_eq!(ch, Some(36));
        assert_eq!(width, Some(80));
        assert_eq!(band.as_deref(), Some("5"));
    }

    #[test]
    fn handles_24ghz_band() {
        let info = "\tchannel 6 (2437 MHz), width: 20 MHz, center1: 2437 MHz\n";
        let (ch, width, band) = parse_iw_channel(info);
        assert_eq!(ch, Some(6));
        assert_eq!(width, Some(20));
        assert_eq!(band.as_deref(), Some("2.4"));
    }
}
