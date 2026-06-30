use super::WifiCollector;
use crate::types::{LinkStats, ReachabilityStats};
use anyhow::Result;
use async_trait::async_trait;
use tokio::process::Command;
use tokio::time::{timeout, Duration};

pub struct MacOsCollector;

#[async_trait]
impl WifiCollector for MacOsCollector {
    async fn link_stats(&self) -> Result<LinkStats> {
        let out = timeout(
            Duration::from_secs(30),
            Command::new("system_profiler")
                .arg("SPAirPortDataType")
                .output(),
        )
        .await??;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let mut link = parse_system_profiler(&stdout);

        // `system_profiler` runs as a child process and can't inherit this
        // app's Location Services grant, so on macOS 14+ its Signal/Noise
        // usually reads the 0-dBm "no measurement" sentinel — which is why
        // the signal tiles showed 0. Override RSSI/noise with an in-process
        // CoreWLAN read, which DOES see the grant and returns real values.
        if let Some((rssi, noise)) =
            tokio::task::spawn_blocking(crate::probes::macos_corewlan::current_link_signal)
                .await
                .ok()
                .flatten()
        {
            if rssi.is_some() {
                link.rssi_dbm = rssi;
            }
            if noise.is_some() {
                link.noise_dbm = noise;
            }
        }

        // Recompute SNR from whatever RSSI/noise we ended up with.
        link.snr_db = match (link.rssi_dbm, link.noise_dbm) {
            (Some(r), Some(n)) => Some(r - n),
            _ => None,
        };

        Ok(link)
    }

    async fn reachability(&self, iface: Option<&str>) -> Result<ReachabilityStats> {
        crate::probes::reachability::collect(iface).await
    }
}

fn parse_system_profiler(s: &str) -> LinkStats {
    // We want the block under "Current Network Information:".
    // The SSID line ends with ':' and is indented inside that section.
    let mut ssid: Option<String> = None;
    let mut channel: Option<u32> = None;
    let mut channel_width_mhz: Option<u32> = None;
    let mut band: Option<String> = None;
    let mut security: Option<String> = None;
    let mut rssi: Option<i32> = None;
    let mut noise: Option<i32> = None;
    let mut tx_rate: Option<f32> = None;
    let mut phy_mode: Option<String> = None;

    let mut in_current = false;
    let mut took_ssid = false;
    for raw in s.lines() {
        let line = raw.trim_end();
        if line.contains("Current Network Information:") {
            in_current = true;
            took_ssid = false;
            continue;
        }
        if in_current && line.contains("Other Local Wi-Fi Networks:") {
            break;
        }
        if !in_current {
            continue;
        }

        let trimmed = line.trim();
        if !took_ssid && trimmed.ends_with(':') {
            let name = trimmed.trim_end_matches(':').to_string();
            // <redacted> happens when Location Services is off.
            if name != "<redacted>" {
                ssid = Some(name);
            }
            took_ssid = true;
            continue;
        }

        if let Some(v) = trimmed.strip_prefix("Channel: ") {
            // e.g. "157 (5GHz, 80MHz)"
            let (num, rest) = v.split_once(' ').unwrap_or((v, ""));
            channel = num.parse::<u32>().ok();
            if let Some(open) = rest.find('(') {
                let inner = &rest[open + 1..rest.rfind(')').unwrap_or(rest.len())];
                let mut parts = inner.split(',').map(|p| p.trim());
                if let Some(band_str) = parts.next() {
                    band = Some(match band_str {
                        "2GHz" | "2.4GHz" => "2.4".to_string(),
                        "5GHz" => "5".to_string(),
                        "6GHz" => "6".to_string(),
                        other => other.to_string(),
                    });
                }
                if let Some(width_str) = parts.next() {
                    channel_width_mhz = width_str.trim_end_matches("MHz").parse::<u32>().ok();
                }
            }
        } else if let Some(v) = trimmed.strip_prefix("Security: ") {
            security = Some(v.to_string());
        } else if let Some(v) = trimmed.strip_prefix("Signal / Noise: ") {
            // e.g. "-47 dBm / -94 dBm". macOS reports 0 dBm as a "no
            // measurement" sentinel (e.g. when the process lacks Location
            // Services), so treat 0 as absent rather than a real reading.
            let mut parts = v.split('/').map(|p| p.trim());
            if let Some(rssi_part) = parts.next() {
                rssi = rssi_part
                    .trim_end_matches(" dBm")
                    .parse::<i32>()
                    .ok()
                    .filter(|&v| v != 0);
            }
            if let Some(noise_part) = parts.next() {
                noise = noise_part
                    .trim_end_matches(" dBm")
                    .parse::<i32>()
                    .ok()
                    .filter(|&v| v != 0);
            }
        } else if let Some(v) = trimmed.strip_prefix("Transmit Rate: ") {
            tx_rate = v.parse::<f32>().ok();
        } else if let Some(v) = trimmed.strip_prefix("PHY Mode: ") {
            phy_mode = Some(v.to_string());
        }
    }

    let snr = match (rssi, noise) {
        (Some(r), Some(n)) => Some(r - n),
        _ => None,
    };

    LinkStats {
        ssid,
        bssid: None, // redacted by macOS without Location Services
        band,
        channel,
        channel_width_mhz,
        rssi_dbm: rssi,
        noise_dbm: noise,
        snr_db: snr,
        tx_rate_mbps: tx_rate,
        rx_rate_mbps: None,
        security,
        phy_mode,
        wifi_generation: None,
        vendor: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
      Interfaces:
        en0:
          Status: Connected
          Current Network Information:
            <redacted>:
              PHY Mode: 802.11ac
              Channel: 157 (5GHz, 80MHz)
              Country Code: US
              Network Type: Infrastructure
              Security: WPA2 Personal
              Signal / Noise: -47 dBm / -94 dBm
              Transmit Rate: 866
              MCS Index: 9
          Other Local Wi-Fi Networks:
"#;

    #[test]
    fn parses_redacted_ssid_block() {
        let link = parse_system_profiler(SAMPLE);
        assert_eq!(link.ssid, None, "<redacted> SSID should be None");
        assert_eq!(link.channel, Some(157));
        assert_eq!(link.band.as_deref(), Some("5"));
        assert_eq!(link.channel_width_mhz, Some(80));
        assert_eq!(link.rssi_dbm, Some(-47));
        assert_eq!(link.noise_dbm, Some(-94));
        assert_eq!(link.snr_db, Some(47));
        assert_eq!(link.tx_rate_mbps, Some(866.0));
        assert_eq!(link.security.as_deref(), Some("WPA2 Personal"));
    }

    #[test]
    fn parses_visible_ssid() {
        let s = SAMPLE.replace("<redacted>", "CafeWiFi-5G");
        let link = parse_system_profiler(&s);
        assert_eq!(link.ssid.as_deref(), Some("CafeWiFi-5G"));
    }

    #[test]
    fn zero_dbm_signal_is_treated_as_no_measurement() {
        // macOS returns 0 dBm when the process lacks Location Services; it
        // must not surface as a real -0/0 reading (the "always shows 0" bug).
        let s = SAMPLE.replace("-47 dBm / -94 dBm", "0 dBm / 0 dBm");
        let link = parse_system_profiler(&s);
        assert_eq!(link.rssi_dbm, None);
        assert_eq!(link.noise_dbm, None);
        assert_eq!(link.snr_db, None);
    }
}
