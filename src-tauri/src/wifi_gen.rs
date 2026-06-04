//! Wi-Fi generation labelling + alternate-AP suggestion.

use crate::types::{AlternateApSuggestion, LinkStats, NearbyAp};

/// Map a PHY mode string + band hint to a marketing Wi-Fi generation label.
///
/// Returns `None` if the PHY mode is unknown.
pub fn wifi_generation(phy_mode: Option<&str>, band: Option<&str>) -> Option<String> {
    let phy_raw = phy_mode.unwrap_or("").to_ascii_lowercase();
    let band = band.unwrap_or("");
    let label = if phy_raw.contains("be") || phy_raw.contains("wi-fi 7") {
        "Wi-Fi 7"
    } else if phy_raw.contains("ax") || phy_raw.contains("wi-fi 6") {
        if band == "6" {
            "Wi-Fi 6E"
        } else {
            "Wi-Fi 6"
        }
    } else if phy_raw.contains("ac") {
        "Wi-Fi 5"
    } else if phy_raw.contains("802.11n") || phy_raw == "n" {
        "Wi-Fi 4"
    } else if phy_raw.contains("802.11g") || phy_raw.contains("802.11a") {
        "Wi-Fi 3"
    } else if phy_raw.contains("802.11b") {
        "Wi-Fi 1"
    } else {
        return None;
    };
    Some(label.to_string())
}

/// dB improvement required to suggest the user roam to an alternate AP.
const MIN_IMPROVEMENT_DB: i32 = 8;

/// dBm threshold below which the current link is considered weak enough
/// to warrant suggesting an alternate.
const WEAK_RSSI_THRESHOLD: i32 = -65;

/// If the current link is weak and a materially stronger AP on the same
/// SSID is visible, return a suggestion to roam to it.
pub fn alternate_ap(link: &LinkStats, nearby: &[NearbyAp]) -> Option<AlternateApSuggestion> {
    let current_rssi = link.rssi_dbm?;
    let current_ssid = link.ssid.as_deref()?;
    let current_bssid = link.bssid.as_deref();

    if current_rssi > WEAK_RSSI_THRESHOLD {
        // Signal is already strong — no need to suggest a different AP.
        return None;
    }

    let mut best: Option<&NearbyAp> = None;
    for ap in nearby {
        let Some(ssid) = ap.ssid.as_deref() else {
            continue;
        };
        if ssid != current_ssid {
            continue;
        }
        let Some(bssid) = ap.bssid.as_deref() else {
            continue;
        };
        // Don't recommend the AP we're already on.
        if Some(bssid) == current_bssid {
            continue;
        }
        let Some(rssi) = ap.rssi_dbm else { continue };
        if best.is_none_or(|b: &NearbyAp| b.rssi_dbm.unwrap_or(-127) < rssi) {
            best = Some(ap);
        }
    }

    let best = best?;
    let best_rssi = best.rssi_dbm?;
    let improvement = best_rssi - current_rssi;
    if improvement < MIN_IMPROVEMENT_DB {
        return None;
    }

    Some(AlternateApSuggestion {
        ssid: current_ssid.to_string(),
        current_bssid: current_bssid.map(|s| s.to_string()),
        current_rssi_dbm: current_rssi,
        alternate_bssid: best.bssid.clone().unwrap_or_default(),
        alternate_rssi_dbm: best_rssi,
        alternate_channel: best.channel,
        alternate_band: best.band.clone(),
        improvement_db: improvement,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ap(ssid: &str, bssid: &str, rssi: i32) -> NearbyAp {
        NearbyAp {
            ssid: Some(ssid.into()),
            bssid: Some(bssid.into()),
            channel: Some(36),
            band: Some("5".into()),
            rssi_dbm: Some(rssi),
            security: None,
            phy_mode: None,
            width_mhz: None,
            vendor: None,
            name_redacted: false,
        }
    }

    fn link(rssi: i32, ssid: &str, bssid: &str) -> LinkStats {
        LinkStats {
            ssid: Some(ssid.into()),
            bssid: Some(bssid.into()),
            band: Some("5".into()),
            channel: Some(36),
            channel_width_mhz: Some(80),
            rssi_dbm: Some(rssi),
            noise_dbm: Some(-95),
            snr_db: Some(20),
            tx_rate_mbps: Some(300.0),
            rx_rate_mbps: Some(300.0),
            security: Some("WPA2".into()),
            phy_mode: Some("802.11ac".into()),
            wifi_generation: None,
            vendor: None,
        }
    }

    #[test]
    fn maps_phy_to_generation() {
        assert_eq!(
            wifi_generation(Some("802.11ax"), Some("5")).as_deref(),
            Some("Wi-Fi 6")
        );
        assert_eq!(
            wifi_generation(Some("802.11ax"), Some("6")).as_deref(),
            Some("Wi-Fi 6E")
        );
        assert_eq!(
            wifi_generation(Some("802.11ac"), Some("5")).as_deref(),
            Some("Wi-Fi 5")
        );
        assert_eq!(
            wifi_generation(Some("802.11n"), Some("2.4")).as_deref(),
            Some("Wi-Fi 4")
        );
        assert_eq!(
            wifi_generation(Some("802.11be"), Some("6")).as_deref(),
            Some("Wi-Fi 7")
        );
        assert_eq!(wifi_generation(None, None), None);
    }

    #[test]
    fn no_suggestion_when_signal_is_strong() {
        let l = link(-55, "HomeWiFi", "aa:bb:cc:11:22:33");
        let nearby = vec![ap("HomeWiFi", "aa:bb:cc:44:55:66", -45)];
        assert!(alternate_ap(&l, &nearby).is_none());
    }

    #[test]
    fn suggestion_when_alternate_is_materially_stronger() {
        let l = link(-78, "HomeWiFi", "aa:bb:cc:11:22:33");
        let nearby = vec![
            ap("HomeWiFi", "aa:bb:cc:44:55:66", -55),
            ap("OtherSSID", "ff:ff:ff:ff:ff:ff", -40),
        ];
        let s = alternate_ap(&l, &nearby).expect("should suggest");
        assert_eq!(s.alternate_bssid, "aa:bb:cc:44:55:66");
        assert_eq!(s.improvement_db, 23);
    }

    #[test]
    fn no_suggestion_when_improvement_is_marginal() {
        let l = link(-72, "HomeWiFi", "aa:bb:cc:11:22:33");
        let nearby = vec![ap("HomeWiFi", "aa:bb:cc:44:55:66", -68)];
        assert!(alternate_ap(&l, &nearby).is_none());
    }

    #[test]
    fn ignores_current_bssid_in_alternates() {
        let l = link(-78, "HomeWiFi", "aa:bb:cc:11:22:33");
        let nearby = vec![ap("HomeWiFi", "aa:bb:cc:11:22:33", -55)];
        assert!(alternate_ap(&l, &nearby).is_none());
    }
}
