//! PHY-rate efficiency.
//!
//! Given the link's PHY mode (802.11 generation), channel width, and the
//! negotiated TX rate, estimate how close we are to the theoretical max for
//! a 2-spatial-stream device. Most modern client radios (laptops, phones)
//! ship 2x2 MIMO — so this is the realistic ceiling, not the marketing
//! "up to 9.6 Gbps" Wi-Fi 6E peak which assumes 8x8 + 4096-QAM.
//!
//! Values used (2x2 MIMO, max MCS, short GI):
//!
//!   | PHY     | 20 MHz | 40 MHz | 80 MHz | 160 MHz |
//!   |---------|--------|--------|--------|---------|
//!   | 802.11n | 144    | 300    |   —    |    —    |
//!   | 802.11ac| 173    | 400    | 866    | 1733    |
//!   | 802.11ax| 287    | 573    | 1200   | 2402    |
//!   | 802.11be| 287    | 573    | 1200   | 2402    | (Wi-Fi 7 baseline; MLO ignored)
//!   | 802.11g/a | 54   |        |        |         |
//!   | 802.11b   | 11   |        |        |         |
//!
//! The grade buckets are:
//!   ≥ 75%  → excellent
//!   ≥ 50%  → good
//!   ≥ 25%  → fair
//!   < 25%  → poor
//!
//! Below 50% with strong RSSI ⇒ likely interference or driver/MCS issue.
//! Below 50% with weak RSSI   ⇒ expected, signal-limited.

use crate::types::{LinkStats, PhyEfficiency};

pub fn evaluate(link: &LinkStats) -> Option<PhyEfficiency> {
    let actual = link.tx_rate_mbps?;
    let phy = normalised_phy(link.phy_mode.as_deref(), link.band.as_deref())?;
    let width = link.channel_width_mhz.unwrap_or(match link.band.as_deref() {
        Some("2.4") => 20,
        Some("5") => 80,
        Some("6") => 160,
        _ => 20,
    });
    let theoretical = theoretical_max(phy, width)?;
    let efficiency = (actual / theoretical).clamp(0.0, 1.0);
    let grade = match efficiency {
        e if e >= 0.75 => "excellent",
        e if e >= 0.50 => "good",
        e if e >= 0.25 => "fair",
        _ => "poor",
    };
    let diagnostic = build_diagnostic(efficiency, link.rssi_dbm, phy, width);

    Some(PhyEfficiency {
        phy_mode: format!("{} @ {} MHz (2 streams)", phy_label(phy), width),
        theoretical_max_mbps: theoretical,
        actual_mbps: actual,
        efficiency,
        grade: grade.to_string(),
        diagnostic,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phy {
    B,
    GA,
    N,
    Ac,
    Ax,
    Be,
}

fn phy_label(p: Phy) -> &'static str {
    match p {
        Phy::B => "802.11b",
        Phy::GA => "802.11g/a",
        Phy::N => "802.11n (Wi-Fi 4)",
        Phy::Ac => "802.11ac (Wi-Fi 5)",
        Phy::Ax => "802.11ax (Wi-Fi 6)",
        Phy::Be => "802.11be (Wi-Fi 7)",
    }
}

/// Normalise a free-form PHY string (from system_profiler or iw) into our enum.
fn normalised_phy(raw: Option<&str>, band: Option<&str>) -> Option<Phy> {
    let s = raw.unwrap_or("").to_lowercase();
    if s.contains("802.11be") || s.contains("wi-fi 7") || s.contains("wifi7") {
        Some(Phy::Be)
    } else if s.contains("802.11ax") || s.contains("wi-fi 6") || s.contains("wifi6") {
        Some(Phy::Ax)
    } else if s.contains("802.11ac") {
        Some(Phy::Ac)
    } else if s.contains("802.11n") {
        Some(Phy::N)
    } else if s.contains("802.11g") || s.contains("802.11a") {
        Some(Phy::GA)
    } else if s.contains("802.11b") {
        Some(Phy::B)
    } else {
        // Fallback: guess from band.
        match band {
            Some("2.4") => Some(Phy::N),
            Some("5") => Some(Phy::Ac),
            Some("6") => Some(Phy::Ax),
            _ => None,
        }
    }
}

fn theoretical_max(phy: Phy, width_mhz: u32) -> Option<f32> {
    Some(match (phy, width_mhz) {
        (Phy::B, _) => 11.0,
        (Phy::GA, _) => 54.0,
        (Phy::N, 20) => 144.0,
        (Phy::N, 40) => 300.0,
        (Phy::N, _) => 144.0, // fallback for odd widths
        (Phy::Ac, 20) => 173.0,
        (Phy::Ac, 40) => 400.0,
        (Phy::Ac, 80) => 866.0,
        (Phy::Ac, 160) => 1733.0,
        (Phy::Ac, _) => 866.0,
        (Phy::Ax, 20) => 287.0,
        (Phy::Ax, 40) => 573.0,
        (Phy::Ax, 80) => 1200.0,
        (Phy::Ax, 160) => 2402.0,
        (Phy::Ax, _) => 1200.0,
        (Phy::Be, 20) => 287.0,
        (Phy::Be, 40) => 573.0,
        (Phy::Be, 80) => 1200.0,
        (Phy::Be, 160) => 2402.0,
        (Phy::Be, _) => 1200.0,
    })
}

fn build_diagnostic(efficiency: f32, rssi: Option<i32>, phy: Phy, width: u32) -> String {
    if efficiency >= 0.75 {
        return format!(
            "Link is hitting near-peak rates for {} at {} MHz — nothing to do.",
            phy_label(phy),
            width
        );
    }
    if efficiency >= 0.50 {
        return "Negotiated rate is in the healthy range, but not maxed. \
                Probably normal for current conditions."
            .to_string();
    }
    match rssi {
        Some(r) if r < -70 => format!(
            "Low rate is consistent with weak signal ({r} dBm). Get closer to the AP \
             or add a second AP."
        ),
        Some(r) if r >= -60 => format!(
            "Signal is strong ({r} dBm) but rate is low — almost certainly \
             channel contention, interference, or an AP-side MCS limit."
        ),
        _ => "Rate is below half of theoretical max — likely interference or \
              driver-negotiated low MCS."
            .to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(phy: &str, width: u32, rate: f32, rssi: i32, band: &str) -> LinkStats {
        LinkStats {
            ssid: None,
            bssid: None,
            band: Some(band.into()),
            channel: Some(36),
            channel_width_mhz: Some(width),
            rssi_dbm: Some(rssi),
            noise_dbm: None,
            snr_db: None,
            tx_rate_mbps: Some(rate),
            rx_rate_mbps: None,
            security: None,
            phy_mode: Some(phy.into()),
            wifi_generation: None,
            vendor: None,
        }
    }

    #[test]
    fn ax_80mhz_at_full_rate_is_excellent() {
        let e = evaluate(&link("802.11ax", 80, 1100.0, -50, "5")).unwrap();
        assert_eq!(e.grade, "excellent");
        assert!(e.efficiency > 0.9);
    }

    #[test]
    fn weak_signal_low_rate_diagnoses_signal() {
        let e = evaluate(&link("802.11ac", 80, 100.0, -85, "5")).unwrap();
        assert!(e.diagnostic.to_lowercase().contains("weak signal"));
    }

    #[test]
    fn strong_signal_low_rate_diagnoses_contention() {
        let e = evaluate(&link("802.11ac", 80, 100.0, -50, "5")).unwrap();
        assert!(
            e.diagnostic.to_lowercase().contains("contention")
                || e.diagnostic.to_lowercase().contains("interference"),
            "got: {}",
            e.diagnostic
        );
    }

    #[test]
    fn fallback_phy_from_band_when_string_missing() {
        let mut l = link("unknown", 80, 600.0, -55, "5");
        l.phy_mode = None;
        let e = evaluate(&l).unwrap();
        assert!(e.phy_mode.contains("802.11ac")); // 5 GHz fallback
    }

    #[test]
    fn returns_none_without_actual_rate() {
        let mut l = link("802.11ax", 80, 0.0, -50, "5");
        l.tx_rate_mbps = None;
        assert!(evaluate(&l).is_none());
    }
}
