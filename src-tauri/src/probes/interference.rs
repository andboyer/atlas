//! Channel interference scoring.
//!
//! Builds an [`InterferenceReport`] by walking every channel observed in
//! the nearby-AP scan and weighting each neighbour by RSSI:
//!
//!   score(channel) = Σ over interferers of {
//!     2.0 * linear(RSSI)    if same channel (co-channel)
//!     1.0 * linear(RSSI)    if adjacent (2.4 GHz, channels within 4 of each other)
//!   }
//!
//! `linear(RSSI)` maps dBm to a [0, 1] severity weight using a sigmoid
//! centred at -70 dBm so a strong neighbour at -45 dBm hurts ~10× more
//! than a faint one at -85 dBm. The final score is rescaled to 0-100
//! per band so it's directly comparable inside the UI.
//!
//! "Recommended" channels:
//!   • 2.4 GHz → cleanest of the three non-overlapping channels (1, 6, 11)
//!   • 5 GHz   → cleanest channel actually observed in scan (we don't suggest
//!     unused channels because DFS / regulatory rules vary by country)

use crate::types::{ChannelScore, InterferenceReport, NearbyAp};

const NON_OVERLAPPING_24: [u32; 3] = [1, 6, 11];

/// Build an interference report from a fresh `NearbyAp` list.
///
/// `own_channel` lets us compute the current-channel score even if the
/// device's channel has zero scanned neighbours.
pub fn build_report(nearby: &[NearbyAp], own_channel: Option<u32>) -> InterferenceReport {
    use std::collections::BTreeMap;

    // Bucket APs by (band, channel). We score every channel we observed plus
    // the three non-overlapping 2.4 GHz channels even when empty, so the user
    // gets a recommendation regardless of what showed up in the scan.
    let mut all_channels: BTreeMap<(String, u32), ()> = BTreeMap::new();
    for ap in nearby {
        if let (Some(ch), Some(band)) = (ap.channel, ap.band.as_ref()) {
            all_channels.insert((band.clone(), ch), ());
        }
    }
    for ch in NON_OVERLAPPING_24 {
        all_channels.insert(("2.4".to_string(), ch), ());
    }
    if let Some(ch) = own_channel {
        let band = if ch <= 14 { "2.4" } else { "5" };
        all_channels.insert((band.to_string(), ch), ());
    }

    let mut scores: Vec<ChannelScore> = all_channels
        .into_iter()
        .map(|((band, ch), _)| score_channel(ch, &band, nearby))
        .collect();
    scores.sort_by(|a, b| {
        a.interference_score
            .partial_cmp(&b.interference_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let recommended_24 = scores
        .iter()
        .filter(|s| s.band == "2.4" && NON_OVERLAPPING_24.contains(&s.channel))
        .min_by(|a, b| {
            a.interference_score
                .partial_cmp(&b.interference_score)
                .unwrap()
        })
        .map(|s| s.channel);

    let recommended_5 = scores
        .iter()
        .filter(|s| s.band == "5")
        .min_by(|a, b| {
            a.interference_score
                .partial_cmp(&b.interference_score)
                .unwrap()
        })
        .map(|s| s.channel);

    let current_channel_score = own_channel.and_then(|ch| {
        scores
            .iter()
            .find(|s| s.channel == ch)
            .map(|s| s.interference_score)
    });

    InterferenceReport {
        channels: scores,
        recommended_24,
        recommended_5,
        current_channel_score,
    }
}

fn score_channel(channel: u32, band: &str, nearby: &[NearbyAp]) -> ChannelScore {
    let mut co_count: u32 = 0;
    let mut adj_count: u32 = 0;
    let mut raw_score = 0.0_f32;
    let mut strongest: Option<i32> = None;

    for ap in nearby {
        let other_ch = match ap.channel {
            Some(c) => c,
            None => continue,
        };
        // Same-band only: 2.4 doesn't interfere with 5 (and vice versa).
        let same_band = ap.band.as_deref() == Some(band);
        if !same_band {
            continue;
        }
        let rssi = ap.rssi_dbm.unwrap_or(-90);
        let weight = severity_weight(rssi);

        if other_ch == channel {
            co_count += 1;
            raw_score += 2.0 * weight;
            if strongest.is_none_or(|s| rssi > s) {
                strongest = Some(rssi);
            }
        } else if band == "2.4" && channel <= 14 && other_ch <= 14 {
            let diff = channel.abs_diff(other_ch);
            if diff > 0 && diff < 5 {
                adj_count += 1;
                // Adjacent-channel interference scales down with separation.
                let attenuation = 1.0 - (diff as f32 - 1.0) * 0.20;
                raw_score += attenuation * weight;
                if strongest.is_none_or(|s| rssi > s) {
                    strongest = Some(rssi);
                }
            }
        }
        // 5 GHz adjacent-channel interference is negligible because the
        // channels in modern APs (36, 40, 44, ... at 20 MHz; 36, 52, 100, ...
        // at 80 MHz) don't overlap when picked correctly. We skip it.
    }

    // Rescale to 0-100. A single max-strength co-channel neighbour scores ~2.0,
    // so we cap at 10 (≈ five strong co-channel APs) for the 100-line.
    let interference_score = (raw_score / 10.0 * 100.0).clamp(0.0, 100.0);

    ChannelScore {
        channel,
        band: band.to_string(),
        interference_score,
        co_channel_count: co_count,
        adjacent_channel_count: adj_count,
        strongest_interferer_dbm: strongest,
    }
}

/// Convert RSSI (dBm) to a 0.0-1.0 severity weight.
///
/// Logistic curve centred at -70 dBm, slope tuned so:
///   -45 dBm → ~0.95
///   -60 dBm → ~0.80
///   -70 dBm → 0.50
///   -80 dBm → ~0.20
///   -90 dBm → ~0.05
fn severity_weight(rssi_dbm: i32) -> f32 {
    let x = (rssi_dbm + 70) as f32 / 8.0;
    1.0 / (1.0 + (-x).exp())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ap(channel: u32, band: &str, rssi: i32) -> NearbyAp {
        NearbyAp {
            ssid: Some("X".into()),
            bssid: Some(format!("00:11:22:33:44:{:02x}", channel)),
            channel: Some(channel),
            band: Some(band.into()),
            rssi_dbm: Some(rssi),
            security: None,
            phy_mode: None,
            width_mhz: None,
            vendor: None,
            name_redacted: false,
        }
    }

    #[test]
    fn severity_weight_curve_shape() {
        assert!(severity_weight(-45) > 0.9);
        assert!((severity_weight(-70) - 0.5).abs() < 0.05);
        assert!(severity_weight(-90) < 0.10);
    }

    #[test]
    fn co_channel_outweighs_adjacent() {
        let nearby = vec![ap(6, "2.4", -55), ap(8, "2.4", -55)];
        let report = build_report(&nearby, Some(6));
        let ch6 = report
            .channels
            .iter()
            .find(|s| s.channel == 6 && s.band == "2.4")
            .unwrap();
        let ch11 = report
            .channels
            .iter()
            .find(|s| s.channel == 11 && s.band == "2.4")
            .unwrap();
        assert_eq!(ch6.co_channel_count, 1);
        assert!(ch6.interference_score > ch11.interference_score);
    }

    #[test]
    fn recommends_quietest_non_overlapping_24() {
        // ch1 and ch6 both heavily congested; ch11 only has one faint neighbour.
        let nearby = vec![
            ap(1, "2.4", -45),
            ap(1, "2.4", -55),
            ap(6, "2.4", -50),
            ap(6, "2.4", -60),
            ap(11, "2.4", -85),
        ];
        let report = build_report(&nearby, None);
        assert_eq!(report.recommended_24, Some(11));
    }

    #[test]
    fn recommends_5ghz_when_present() {
        let nearby = vec![ap(36, "5", -75), ap(149, "5", -55)];
        let report = build_report(&nearby, None);
        // 36 has lower interference (faint neighbour) than 149 (strong neighbour).
        assert_eq!(report.recommended_5, Some(36));
    }

    #[test]
    fn current_channel_score_is_populated() {
        let nearby = vec![ap(6, "2.4", -50)];
        let report = build_report(&nearby, Some(6));
        assert!(report.current_channel_score.unwrap() > 0.0);
    }

    #[test]
    fn empty_scan_still_returns_24ghz_recommendation() {
        let report = build_report(&[], None);
        assert!(report.recommended_24.is_some());
    }
}
