//! Roaming statistics — pure computations over a recent list of
//! [`RoamingEvent`]s persisted by the store.
//!
//! Surface signals:
//!   • `events_last_hour`     — too-many-roams flapping detector
//!   • `events_last_24h`      — daily baseline
//!   • `avg_dwell_secs`       — typical gap between roams (≥2 events)
//!   • `sticky_warning`       — current RSSI ≤ -75 dBm yet no roam in 30+ min
//!     ⇒ classic "sticky-client" failure to roam onto a closer AP

use crate::types::{LinkStats, RoamingEvent, RoamingStats};
use chrono::{Duration, Utc};

const STICKY_RSSI_THRESHOLD: i32 = -75;
const STICKY_NO_ROAM_MINUTES: i64 = 30;
const RECENT_LIMIT: usize = 20;

/// Build a `RoamingStats` from a chronologically-sorted (oldest-first) event
/// list and the current link state.
pub fn summarise(events: &[RoamingEvent], link: &LinkStats) -> RoamingStats {
    let now = Utc::now();
    let hour_ago = now - Duration::hours(1);
    let day_ago = now - Duration::hours(24);

    let events_last_hour = events.iter().filter(|e| e.at >= hour_ago).count() as u32;
    let events_last_24h = events.iter().filter(|e| e.at >= day_ago).count() as u32;

    let dwell = average_gap_secs(events, day_ago);

    let last_roam = events.iter().map(|e| e.at).max();
    let no_roam_minutes = last_roam
        .map(|t| (now - t).num_minutes())
        .unwrap_or(i64::MAX);
    let weak_link = link
        .rssi_dbm
        .map(|r| r <= STICKY_RSSI_THRESHOLD)
        .unwrap_or(false);
    let sticky_warning = weak_link && no_roam_minutes >= STICKY_NO_ROAM_MINUTES;

    // Most-recent first, capped.
    let mut recent: Vec<RoamingEvent> = events.iter().rev().take(RECENT_LIMIT).cloned().collect();
    recent.sort_by_key(|e| std::cmp::Reverse(e.at));

    RoamingStats {
        events_last_hour,
        events_last_24h,
        avg_dwell_secs: dwell,
        sticky_warning,
        recent_events: recent,
    }
}

fn average_gap_secs(events: &[RoamingEvent], since: chrono::DateTime<chrono::Utc>) -> Option<u32> {
    let filtered: Vec<_> = events.iter().filter(|e| e.at >= since).collect();
    if filtered.len() < 2 {
        return None;
    }
    let mut gaps: Vec<i64> = Vec::with_capacity(filtered.len() - 1);
    for w in filtered.windows(2) {
        gaps.push((w[1].at - w[0].at).num_seconds().abs());
    }
    let total: i64 = gaps.iter().sum();
    Some((total / gaps.len() as i64).max(0) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evt(mins_ago: i64, from: &str, to: &str) -> RoamingEvent {
        RoamingEvent {
            at: Utc::now() - Duration::minutes(mins_ago),
            ssid: Some("HomeWiFi".into()),
            from_bssid: Some(from.into()),
            to_bssid: Some(to.into()),
            rssi_at_roam_dbm: Some(-72),
        }
    }

    fn link(rssi: i32) -> LinkStats {
        LinkStats {
            ssid: Some("HomeWiFi".into()),
            bssid: Some("aa:bb:cc:dd:ee:01".into()),
            band: Some("5".into()),
            channel: Some(36),
            channel_width_mhz: Some(80),
            rssi_dbm: Some(rssi),
            noise_dbm: Some(-95),
            snr_db: Some(35),
            tx_rate_mbps: Some(400.0),
            rx_rate_mbps: None,
            security: Some("WPA2".into()),
            phy_mode: Some("802.11ac".into()),
            wifi_generation: None,
            vendor: None,
        }
    }

    #[test]
    fn counts_recent_events() {
        let events = vec![
            evt(5, "A", "B"),
            evt(15, "B", "A"),
            evt(2000, "A", "B"), // > 24h via 2000min = 33h
        ];
        let s = summarise(&events, &link(-50));
        assert_eq!(s.events_last_hour, 2);
        assert_eq!(s.events_last_24h, 2);
    }

    #[test]
    fn sticky_warning_fires_on_weak_signal_no_roam() {
        let events = vec![evt(120, "A", "B")]; // last roam 2h ago
        let s = summarise(&events, &link(-80));
        assert!(s.sticky_warning, "expected sticky warning");
    }

    #[test]
    fn no_sticky_when_signal_strong() {
        let events = vec![evt(120, "A", "B")];
        let s = summarise(&events, &link(-50));
        assert!(!s.sticky_warning);
    }

    #[test]
    fn no_sticky_when_recently_roamed() {
        let events = vec![evt(5, "A", "B")]; // 5min ago
        let s = summarise(&events, &link(-80));
        assert!(!s.sticky_warning);
    }

    #[test]
    fn average_dwell_handles_single_event() {
        let events = vec![evt(5, "A", "B")];
        let s = summarise(&events, &link(-50));
        assert!(s.avg_dwell_secs.is_none());
    }
}
