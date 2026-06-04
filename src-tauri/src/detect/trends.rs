//! Trend analysis: compares the current scan's headline metrics to the
//! averages over the previous hour. Surfaces findings when a metric has
//! materially degraded (or improved) so the user gets context like
//! "your gateway latency has tripled vs the last hour".

use crate::store::Store;
use crate::types::{LinkStats, ReachabilityStats, TrendDelta, TrendReport};

/// Direction labels for `TrendDelta.direction`.
const DIR_IMPROVED: &str = "improved";
const DIR_STABLE: &str = "stable";
const DIR_DEGRADED: &str = "degraded";

/// Build a trend report from persisted metric samples.
///
/// `link` and `reach` are the current scan's values; we compare each
/// against the average of the most-recent 60 stored samples (capped at
/// roughly the prior hour because samples land once per scan).
pub fn build_report(
    store: &Store,
    link: &LinkStats,
    reach: &ReachabilityStats,
) -> Option<TrendReport> {
    let probes: &[(&str, &str, Option<f32>, TrendDirection)] = &[
        (
            "link.rssi_dbm",
            "RSSI (dBm)",
            link.rssi_dbm.map(|v| v as f32),
            TrendDirection::HigherIsBetter,
        ),
        (
            "link.snr_db",
            "SNR (dB)",
            link.snr_db.map(|v| v as f32),
            TrendDirection::HigherIsBetter,
        ),
        (
            "link.tx_rate_mbps",
            "Tx rate (Mbps)",
            link.tx_rate_mbps,
            TrendDirection::HigherIsBetter,
        ),
        (
            "reach.gateway_latency_ms",
            "Gateway latency (ms)",
            reach.gateway_latency_ms,
            TrendDirection::LowerIsBetter,
        ),
        (
            "reach.internet_latency_ms",
            "Internet latency (ms)",
            reach.internet_latency_ms,
            TrendDirection::LowerIsBetter,
        ),
        (
            "reach.packet_loss_pct",
            "Packet loss (%)",
            reach.packet_loss_pct,
            TrendDirection::LowerIsBetter,
        ),
    ];

    let mut deltas: Vec<TrendDelta> = Vec::new();
    let mut max_samples = 0u32;

    for (metric, label, current, dir) in probes {
        let Some(current) = current else { continue };
        let samples = store.recent_metric_samples(metric, 60).unwrap_or_default();
        if samples.len() < 3 {
            // Not enough history to claim a trend.
            continue;
        }
        max_samples = max_samples.max(samples.len() as u32);
        let avg: f32 = samples.iter().map(|s| s.value as f32).sum::<f32>() / samples.len() as f32;
        let delta = current - avg;
        let direction = classify(delta, avg, *dir);
        deltas.push(TrendDelta {
            metric: (*metric).to_string(),
            label: (*label).to_string(),
            current: *current,
            prev_hour_avg: avg,
            delta,
            direction: direction.to_string(),
        });
    }

    if deltas.is_empty() {
        return None;
    }
    Some(TrendReport {
        deltas,
        samples_considered: max_samples,
    })
}

#[derive(Copy, Clone)]
enum TrendDirection {
    HigherIsBetter,
    LowerIsBetter,
}

fn classify(delta: f32, avg: f32, dir: TrendDirection) -> &'static str {
    // Threshold of "material change": 15% of the average value, with an
    // absolute floor of 2 units to avoid noisy classifications near zero.
    let threshold = (avg.abs() * 0.15).max(2.0);
    if delta.abs() < threshold {
        return DIR_STABLE;
    }
    let improving = match dir {
        TrendDirection::HigherIsBetter => delta > 0.0,
        TrendDirection::LowerIsBetter => delta < 0.0,
    };
    if improving {
        DIR_IMPROVED
    } else {
        DIR_DEGRADED
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn higher_better_improves_when_delta_positive() {
        assert_eq!(
            classify(8.0, 30.0, TrendDirection::HigherIsBetter),
            DIR_IMPROVED
        );
        assert_eq!(
            classify(-8.0, 30.0, TrendDirection::HigherIsBetter),
            DIR_DEGRADED
        );
    }

    #[test]
    fn lower_better_improves_when_delta_negative() {
        assert_eq!(
            classify(-15.0, 50.0, TrendDirection::LowerIsBetter),
            DIR_IMPROVED
        );
        assert_eq!(
            classify(15.0, 50.0, TrendDirection::LowerIsBetter),
            DIR_DEGRADED
        );
    }

    #[test]
    fn small_change_is_stable() {
        assert_eq!(
            classify(1.0, 100.0, TrendDirection::HigherIsBetter),
            DIR_STABLE
        );
    }

    #[test]
    fn absolute_floor_protects_near_zero() {
        // avg = 1, threshold floor = 2, so delta of 1.5 must still be stable.
        assert_eq!(
            classify(1.5, 1.0, TrendDirection::HigherIsBetter),
            DIR_STABLE
        );
    }
}
