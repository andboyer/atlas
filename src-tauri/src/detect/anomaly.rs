//! EWMA-based anomaly detection over time-series metric samples.
//!
//! For each tracked metric we maintain an Exponentially Weighted Moving
//! Average (EWMA) baseline and an EWMA of the squared deviation to estimate
//! variance. The z-score for the most recent observation is
//!     z = (current − ewma) / sqrt(ewma_variance)
//!
//! Rules in `detect/rules.rs` fire when |z| exceeds a per-metric threshold.

use crate::store::{MetricSample, Store};

/// The metrics we check for anomalies and the minimum number of historical
/// samples needed before we trust the baseline.
const TRACKED: &[(&str, usize)] = &[
    ("link.rssi_dbm", 4),
    ("reach.gateway_ms", 4),
    ("reach.loss_pct", 4),
];

/// How many samples to load for the EWMA window.
const HISTORY_LIMIT: usize = 20;

/// EWMA smoothing factor (α). Higher → more weight on recent samples.
const ALPHA: f64 = 0.3;

/// Per-metric anomaly signal emitted by [`compute_anomalies`].
#[derive(Debug, Clone)]
pub struct AnomalySignal {
    pub metric: &'static str,
    /// Most recent observed value.
    pub current: f64,
    /// EWMA baseline computed from all prior samples (excluding `current`).
    pub baseline: f64,
    /// Signed z-score: positive = above baseline, negative = below.
    pub z_score: f32,
}

/// Compute EWMA + z-score on a slice of values (oldest → newest).
/// Returns `(baseline_ewma, z_score)` for the **last** element or `None` if
/// there is insufficient history or the signal is flat.
fn ewma_z(values: &[f64]) -> Option<(f64, f64)> {
    if values.len() < 3 {
        return None;
    }
    // Build EWMA on everything except the final (current) observation.
    let historical = &values[..values.len() - 1];
    let mut ewma = historical[0];
    let mut ewma_sq = historical[0] * historical[0];
    for &v in &historical[1..] {
        ewma = ALPHA * v + (1.0 - ALPHA) * ewma;
        ewma_sq = ALPHA * v * v + (1.0 - ALPHA) * ewma_sq;
    }
    let variance = (ewma_sq - ewma * ewma).max(0.0);
    let std_dev = variance.sqrt();
    if std_dev < 1e-6 {
        return None; // flat signal — no anomaly possible
    }
    let current = *values.last().unwrap();
    let z = (current - ewma) / std_dev;
    Some((ewma, z))
}

/// Query the store for each tracked metric and return any anomaly signals
/// found. Signals are only emitted when there are at least `min_samples`
/// historical points. Returns an empty vec when the store is empty (e.g.
/// first scan).
pub fn compute_anomalies(store: &Store) -> Vec<AnomalySignal> {
    let mut out = Vec::new();
    for &(metric, min_samples) in TRACKED {
        let samples: Vec<MetricSample> = match store.recent_metric_samples(metric, HISTORY_LIMIT) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if samples.len() < min_samples {
            continue;
        }
        let values: Vec<f64> = samples.iter().map(|s| s.value).collect();
        if let Some((baseline, z)) = ewma_z(&values) {
            out.push(AnomalySignal {
                metric,
                current: *values.last().unwrap(),
                baseline,
                z_score: z as f32,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flat_signal_returns_none() {
        let flat: Vec<f64> = vec![50.0; 10];
        assert!(ewma_z(&flat).is_none());
    }

    #[test]
    fn too_few_samples_returns_none() {
        assert!(ewma_z(&[1.0, 2.0]).is_none());
    }

    #[test]
    fn spike_produces_positive_z() {
        // Baseline with natural variance, then a sudden spike.
        let vals: Vec<f64> = vec![
            10.0, 11.0, 9.5, 10.5, 10.0, 11.5, 9.0, 10.2, 10.8, 9.8, 10.1, 11.0, 9.7, 10.3,
            100.0, // spike
        ];
        let (_, z) = ewma_z(&vals).expect("should compute");
        assert!(z > 2.0, "expected z > 2.0 for spike, got {z}");
    }

    #[test]
    fn drop_produces_negative_z() {
        let vals: Vec<f64> = vec![
            10.0, 11.0, 9.5, 10.5, 10.0, 11.5, 9.0, 10.2, 10.8, 9.8, 10.1, 11.0, 9.7, 10.3,
            -40.0, // drop
        ];
        let (_, z) = ewma_z(&vals).expect("should compute");
        assert!(z < -2.0, "expected z < -2.0 for drop, got {z}");
    }
}
