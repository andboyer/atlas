use crate::types::{
    DeviceClass, DeviceInfo, Finding, LinkStats, ReachabilityStats, Recommendation, ServiceProbe,
    Severity,
};
use chrono::Utc;
use uuid::Uuid;

pub mod anomaly;
pub mod rules;

pub use anomaly::AnomalySignal;

/// Tunable hints derived from the active industry profile + user settings.
#[derive(Default, Debug, Clone)]
pub struct ProfileHints {
    /// MACs the user has pinned. Going offline on a watched MAC produces a
    /// high-severity finding.
    pub watchlist: Vec<String>,
    /// Maximum acceptable RTT (ms) for SaaS/POS targets.
    pub service_high_latency_ms: f32,
}

pub struct Context<'a> {
    pub link: &'a LinkStats,
    pub reach: &'a ReachabilityStats,
    pub devices: &'a [DeviceInfo],
    pub services: &'a [ServiceProbe],
    pub profile: ProfileHints,
    /// Pre-computed anomaly signals from the EWMA engine. Empty on first scan.
    pub anomalies: Vec<AnomalySignal>,
    /// True when a captive portal was detected during this scan.
    pub captive_portal: bool,
    /// True when DNS queries appear to leak to a public/unexpected resolver.
    pub dns_leak: bool,
    /// Effective path MTU discovered via ping DF-bit probing (None if unavailable).
    pub mtu_bytes: Option<u32>,
}

pub struct RuleHit {
    pub rule_id: &'static str,
    pub title: String,
    pub severity: Severity,
    pub confidence: f32,
    pub evidence: Vec<String>,
    pub affected_devices: Vec<String>,
    pub recommendation_id: Option<&'static str>,
}

pub fn evaluate(ctx: &Context) -> Vec<Finding> {
    let now = Utc::now();
    rules::all_rules()
        .iter()
        .filter_map(|rule| rule(ctx))
        .map(|hit| Finding {
            id: Uuid::new_v4().to_string(),
            rule_id: hit.rule_id.to_string(),
            title: hit.title,
            severity: hit.severity,
            confidence: hit.confidence,
            evidence: hit.evidence,
            affected_devices: hit.affected_devices,
            recommendation_id: hit.recommendation_id.map(|s| s.to_string()),
            observed_at: now,
        })
        .collect()
}

#[allow(dead_code)]
pub fn devices_in_class<'a>(
    devices: &'a [DeviceInfo],
    class: &DeviceClass,
) -> impl Iterator<Item = &'a DeviceInfo> {
    let target = std::mem::discriminant(class);
    devices
        .iter()
        .filter(move |d| std::mem::discriminant(&d.class) == target)
}

pub fn collect_recommendations(findings: &[Finding]) -> Vec<Recommendation> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for f in findings {
        if let Some(rid) = &f.recommendation_id {
            if seen.insert(rid.clone()) {
                if let Some(rec) = crate::recommend::lookup(rid) {
                    out.push(rec);
                }
            }
        }
    }
    out
}
