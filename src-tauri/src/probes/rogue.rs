//! Rogue / evil-twin AP detection.
//!
//! Heuristics applied to the latest `NearbyAp` scan:
//!
//! 1. **Mixed security on one SSID**: same network name advertised by APs
//!    with different security modes (e.g. one WPA2, one Open). Classic
//!    captive-portal-impersonation / evil-twin signature.
//! 2. **Same SSID, different OUI prefixes**: legitimate enterprise meshes
//!    have a consistent OUI (first three octets of BSSID); a stranger
//!    showing up with a different vendor prefix is suspicious.
//! 3. **Open broadcast with same SSID as a secured network**: even rarer
//!    than #1 — explicitly call it out as a separate finding.
//! 4. **Unusually large BSSID fan-out (≥6) for one SSID on a single band**:
//!    not by itself rogue, but useful info — flagged at low severity.
//!
//! Returns a vector of [`RogueApFinding`]s, severity-sorted (high first).

use crate::types::{NearbyAp, RogueApFinding, Severity};
use std::collections::{BTreeMap, BTreeSet};

pub fn detect(nearby: &[NearbyAp]) -> Vec<RogueApFinding> {
    // Group APs by SSID. We ignore APs with no SSID (hidden / redacted) —
    // there's no way to attribute them to a network without knowing which
    // ESS we're looking at.
    let mut by_ssid: BTreeMap<String, Vec<&NearbyAp>> = BTreeMap::new();
    for ap in nearby {
        if let Some(ssid) = ap.ssid.as_ref() {
            if !ssid.is_empty() {
                by_ssid.entry(ssid.clone()).or_default().push(ap);
            }
        }
    }

    let mut findings = Vec::new();
    for (ssid, aps) in &by_ssid {
        if aps.len() < 2 {
            continue;
        }
        let bssids: Vec<String> = aps.iter().filter_map(|a| a.bssid.clone()).collect();
        let security_modes: BTreeSet<String> = aps
            .iter()
            .filter_map(|a| a.security.clone())
            .map(|s| canonical_security(&s))
            .collect();
        let security_vec: Vec<String> = security_modes.iter().cloned().collect();

        // (1) Mixed security including Open vs secured.
        let has_open = security_modes.iter().any(|m| m == "Open");
        let has_secured = security_modes.iter().any(|m| m != "Open" && m != "Unknown");

        if has_open && has_secured {
            findings.push(RogueApFinding {
                ssid: ssid.clone(),
                bssids: bssids.clone(),
                security_modes: security_vec.clone(),
                reason: format!(
                    "SSID '{ssid}' is broadcast both Open and secured — possible \
                     evil-twin impersonation of your real network."
                ),
                severity: Severity::High,
            });
            continue;
        }

        // (2) Mixed security among secured APs (e.g. WPA2 + WPA3 personal).
        if security_modes.len() > 1 {
            // WPA2/WPA3 transition mode is legitimate — skip if that's the only mix.
            let only_wpa_transition = security_modes
                .iter()
                .all(|m| m.starts_with("WPA2") || m.starts_with("WPA3") || m.starts_with("WPA/WPA2"));
            if !only_wpa_transition {
                findings.push(RogueApFinding {
                    ssid: ssid.clone(),
                    bssids: bssids.clone(),
                    security_modes: security_vec.clone(),
                    reason: format!(
                        "SSID '{ssid}' uses mixed security modes across BSSIDs — \
                         suspicious."
                    ),
                    severity: Severity::High,
                });
                continue;
            }
        }

        // (3) Same SSID, multiple OUI vendors → likely impersonation.
        let ouis: BTreeSet<String> = bssids.iter().filter_map(|b| oui(b)).collect();
        if ouis.len() > 1 && bssids.len() <= 4 {
            findings.push(RogueApFinding {
                ssid: ssid.clone(),
                bssids: bssids.clone(),
                security_modes: security_vec.clone(),
                reason: format!(
                    "SSID '{ssid}' is broadcast by APs from {} different vendor \
                     OUI prefixes — verify all are legitimate.",
                    ouis.len()
                ),
                severity: Severity::Medium,
            });
            continue;
        }

        // (4) Large fan-out on a single band → informational.
        let bands: BTreeMap<String, u32> =
            aps.iter()
                .filter_map(|a| a.band.clone())
                .fold(BTreeMap::new(), |mut acc, b| {
                    *acc.entry(b).or_insert(0) += 1;
                    acc
                });
        if bands.values().any(|&c| c >= 6) {
            findings.push(RogueApFinding {
                ssid: ssid.clone(),
                bssids: bssids.clone(),
                security_modes: security_vec.clone(),
                reason: format!(
                    "SSID '{ssid}' has an unusually large number of BSSIDs on one band — \
                     normal for stadium / campus deployments, suspicious in a home."
                ),
                severity: Severity::Low,
            });
        }
    }

    findings.sort_by_key(|f| match f.severity {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    });
    findings
}

fn canonical_security(s: &str) -> String {
    let s = s.trim();
    let lower = s.to_lowercase();
    if lower.is_empty() || lower == "none" || lower == "open" {
        "Open".into()
    } else if lower.contains("wpa3") {
        "WPA3".into()
    } else if lower.contains("wpa2") {
        "WPA2".into()
    } else if lower.contains("wpa") {
        "WPA".into()
    } else if lower.contains("wep") {
        "WEP".into()
    } else {
        s.to_string()
    }
}

fn oui(bssid: &str) -> Option<String> {
    // BSSID like "00:11:22:33:44:55"; take first three octets.
    let parts: Vec<&str> = bssid.split(':').collect();
    if parts.len() < 3 {
        return None;
    }
    Some(format!("{}:{}:{}", parts[0], parts[1], parts[2]).to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ap(ssid: &str, bssid: &str, security: Option<&str>, band: &str) -> NearbyAp {
        NearbyAp {
            ssid: Some(ssid.into()),
            bssid: Some(bssid.into()),
            channel: Some(6),
            band: Some(band.into()),
            rssi_dbm: Some(-60),
            security: security.map(|s| s.into()),
            phy_mode: None,
            width_mhz: None,
            vendor: None,
            name_redacted: false,
        }
    }

    #[test]
    fn detects_open_plus_secured_evil_twin() {
        let nearby = vec![
            ap("CoffeeShop", "aa:bb:cc:11:22:33", Some("WPA2 Personal"), "2.4"),
            ap("CoffeeShop", "00:11:22:33:44:55", Some("None"), "2.4"),
        ];
        let findings = detect(&nearby);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].reason.contains("evil-twin"));
    }

    #[test]
    fn ignores_wpa2_wpa3_transition_mode() {
        let nearby = vec![
            ap("HomeWiFi", "aa:bb:cc:11:22:33", Some("WPA2/WPA3 Personal"), "5"),
            ap("HomeWiFi", "aa:bb:cc:11:22:34", Some("WPA3 Personal"), "5"),
        ];
        let findings = detect(&nearby);
        assert!(
            findings.is_empty(),
            "transition-mode should not flag rogue: {findings:?}"
        );
    }

    #[test]
    fn detects_different_vendor_ouis() {
        let nearby = vec![
            ap("OfficeWiFi", "aa:bb:cc:11:22:33", Some("WPA2"), "5"),
            ap("OfficeWiFi", "00:11:22:33:44:55", Some("WPA2"), "5"),
        ];
        let findings = detect(&nearby);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn ignores_single_bssid_ssid() {
        let nearby = vec![ap("HomeWiFi", "aa:bb:cc:11:22:33", Some("WPA2"), "5")];
        assert!(detect(&nearby).is_empty());
    }

    #[test]
    fn ignores_redacted_ssid() {
        let mut a1 = ap("X", "aa:bb:cc:11:22:33", Some("Open"), "5");
        let mut a2 = ap("X", "00:11:22:33:44:55", Some("WPA2"), "5");
        a1.ssid = None;
        a2.ssid = None;
        assert!(detect(&[a1, a2]).is_empty());
    }
}
