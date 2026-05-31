use super::{Context, RuleHit};
use crate::types::{DeviceClass, Severity};

pub type Rule = fn(&Context) -> Option<RuleHit>;

pub fn all_rules() -> Vec<Rule> {
    vec![
        rule_weak_signal,
        rule_low_snr,
        rule_dns_slow,
        rule_bufferbloat_hint,
        rule_pos_terminal_offline,
        rule_iot_dropouts_2_4ghz,
    ]
}

fn rule_weak_signal(ctx: &Context) -> Option<RuleHit> {
    let rssi = ctx.link.rssi_dbm?;
    if rssi <= -70 {
        Some(RuleHit {
            rule_id: "link.weak_signal",
            title: "Weak WiFi signal at this location".into(),
            severity: if rssi <= -80 {
                Severity::High
            } else {
                Severity::Medium
            },
            confidence: 0.9,
            evidence: vec![format!(
                "RSSI {} dBm (anything below -70 dBm is weak)",
                rssi
            )],
            affected_devices: vec![],
            recommendation_id: Some("rec.move_closer_or_add_ap"),
        })
    } else {
        None
    }
}

fn rule_low_snr(ctx: &Context) -> Option<RuleHit> {
    let snr = ctx.link.snr_db?;
    let rssi = ctx.link.rssi_dbm.unwrap_or(0);
    if snr < 20 && rssi > -70 {
        Some(RuleHit {
            rule_id: "link.low_snr",
            title: "Noisy RF environment".into(),
            severity: Severity::Medium,
            confidence: 0.7,
            evidence: vec![format!(
                "SNR {} dB with otherwise strong RSSI {} dBm — likely interference",
                snr, rssi
            )],
            affected_devices: vec![],
            recommendation_id: Some("rec.change_channel"),
        })
    } else {
        None
    }
}

fn rule_dns_slow(ctx: &Context) -> Option<RuleHit> {
    let dns = ctx.reach.dns_latency_ms?;
    let gw = ctx.reach.gateway_latency_ms.unwrap_or(0.0);
    if dns > 40.0 && gw < 10.0 {
        Some(RuleHit {
            rule_id: "internet.dns_slow",
            title: "DNS resolution is slow".into(),
            severity: Severity::Medium,
            confidence: 0.8,
            evidence: vec![
                format!("DNS lookup ~{:.1} ms vs gateway ping ~{:.1} ms", dns, gw),
                "Local network is fine; resolver is the bottleneck".into(),
            ],
            affected_devices: vec![],
            recommendation_id: Some("rec.switch_dns"),
        })
    } else {
        None
    }
}

fn rule_bufferbloat_hint(ctx: &Context) -> Option<RuleHit> {
    let loss = ctx.reach.packet_loss_pct?;
    if loss >= 1.0 {
        Some(RuleHit {
            rule_id: "internet.packet_loss",
            title: "Packet loss on internet path".into(),
            severity: if loss >= 3.0 {
                Severity::High
            } else {
                Severity::Medium
            },
            confidence: 0.7,
            evidence: vec![format!("{:.1}% packet loss observed", loss)],
            affected_devices: vec![],
            recommendation_id: Some("rec.enable_sqm_qos"),
        })
    } else {
        None
    }
}

fn rule_pos_terminal_offline(ctx: &Context) -> Option<RuleHit> {
    let offline: Vec<_> = ctx
        .devices
        .iter()
        .filter(|d| matches!(d.class, DeviceClass::PosTerminal) && !d.online)
        .collect();
    if offline.is_empty() {
        return None;
    }
    Some(RuleHit {
        rule_id: "pos.terminal_offline",
        title: format!("{} POS terminal(s) currently offline", offline.len()),
        severity: Severity::Critical,
        confidence: 0.95,
        evidence: offline
            .iter()
            .map(|d| {
                format!(
                    "{} ({}) last seen {}",
                    d.hostname.clone().unwrap_or_else(|| d.mac.clone()),
                    d.ip.clone().unwrap_or_else(|| "no IP".into()),
                    d.last_seen
                )
            })
            .collect(),
        affected_devices: offline.iter().map(|d| d.mac.clone()).collect(),
        recommendation_id: Some("rec.pos_stabilize"),
    })
}

fn rule_iot_dropouts_2_4ghz(ctx: &Context) -> Option<RuleHit> {
    let smart: Vec<_> = ctx
        .devices
        .iter()
        .filter(|d| matches!(d.class, DeviceClass::SmartHome | DeviceClass::IpCamera))
        .collect();
    let any_offline = smart.iter().any(|d| !d.online);
    let on_24 = matches!(ctx.link.band.as_deref(), Some("2.4"));
    if any_offline && (on_24 || ctx.link.band.is_none()) {
        Some(RuleHit {
            rule_id: "iot.dropouts_2_4ghz",
            title: "IoT devices intermittently offline (likely 2.4 GHz congestion)".into(),
            severity: Severity::High,
            confidence: 0.65,
            evidence: vec![
                "Smart-home / camera devices appear offline".into(),
                "Most IoT devices use 2.4 GHz where congestion is common".into(),
            ],
            affected_devices: smart
                .iter()
                .filter(|d| !d.online)
                .map(|d| d.mac.clone())
                .collect(),
            recommendation_id: Some("rec.iot_dedicated_ssid"),
        })
    } else {
        None
    }
}
