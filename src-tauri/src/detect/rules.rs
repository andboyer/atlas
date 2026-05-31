use super::{Context, RuleHit};
use crate::types::{DeviceClass, Severity};

pub type Rule = fn(&Context) -> Option<RuleHit>;

pub fn all_rules() -> Vec<Rule> {
    vec![
        // ── Local link ──
        rule_weak_signal,
        rule_low_snr,
        rule_slow_tx_rate,
        rule_on_2_4ghz_band,
        // ── Internet / upstream ──
        rule_no_gateway,
        rule_gateway_high_latency,
        rule_upstream_only_high,
        rule_dns_slow,
        rule_packet_loss,
        rule_internet_unreachable,
        // ── Network-wide ──
        rule_ap_overload,
        rule_many_devices_offline,
        rule_slow_device,
        // ── POS-specific ──
        rule_pos_terminal_offline,
        rule_pos_printer_break,
        rule_pos_processor_unreachable,
        rule_pos_processor_high_latency,
        // ── IoT-specific ──
        rule_iot_dropouts_2_4ghz,
        rule_iot_majority_offline,
        // ── User watchlist ──
        rule_watched_device_offline,
        // ── Anomaly detection ──
        rule_anomaly_rssi_drop,
        rule_anomaly_latency_spike,
        rule_anomaly_loss_spike,
        // ── Captive portal ──
        rule_captive_portal,
        // ── DNS leak + MTU ──
        rule_dns_leak,
        rule_low_mtu,
    ]
}

// ─────────────────────────── Local-link rules ───────────────────────────

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
                "SNR {snr} dB with otherwise strong RSSI {rssi} dBm — likely interference"
            )],
            affected_devices: vec![],
            recommendation_id: Some("rec.change_channel"),
        })
    } else {
        None
    }
}

fn rule_slow_tx_rate(ctx: &Context) -> Option<RuleHit> {
    let tx = ctx.link.tx_rate_mbps?;
    let rssi = ctx.link.rssi_dbm.unwrap_or(-100);
    // If the radio claims a healthy RSSI but tx rate is in the basement,
    // it usually means heavy retries, driver issues, or channel contention.
    if tx < 50.0 && rssi > -65 {
        Some(RuleHit {
            rule_id: "link.slow_tx_rate",
            title: "WiFi link is much slower than your signal suggests".into(),
            severity: Severity::Medium,
            confidence: 0.7,
            evidence: vec![format!(
                "Negotiated TX rate {tx:.0} Mbps with RSSI {rssi} dBm — \
                 expect a few hundred Mbps at this signal strength"
            )],
            affected_devices: vec![],
            recommendation_id: Some("rec.change_channel"),
        })
    } else {
        None
    }
}

fn rule_on_2_4ghz_band(ctx: &Context) -> Option<RuleHit> {
    if matches!(ctx.link.band.as_deref(), Some("2.4")) {
        Some(RuleHit {
            rule_id: "link.on_2_4ghz",
            title: "This device is connected on 2.4 GHz".into(),
            severity: Severity::Low,
            confidence: 0.8,
            evidence: vec![
                "2.4 GHz is slower and more congested than 5 / 6 GHz".into(),
                "Modern routers usually steer capable devices to 5 GHz \
                 automatically; if this device is sticking to 2.4, it may \
                 be too far from the AP or the AP needs band-steering."
                    .into(),
            ],
            affected_devices: vec![],
            recommendation_id: Some("rec.prefer_5ghz"),
        })
    } else {
        None
    }
}

// ─────────────────────────── Internet / upstream rules ───────────────────

fn rule_no_gateway(ctx: &Context) -> Option<RuleHit> {
    if ctx.reach.gateway_ip.is_none() {
        Some(RuleHit {
            rule_id: "internet.no_gateway",
            title: "No default gateway detected".into(),
            severity: Severity::Critical,
            confidence: 0.95,
            evidence: vec![
                "Couldn't find a default route — this machine has no path off the LAN.".into(),
            ],
            affected_devices: vec![],
            recommendation_id: Some("rec.check_router_link"),
        })
    } else if ctx.reach.gateway_latency_ms.is_none() {
        Some(RuleHit {
            rule_id: "internet.gateway_unreachable",
            title: "Default gateway is not responding".into(),
            severity: Severity::Critical,
            confidence: 0.9,
            evidence: vec![format!(
                "Gateway {} did not answer pings — the router may be down \
                 or blocking ICMP.",
                ctx.reach.gateway_ip.as_deref().unwrap_or("?")
            )],
            affected_devices: vec![],
            recommendation_id: Some("rec.check_router_link"),
        })
    } else {
        None
    }
}

fn rule_gateway_high_latency(ctx: &Context) -> Option<RuleHit> {
    let gw = ctx.reach.gateway_latency_ms?;
    if gw > 30.0 {
        Some(RuleHit {
            rule_id: "internet.gateway_high_latency",
            title: "Slow round-trip to your router".into(),
            severity: if gw > 80.0 {
                Severity::High
            } else {
                Severity::Medium
            },
            confidence: 0.8,
            evidence: vec![format!(
                "Gateway ping ~{gw:.0} ms — wired LAN is normally <5 ms, \
                 strong WiFi is normally <15 ms"
            )],
            affected_devices: vec![],
            recommendation_id: Some("rec.move_closer_or_add_ap"),
        })
    } else {
        None
    }
}

fn rule_upstream_only_high(ctx: &Context) -> Option<RuleHit> {
    let gw = ctx.reach.gateway_latency_ms?;
    let inet = ctx.reach.internet_latency_ms?;
    if gw < 15.0 && inet > 80.0 {
        Some(RuleHit {
            rule_id: "internet.upstream_slow",
            title: "Your LAN is fine but the internet path is slow".into(),
            severity: Severity::Medium,
            confidence: 0.85,
            evidence: vec![format!(
                "Gateway ~{gw:.0} ms, internet ~{inet:.0} ms — bottleneck is \
                 upstream of your router (ISP / peering)."
            )],
            affected_devices: vec![],
            recommendation_id: Some("rec.contact_isp"),
        })
    } else {
        None
    }
}

fn rule_dns_slow(ctx: &Context) -> Option<RuleHit> {
    let dns = ctx.reach.dns_latency_ms?;
    let gw = ctx.reach.gateway_latency_ms.unwrap_or(0.0);
    if dns > 40.0 && gw < 15.0 {
        Some(RuleHit {
            rule_id: "internet.dns_slow",
            title: "DNS resolution is slow".into(),
            severity: Severity::Medium,
            confidence: 0.8,
            evidence: vec![
                format!("DNS lookup ~{dns:.1} ms vs gateway ping ~{gw:.1} ms"),
                "Local network is fine; resolver is the bottleneck".into(),
            ],
            affected_devices: vec![],
            recommendation_id: Some("rec.switch_dns"),
        })
    } else {
        None
    }
}

fn rule_packet_loss(ctx: &Context) -> Option<RuleHit> {
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
            evidence: vec![format!("{loss:.1}% packet loss observed")],
            affected_devices: vec![],
            recommendation_id: Some("rec.enable_sqm_qos"),
        })
    } else {
        None
    }
}

fn rule_internet_unreachable(ctx: &Context) -> Option<RuleHit> {
    let gw_ok = ctx.reach.gateway_latency_ms.is_some();
    let inet_down = ctx.reach.internet_latency_ms.is_none();
    if gw_ok && inet_down {
        Some(RuleHit {
            rule_id: "internet.unreachable",
            title: "Router is reachable but the internet is not".into(),
            severity: Severity::Critical,
            confidence: 0.85,
            evidence: vec!["Pings to the router succeed but pings to 1.1.1.1 do not — \
                 your ISP link is down or the WAN port has no upstream."
                .into()],
            affected_devices: vec![],
            recommendation_id: Some("rec.contact_isp"),
        })
    } else {
        None
    }
}

// ─────────────────────────── Network-wide rules ─────────────────────────

fn rule_ap_overload(ctx: &Context) -> Option<RuleHit> {
    // Don't include the router itself or APs in the device-count concern.
    let clients = ctx
        .devices
        .iter()
        .filter(|d| !matches!(d.class, DeviceClass::RouterAp))
        .count();
    if clients >= 25 {
        Some(RuleHit {
            rule_id: "network.ap_overload",
            title: format!("Many devices on one network ({clients})"),
            severity: if clients >= 40 {
                Severity::High
            } else {
                Severity::Medium
            },
            confidence: 0.6,
            evidence: vec![
                format!("{clients} client devices visible on the LAN"),
                "A single consumer AP usually starts to struggle past ~25–30 \
                 concurrent clients, especially with mixed IoT traffic."
                    .into(),
            ],
            affected_devices: vec![],
            recommendation_id: Some("rec.add_capacity"),
        })
    } else {
        None
    }
}

fn rule_many_devices_offline(ctx: &Context) -> Option<RuleHit> {
    let total = ctx.devices.len();
    if total < 6 {
        return None;
    }
    let offline = ctx.devices.iter().filter(|d| !d.online).count();
    let pct = (offline as f32 / total as f32) * 100.0;
    if pct >= 40.0 {
        Some(RuleHit {
            rule_id: "network.many_offline",
            title: format!("{offline} of {total} known devices are not responding"),
            severity: Severity::High,
            confidence: 0.6,
            evidence: vec![
                format!("{pct:.0}% of recently-seen devices didn't answer pings just now"),
                "Could be normal (laptops asleep, phones away) or could be a \
                 broader LAN/DHCP issue — check the per-device list."
                    .into(),
            ],
            affected_devices: ctx
                .devices
                .iter()
                .filter(|d| !d.online)
                .map(|d| d.mac.clone())
                .collect(),
            recommendation_id: Some("rec.check_router_link"),
        })
    } else {
        None
    }
}

fn rule_slow_device(ctx: &Context) -> Option<RuleHit> {
    let slow: Vec<_> = ctx
        .devices
        .iter()
        .filter(|d| d.online && d.latency_ms.is_some_and(|l| l > 200.0))
        .collect();
    if slow.is_empty() {
        return None;
    }
    Some(RuleHit {
        rule_id: "network.slow_device",
        title: format!("{} device(s) responding slowly on the LAN", slow.len()),
        severity: Severity::Medium,
        confidence: 0.65,
        evidence: slow
            .iter()
            .map(|d| {
                format!(
                    "{} ({}) responding in {:.0} ms",
                    d.hostname.clone().unwrap_or_else(|| d.mac.clone()),
                    d.ip.clone().unwrap_or_else(|| "no IP".into()),
                    d.latency_ms.unwrap_or_default()
                )
            })
            .collect(),
        affected_devices: slow.iter().map(|d| d.mac.clone()).collect(),
        recommendation_id: Some("rec.move_closer_or_add_ap"),
    })
}

// ─────────────────────────── POS-specific rules ─────────────────────────

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

fn rule_pos_printer_break(ctx: &Context) -> Option<RuleHit> {
    let pos_online = ctx
        .devices
        .iter()
        .any(|d| matches!(d.class, DeviceClass::PosTerminal) && d.online);
    let offline_printers: Vec<_> = ctx
        .devices
        .iter()
        .filter(|d| matches!(d.class, DeviceClass::Printer) && !d.online)
        .collect();
    if pos_online && !offline_printers.is_empty() {
        Some(RuleHit {
            rule_id: "pos.printer_unreachable",
            title: "POS terminal can't reach a kitchen / receipt printer".into(),
            severity: Severity::High,
            confidence: 0.8,
            evidence: offline_printers
                .iter()
                .map(|d| {
                    format!(
                        "Printer {} ({}) is offline while POS terminals are up",
                        d.hostname.clone().unwrap_or_else(|| d.mac.clone()),
                        d.ip.clone().unwrap_or_else(|| "no IP".into())
                    )
                })
                .collect(),
            affected_devices: offline_printers.iter().map(|d| d.mac.clone()).collect(),
            recommendation_id: Some("rec.pos_printer_path"),
        })
    } else {
        None
    }
}

// ─────────────────────────── IoT-specific rules ─────────────────────────

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

fn rule_iot_majority_offline(ctx: &Context) -> Option<RuleHit> {
    let smart: Vec<_> = ctx
        .devices
        .iter()
        .filter(|d| {
            matches!(
                d.class,
                DeviceClass::SmartHome
                    | DeviceClass::IpCamera
                    | DeviceClass::Thermostat
                    | DeviceClass::VoiceAssistant
            )
        })
        .collect();
    if smart.len() < 3 {
        return None;
    }
    let offline = smart.iter().filter(|d| !d.online).count();
    if offline * 2 >= smart.len() {
        Some(RuleHit {
            rule_id: "iot.majority_offline",
            title: format!(
                "{} of {} smart-home devices not responding",
                offline,
                smart.len()
            ),
            severity: Severity::High,
            confidence: 0.7,
            evidence: vec![
                "Half or more of your smart-home / IoT fleet is offline at once".into(),
                "When this many cheap radios drop simultaneously it's almost \
                 always the 2.4 GHz band or the IoT-specific SSID, not the \
                 devices themselves."
                    .into(),
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

// ─────────────────────────── POS service & watchlist rules ───────────────────────────

fn rule_pos_processor_unreachable(ctx: &Context) -> Option<RuleHit> {
    if ctx.services.is_empty() {
        return None;
    }
    let down: Vec<&str> = ctx
        .services
        .iter()
        .filter(|s| !s.reachable)
        .map(|s| s.target.as_str())
        .collect();
    if down.is_empty() {
        return None;
    }
    Some(RuleHit {
        rule_id: "pos.processor_unreachable",
        title: format!("{} payment / SaaS endpoint(s) unreachable", down.len()),
        severity: Severity::High,
        confidence: 0.95,
        evidence: down.iter().map(|s| format!("Cannot reach {s}")).collect(),
        affected_devices: vec![],
        recommendation_id: Some("rec.pos_processor_path"),
    })
}

fn rule_pos_processor_high_latency(ctx: &Context) -> Option<RuleHit> {
    if ctx.services.is_empty() {
        return None;
    }
    let threshold = ctx.profile.service_high_latency_ms;
    let slow: Vec<(&str, f32)> = ctx
        .services
        .iter()
        .filter_map(|s| s.latency_ms.map(|ms| (s.target.as_str(), ms)))
        .filter(|(_, ms)| *ms > threshold)
        .collect();
    if slow.is_empty() {
        return None;
    }
    Some(RuleHit {
        rule_id: "pos.processor_high_latency",
        title: format!("{} payment / SaaS endpoint(s) responding slowly", slow.len()),
        severity: Severity::Medium,
        confidence: 0.8,
        evidence: slow
            .iter()
            .map(|(t, ms)| format!("{t} took {ms:.0} ms (threshold {threshold:.0})"))
            .collect(),
        affected_devices: vec![],
        recommendation_id: Some("rec.pos_processor_path"),
    })
}

fn rule_watched_device_offline(ctx: &Context) -> Option<RuleHit> {
    if ctx.profile.watchlist.is_empty() {
        return None;
    }
    let watch: std::collections::HashSet<String> = ctx
        .profile
        .watchlist
        .iter()
        .map(|m| m.to_lowercase())
        .collect();
    let offline: Vec<&crate::types::DeviceInfo> = ctx
        .devices
        .iter()
        .filter(|d| !d.online && watch.contains(&d.mac.to_lowercase()))
        .collect();
    if offline.is_empty() {
        return None;
    }
    let names: Vec<String> = offline
        .iter()
        .map(|d| {
            d.hostname
                .clone()
                .or_else(|| d.vendor.clone())
                .unwrap_or_else(|| d.mac.clone())
        })
        .collect();
    Some(RuleHit {
        rule_id: "watch.device_offline",
        title: format!("{} pinned device(s) offline", offline.len()),
        severity: Severity::Critical,
        confidence: 0.99,
        evidence: names
            .iter()
            .map(|n| format!("{n} is not responding"))
            .collect(),
        affected_devices: offline.iter().map(|d| d.mac.clone()).collect(),
        recommendation_id: Some("rec.investigate_device"),
    })
}

// ─────────────────────────── Anomaly rules ───────────────────────────────

fn rule_anomaly_rssi_drop(ctx: &Context) -> Option<RuleHit> {
    let sig = ctx
        .anomalies
        .iter()
        .find(|a| a.metric == "link.rssi_dbm")?;
    if sig.z_score > -2.5 {
        return None;
    }
    Some(RuleHit {
        rule_id: "anomaly.rssi_drop",
        title: format!(
            "WiFi signal dropped suddenly (RSSI {:.0} dBm, z = {:.1})",
            sig.current, sig.z_score
        ),
        severity: Severity::High,
        confidence: 0.75,
        evidence: vec![
            format!(
                "RSSI {:.0} dBm vs baseline {:.0} dBm (z = {:.2})",
                sig.current, sig.baseline, sig.z_score
            ),
            "Sudden drop indicates roaming failure, AP reboot, or physical obstruction.".into(),
        ],
        affected_devices: vec![],
        recommendation_id: Some("rec.anomaly_rssi"),
    })
}

fn rule_anomaly_latency_spike(ctx: &Context) -> Option<RuleHit> {
    let sig = ctx
        .anomalies
        .iter()
        .find(|a| a.metric == "reach.gateway_ms")?;
    if sig.z_score < 3.0 {
        return None;
    }
    Some(RuleHit {
        rule_id: "anomaly.latency_spike",
        title: format!(
            "Gateway latency spiked ({:.0} ms, z = {:.1})",
            sig.current, sig.z_score
        ),
        severity: Severity::High,
        confidence: 0.75,
        evidence: vec![
            format!(
                "Gateway latency {:.0} ms vs baseline {:.0} ms (z = {:.2})",
                sig.current, sig.baseline, sig.z_score
            ),
            "Latency spike may indicate congestion, interference, or router CPU saturation.".into(),
        ],
        affected_devices: vec![],
        recommendation_id: Some("rec.anomaly_latency"),
    })
}

fn rule_anomaly_loss_spike(ctx: &Context) -> Option<RuleHit> {
    let sig = ctx
        .anomalies
        .iter()
        .find(|a| a.metric == "reach.loss_pct")?;
    if sig.z_score < 3.0 {
        return None;
    }
    Some(RuleHit {
        rule_id: "anomaly.loss_spike",
        title: format!(
            "Packet loss spiked ({:.0}%, z = {:.1})",
            sig.current, sig.z_score
        ),
        severity: Severity::Critical,
        confidence: 0.85,
        evidence: vec![
            format!(
                "Loss {:.1}% vs baseline {:.1}% (z = {:.2})",
                sig.current, sig.baseline, sig.z_score
            ),
            "Loss spike often precedes complete connectivity failure; investigate immediately.".into(),
        ],
        affected_devices: vec![],
        recommendation_id: Some("rec.anomaly_loss"),
    })
}

// ─────────────────────────── Captive portal ──────────────────────────────

fn rule_captive_portal(ctx: &Context) -> Option<RuleHit> {
    if !ctx.captive_portal {
        return None;
    }
    Some(RuleHit {
        rule_id: "detect.captive_portal",
        title: "Captive portal detected — login required".into(),
        severity: Severity::Medium,
        confidence: 0.92,
        evidence: vec![
            "HTTP probe to connectivitycheck.gstatic.com did not return 204.".into(),
            "All traffic is being intercepted (hotel, airport, café, or corporate login page).".into(),
        ],
        affected_devices: vec![],
        recommendation_id: Some("rec.captive_portal"),
    })
}

// ─────────────────────────── DNS leak ────────────────────────────────────

fn rule_dns_leak(ctx: &Context) -> Option<RuleHit> {
    if !ctx.dns_leak {
        return None;
    }
    Some(RuleHit {
        rule_id: "detect.dns_leak",
        title: "DNS leak — queries routed to a public resolver".into(),
        severity: Severity::Medium,
        confidence: 0.80,
        evidence: vec![
            "DNS resolution returned an address belonging to a public resolver (Google, Cloudflare, etc.).".into(),
            "If you are using a VPN or private DNS, your DNS traffic may not be tunnelled.".into(),
        ],
        affected_devices: vec![],
        recommendation_id: Some("rec.dns_leak"),
    })
}

// ─────────────────────────── Low MTU ─────────────────────────────────────

fn rule_low_mtu(ctx: &Context) -> Option<RuleHit> {
    use crate::probes::mtu::MTU_LOW_THRESHOLD;
    let mtu = ctx.mtu_bytes?;
    if mtu >= MTU_LOW_THRESHOLD {
        return None;
    }
    Some(RuleHit {
        rule_id: "detect.low_mtu",
        title: format!("Low path MTU detected ({mtu} bytes)"),
        severity: Severity::Low,
        confidence: 0.85,
        evidence: vec![
            format!("Effective path MTU is {mtu} bytes (standard Ethernet is 1500)."),
            "This can cause slowdowns, black-hole routing, and TCP stalls for large transfers.".into(),
            "Common causes: VPN tunnel, PPPoE DSL, 6in4/GRE encapsulation.".into(),
        ],
        affected_devices: vec![],
        recommendation_id: Some("rec.low_mtu"),
    })
}

#[cfg(test)]
impl std::fmt::Debug for RuleHit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleHit")
            .field("rule_id", &self.rule_id)
            .field("title", &self.title)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::{AnomalySignal, ProfileHints};
    use crate::types::{DeviceInfo, LinkStats, ReachabilityStats, ServiceProbe};
    use chrono::Utc;

    fn empty_link() -> LinkStats {
        LinkStats {
            ssid: None,
            bssid: None,
            band: None,
            channel: None,
            channel_width_mhz: None,
            rssi_dbm: None,
            noise_dbm: None,
            snr_db: None,
            tx_rate_mbps: None,
            rx_rate_mbps: None,
            security: None,
        }
    }

    fn good_reach() -> ReachabilityStats {
        ReachabilityStats {
            gateway_ip: Some("192.168.1.1".into()),
            gateway_latency_ms: Some(3.0),
            internet_latency_ms: Some(20.0),
            dns_latency_ms: Some(15.0),
            packet_loss_pct: Some(0.0),
        }
    }

    fn dev(mac: &str, class: DeviceClass, online: bool, latency: Option<f32>) -> DeviceInfo {
        let now = Utc::now();
        DeviceInfo {
            mac: mac.into(),
            ip: Some("192.168.1.10".into()),
            hostname: None,
            vendor: None,
            class,
            first_seen: now,
            last_seen: now,
            online,
            latency_ms: latency,
            services: vec![],
        }
    }

    #[test]
    fn no_gateway_when_gateway_ip_missing() {
        let mut r = good_reach();
        r.gateway_ip = None;
        r.gateway_latency_ms = None;
        let ctx = Context {
            link: &empty_link(),
            reach: &r,
            devices: &[],
            services: &[],
            profile: ProfileHints::default(),
            anomalies: vec![],
            captive_portal: false,
            dns_leak: false,
            mtu_bytes: None,
        };
        assert!(rule_no_gateway(&ctx).is_some());
    }

    #[test]
    fn upstream_slow_fires_when_lan_fine_but_internet_slow() {
        let mut r = good_reach();
        r.internet_latency_ms = Some(150.0);
        let ctx = Context {
            link: &empty_link(),
            reach: &r,
            devices: &[],
            services: &[],
            profile: ProfileHints::default(),
            anomalies: vec![],
            captive_portal: false,
            dns_leak: false,
            mtu_bytes: None,
        };
        assert!(rule_upstream_only_high(&ctx).is_some());
    }

    #[test]
    fn internet_unreachable_fires_when_inet_missing_but_gw_ok() {
        let mut r = good_reach();
        r.internet_latency_ms = None;
        let ctx = Context {
            link: &empty_link(),
            reach: &r,
            devices: &[],
            services: &[],
            profile: ProfileHints::default(),
            anomalies: vec![],
            captive_portal: false,
            dns_leak: false,
            mtu_bytes: None,
        };
        assert!(rule_internet_unreachable(&ctx).is_some());
    }

    #[test]
    fn pos_printer_break_fires() {
        let devices = vec![
            dev(
                "aa:aa:aa:aa:aa:01",
                DeviceClass::PosTerminal,
                true,
                Some(3.0),
            ),
            dev("aa:aa:aa:aa:aa:02", DeviceClass::Printer, false, None),
        ];
        let ctx = Context {
            link: &empty_link(),
            reach: &good_reach(),
            devices: &devices,
            services: &[],
            profile: ProfileHints::default(),
            anomalies: vec![],
            captive_portal: false,
            dns_leak: false,
            mtu_bytes: None,
        };
        assert!(rule_pos_printer_break(&ctx).is_some());
    }

    #[test]
    fn ap_overload_fires_with_many_clients() {
        let devices: Vec<_> = (0..30)
            .map(|i| {
                dev(
                    &format!("aa:aa:aa:aa:aa:{i:02x}"),
                    DeviceClass::Unknown,
                    true,
                    Some(5.0),
                )
            })
            .collect();
        let ctx = Context {
            link: &empty_link(),
            reach: &good_reach(),
            devices: &devices,
            services: &[],
            profile: ProfileHints::default(),
            anomalies: vec![],
            captive_portal: false,
            dns_leak: false,
            mtu_bytes: None,
        };
        assert!(rule_ap_overload(&ctx).is_some());
    }

    #[test]
    fn slow_device_fires_for_high_latency_host() {
        let devices = vec![dev(
            "aa:aa:aa:aa:aa:09",
            DeviceClass::Unknown,
            true,
            Some(450.0),
        )];
        let ctx = Context {
            link: &empty_link(),
            reach: &good_reach(),
            devices: &devices,
            services: &[],
            profile: ProfileHints::default(),
            anomalies: vec![],
            captive_portal: false,
            dns_leak: false,
            mtu_bytes: None,
        };
        assert!(rule_slow_device(&ctx).is_some());
    }

    #[test]
    fn iot_majority_offline_fires() {
        let devices = vec![
            dev("aa:aa:aa:aa:aa:10", DeviceClass::SmartHome, false, None),
            dev("aa:aa:aa:aa:aa:11", DeviceClass::SmartHome, false, None),
            dev("aa:aa:aa:aa:aa:12", DeviceClass::IpCamera, true, Some(8.0)),
        ];
        let ctx = Context {
            link: &empty_link(),
            reach: &good_reach(),
            devices: &devices,
            services: &[],
            profile: ProfileHints::default(),
            anomalies: vec![],
            captive_portal: false,
            dns_leak: false,
            mtu_bytes: None,
        };
        assert!(rule_iot_majority_offline(&ctx).is_some());
    }

    #[test]
    fn happy_path_produces_no_findings() {
        let link = LinkStats {
            rssi_dbm: Some(-50),
            snr_db: Some(45),
            band: Some("5".into()),
            tx_rate_mbps: Some(866.0),
            ..empty_link()
        };
        let ctx = Context {
            link: &link,
            reach: &good_reach(),
            devices: &[dev(
                "aa:aa:aa:aa:aa:20",
                DeviceClass::Laptop,
                true,
                Some(4.0),
            )],
            services: &[],
            profile: ProfileHints::default(),
            anomalies: vec![],
            captive_portal: false,
            dns_leak: false,
            mtu_bytes: None,
        };
        let hits: Vec<_> = all_rules().iter().filter_map(|r| r(&ctx)).collect();
        assert!(hits.is_empty(), "expected no findings, got {hits:?}");
    }

    #[test]
    fn pos_processor_unreachable_fires_for_failed_target() {
        let services = vec![
            ServiceProbe {
                target: "api.clover.com:443".into(),
                reachable: false,
                latency_ms: None,
                error: Some("timeout".into()),
            },
            ServiceProbe {
                target: "connect.squareup.com:443".into(),
                reachable: true,
                latency_ms: Some(45.0),
                error: None,
            },
        ];
        let ctx = Context {
            link: &empty_link(),
            reach: &good_reach(),
            devices: &[],
            services: &services,
            profile: ProfileHints::default(),
            anomalies: vec![],
            captive_portal: false,
            dns_leak: false,
            mtu_bytes: None,
        };
        let hit = rule_pos_processor_unreachable(&ctx).expect("should fire");
        assert_eq!(hit.rule_id, "pos.processor_unreachable");
        assert!(hit.evidence.iter().any(|e| e.contains("clover.com")));
    }

    #[test]
    fn pos_processor_high_latency_uses_profile_threshold() {
        let services = vec![ServiceProbe {
            target: "api.clover.com:443".into(),
            reachable: true,
            latency_ms: Some(800.0),
            error: None,
        }];
        let profile = ProfileHints {
            watchlist: vec![],
            service_high_latency_ms: 600.0,
        };
        let ctx = Context {
            link: &empty_link(),
            reach: &good_reach(),
            devices: &[],
            services: &services,
            profile,
            anomalies: vec![],
            captive_portal: false,
            dns_leak: false,
            mtu_bytes: None,
        };
        let hit = rule_pos_processor_high_latency(&ctx).expect("should fire");
        assert_eq!(hit.rule_id, "pos.processor_high_latency");
    }

    #[test]
    fn watched_device_offline_fires_critical() {
        let devices = vec![
            dev("aa:bb:cc:dd:ee:01", DeviceClass::PosTerminal, false, None),
            dev("11:22:33:44:55:66", DeviceClass::Laptop, true, Some(5.0)),
        ];
        let profile = ProfileHints {
            watchlist: vec!["AA:BB:CC:DD:EE:01".to_string()],
            service_high_latency_ms: 1000.0,
        };
        let ctx = Context {
            link: &empty_link(),
            reach: &good_reach(),
            devices: &devices,
            services: &[],
            profile,
            anomalies: vec![],
            captive_portal: false,
            dns_leak: false,
            mtu_bytes: None,
        };
        let hit = rule_watched_device_offline(&ctx).expect("should fire");
        assert_eq!(hit.severity, Severity::Critical);
        assert_eq!(hit.affected_devices, vec!["aa:bb:cc:dd:ee:01"]);
    }

    #[test]
    fn watched_device_does_not_fire_when_online() {
        let devices = vec![dev("aa:bb:cc:dd:ee:01", DeviceClass::PosTerminal, true, Some(3.0))];
        let profile = ProfileHints {
            watchlist: vec!["aa:bb:cc:dd:ee:01".to_string()],
            service_high_latency_ms: 1000.0,
        };
        let ctx = Context {
            link: &empty_link(),
            reach: &good_reach(),
            devices: &devices,
            services: &[],
            profile,
            anomalies: vec![],
            captive_portal: false,
            dns_leak: false,
            mtu_bytes: None,
        };
        assert!(rule_watched_device_offline(&ctx).is_none());
    }

    #[test]
    fn anomaly_rssi_drop_fires_on_negative_z() {
        let sig = AnomalySignal {
            metric: "link.rssi_dbm",
            current: -85.0,
            baseline: -55.0,
            z_score: -3.2,
        };
        let ctx = Context {
            link: &empty_link(),
            reach: &good_reach(),
            devices: &[],
            services: &[],
            profile: ProfileHints::default(),
            anomalies: vec![sig],
            captive_portal: false,
            dns_leak: false,
            mtu_bytes: None,
        };
        let hit = rule_anomaly_rssi_drop(&ctx).expect("should fire");
        assert_eq!(hit.rule_id, "anomaly.rssi_drop");
    }

    #[test]
    fn anomaly_latency_spike_fires_on_positive_z() {
        let sig = AnomalySignal {
            metric: "reach.gateway_ms",
            current: 350.0,
            baseline: 5.0,
            z_score: 4.1,
        };
        let ctx = Context {
            link: &empty_link(),
            reach: &good_reach(),
            devices: &[],
            services: &[],
            profile: ProfileHints::default(),
            anomalies: vec![sig],
            captive_portal: false,
            dns_leak: false,
            mtu_bytes: None,
        };
        let hit = rule_anomaly_latency_spike(&ctx).expect("should fire");
        assert_eq!(hit.rule_id, "anomaly.latency_spike");
    }

    #[test]
    fn captive_portal_rule_fires_when_detected() {
        let ctx = Context {
            link: &empty_link(),
            reach: &good_reach(),
            devices: &[],
            services: &[],
            profile: ProfileHints::default(),
            anomalies: vec![],
            captive_portal: true,
            dns_leak: false,
            mtu_bytes: None,
        };
        let hit = rule_captive_portal(&ctx).expect("should fire");
        assert_eq!(hit.rule_id, "detect.captive_portal");
    }

    #[test]
    fn captive_portal_rule_silent_when_not_detected() {
        let ctx = Context {
            link: &empty_link(),
            reach: &good_reach(),
            devices: &[],
            services: &[],
            profile: ProfileHints::default(),
            anomalies: vec![],
            captive_portal: false,
            dns_leak: false,
            mtu_bytes: None,
        };
        assert!(rule_captive_portal(&ctx).is_none());
    }
}

// Allow `Debug` formatting of RuleHit inside tests above.
