//! AV-over-IP diagnostics orchestrator.
//!
//! Runs the three unprivileged sub-probes in parallel:
//!   1. Dante mDNS browse (Audinate + AES67 + DDM service types)
//!   2. Multicast group snapshot (`netstat -gn` parse)
//!   3. TCP reachability sweep against Dante control ports (4440/4444/4455/8800)
//!
//! Cross-references each Dante device against the most recent Wi-Fi scan
//! to flag endpoints riding Wi-Fi (officially unsupported by Audinate).
//! Emits a set of deterministic heuristic warnings BEFORE any LLM runs.
//!
//! The privileged half (IGMP querier listen, active PTP, pcap) is handled
//! separately by `probes::deep` and runs as a re-exec of the main binary
//! under `osascript … administrator privileges`. Results land in
//! `AvDiagnosticsResult.deep_probe`.

use chrono::Utc;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::time::timeout;

use crate::probes::{dante, multicast};
use crate::types::{
    AvDiagnosticsResult, AvWarning, DanteDevice, InterfaceMulticast, ScanResult,
};

/// mDNS browse window. Dante devices announce within 1–3s in practice;
/// 5s is a comfortable upper bound that keeps the UI responsive.
const MDNS_WINDOW: Duration = Duration::from_secs(5);

/// Per-port TCP connect timeout for the Dante control reachability sweep.
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_millis(500);

/// Dante control TCP ports we probe. These are well-known to Audinate's
/// protocol stack:
///   - 4440: Discovery (legacy)
///   - 4444: Conmon (status / heartbeat)
///   - 4455: Routing control
///   - 8800: Web admin (status only)
const DANTE_TCP_PORTS: &[u16] = &[4440, 4444, 4455, 8800];

/// Run the full unprivileged AV diagnostics sweep. Takes the most recent
/// `ScanResult` so we can cross-reference Dante endpoints against the
/// currently-associated Wi-Fi subnet.
///
/// Safe to call concurrently with other diagnostics — each sub-probe
/// either blocks in `spawn_blocking` or is async-safe.
pub async fn collect(last_scan: Option<&ScanResult>) -> AvDiagnosticsResult {
    let dante_handle = tokio::task::spawn_blocking(|| dante::browse_blocking(MDNS_WINDOW));
    let multicast_handle = tokio::task::spawn_blocking(multicast::collect_blocking);

    let mut devices: Vec<DanteDevice> = dante_handle.await.unwrap_or_default();
    let multicast: Vec<InterfaceMulticast> = multicast_handle.await.unwrap_or_default();

    // Augment each Dante device with TCP reachability + on-Wi-Fi flag.
    let wifi_subnet = wifi_subnet_from_scan(last_scan);
    for device in devices.iter_mut() {
        device.control_ports_open = probe_dante_ports(&device.ip).await;
        device.on_wifi = wifi_subnet
            .as_ref()
            .is_some_and(|(net, mask)| ip_in_subnet(&device.ip, *net, *mask));
    }

    let ddm_seen = devices
        .iter()
        .any(|d| d.services.iter().any(|s| s.contains("_ddm")));
    let aes67_seen = devices
        .iter()
        .any(|d| d.services.iter().any(|s| s.contains("_aes67")));

    let warnings = build_warnings(&devices, &multicast, last_scan);

    AvDiagnosticsResult {
        generated_at: Utc::now(),
        dante_devices: devices,
        ddm_seen,
        aes67_seen,
        multicast,
        warnings,
        deep_probe: None,
    }
}

/// Async TCP-connect probe of the well-known Dante control ports. Returns
/// the subset that accepted a connection within `TCP_CONNECT_TIMEOUT`.
async fn probe_dante_ports(ip: &str) -> Vec<u16> {
    let mut open = Vec::new();
    for &port in DANTE_TCP_PORTS {
        let addr = format!("{ip}:{port}");
        let fut = tokio::net::TcpStream::connect(addr);
        match timeout(TCP_CONNECT_TIMEOUT, fut).await {
            Ok(Ok(_)) => open.push(port),
            _ => {}
        }
    }
    open
}

/// Pull (network, netmask) from the last scan's Wi-Fi link information.
/// Returns None if no scan, no IP, or the IP doesn't parse.
fn wifi_subnet_from_scan(scan: Option<&ScanResult>) -> Option<(Ipv4Addr, u8)> {
    let scan = scan?;
    // The ScanResult.link doesn't carry the host IP/subnet directly — it
    // would require an interface lookup. For v1 we use the gateway IP as
    // a /24 hint, which is right for the overwhelming majority of home
    // and small-business networks. (A future refinement can read SCDynamicStore
    // for the actual netmask.)
    let gw_str = scan.reachability.gateway_ip.as_deref()?;
    let gw = gw_str.parse::<Ipv4Addr>().ok()?;
    Some((gw, 24))
}

fn ip_in_subnet(ip_str: &str, net: Ipv4Addr, prefix: u8) -> bool {
    let Ok(ip) = ip_str.parse::<Ipv4Addr>() else {
        return false;
    };
    if prefix == 0 {
        return true;
    }
    if prefix > 32 {
        return false;
    }
    let mask: u32 = if prefix == 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    };
    let a = u32::from(ip) & mask;
    let b = u32::from(net) & mask;
    a == b
}

/// Deterministic heuristic warnings. These run with zero AI cost and give
/// the user something concrete even with no LLM configured. The LLM later
/// gets these in its prompt so it can elaborate or contradict.
fn build_warnings(
    devices: &[DanteDevice],
    multicast: &[InterfaceMulticast],
    scan: Option<&ScanResult>,
) -> Vec<AvWarning> {
    let mut out = Vec::new();

    if devices.is_empty() {
        out.push(AvWarning {
            severity: "info".into(),
            category: "dante".into(),
            message: "No Dante or AES67 devices found on this network in the mDNS browse window. \
                If you expect Dante here, verify the device is on the same VLAN and that IGMP/mDNS \
                forwarding is enabled on the switch."
                .into(),
        });
    } else {
        // Sample-rate mismatch — Dante devices on different sample rates
        // cannot subscribe to each other.
        let rates: HashSet<u32> = devices
            .iter()
            .filter_map(|d| d.sample_rate_hz)
            .collect();
        if rates.len() > 1 {
            let mut sorted: Vec<u32> = rates.into_iter().collect();
            sorted.sort();
            let list = sorted
                .iter()
                .map(|r| format!("{:.1} kHz", *r as f32 / 1000.0))
                .collect::<Vec<_>>()
                .join(", ");
            out.push(AvWarning {
                severity: "critical".into(),
                category: "dante".into(),
                message: format!(
                    "Mixed sample rates on the network ({list}). Dante devices on different sample \
                    rates cannot pass audio to each other — align them via Dante Controller before \
                    troubleshooting other symptoms."
                ),
            });
        }

        // Endpoints on Wi-Fi (officially unsupported).
        let on_wifi: Vec<&DanteDevice> = devices.iter().filter(|d| d.on_wifi).collect();
        if !on_wifi.is_empty() {
            let names = on_wifi
                .iter()
                .map(|d| {
                    d.hostname.clone().unwrap_or_else(|| d.ip.clone())
                })
                .collect::<Vec<_>>()
                .join(", ");
            out.push(AvWarning {
                severity: "critical".into(),
                category: "wifi".into(),
                message: format!(
                    "{} Dante endpoint(s) on the Wi-Fi subnet ({names}). Dante is not supported \
                    over Wi-Fi by Audinate — APs do not preserve multicast timing, and PTP sync \
                    typically drifts within minutes.",
                    on_wifi.len()
                ),
            });
        }

        // Redundancy: report distribution if any device has redundancy
        // configured (otherwise silence — most home/small setups are single-NIC).
        let redundant = devices.iter().filter(|d| d.redundancy == "redundant").count();
        if redundant > 0 {
            let total = devices.len();
            if redundant < total {
                out.push(AvWarning {
                    severity: "warn".into(),
                    category: "dante".into(),
                    message: format!(
                        "Mixed redundancy state: {redundant}/{total} Dante devices are running \
                        redundant primary/secondary; the others are single-NIC. A failure on the \
                        primary VLAN will mute the non-redundant devices."
                    ),
                });
            }
        }

        // Devices with the control plane reachable but ZERO open control
        // ports — typically a firewall blocking the audio VLAN.
        let unreachable: Vec<&DanteDevice> = devices
            .iter()
            .filter(|d| d.control_ports_open.is_empty())
            .collect();
        if !unreachable.is_empty() && unreachable.len() < devices.len() {
            out.push(AvWarning {
                severity: "warn".into(),
                category: "dante".into(),
                message: format!(
                    "{}/{} Dante device(s) responded to mDNS but accepted no TCP connection on \
                    any of {:?}. A host firewall or VLAN ACL is likely blocking control traffic.",
                    unreachable.len(),
                    devices.len(),
                    DANTE_TCP_PORTS,
                ),
            });
        }
    }

    // Multicast snapshot heuristics.
    if !multicast.is_empty() {
        let dante_traffic: u32 = multicast.iter().map(|i| i.dante_audio_groups).sum();
        let ptp_traffic: u32 = multicast.iter().map(|i| i.ptp_groups).sum();

        if !devices.is_empty() && dante_traffic == 0 {
            out.push(AvWarning {
                severity: "warn".into(),
                category: "multicast".into(),
                message: "Dante devices announced via mDNS but no audio flows in the 239.69.x.x \
                    range are joined locally. The control plane is reachable; the audio plane \
                    likely is not (check IGMP snooping/querier on the switch)."
                    .into(),
            });
        }
        if !devices.is_empty() && ptp_traffic == 0 {
            out.push(AvWarning {
                severity: "warn".into(),
                category: "ptp".into(),
                message: "No PTP multicast groups joined locally (224.0.1.129 / 224.0.0.107). \
                    Either PTP is filtered upstream or no clock master is announcing — audio \
                    will not synchronise."
                    .into(),
            });
        }
    }

    // Wi-Fi specific. If we have a current Wi-Fi link AND devices found,
    // remind that Dante's PoE-powered endpoints are normally wired.
    if let Some(s) = scan {
        if !devices.is_empty() && s.link.ssid.is_some() {
            out.push(AvWarning {
                severity: "info".into(),
                category: "wifi".into(),
                message: format!(
                    "Diagnosing AV from a Wi-Fi host (SSID '{}'). For accurate PTP / multicast \
                    measurements, plug this machine into the audio VLAN with a wired NIC — \
                    Wi-Fi adds asymmetric latency and converts multicast to unicast.",
                    s.link.ssid.as_deref().unwrap_or("?"),
                ),
            });
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn ip_in_subnet_basic() {
        let net: Ipv4Addr = "192.168.1.1".parse().unwrap();
        assert!(ip_in_subnet("192.168.1.50", net, 24));
        assert!(!ip_in_subnet("192.168.2.50", net, 24));
        assert!(ip_in_subnet("10.0.0.5", net, 0));
    }
}
