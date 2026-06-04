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

use crate::probes::{dante, iface as iface_probe, multicast};
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
/// `pin_iface` lets the user pin every probe (mDNS browse, TCP control
/// reachability sweep, and the Wi-Fi subnet cross-reference) to a
/// specific NIC — typically a wired USB-Ethernet adapter on the audio
/// VLAN. Passing `None` (or empty / "auto") keeps the previous
/// kernel-default routing behaviour.
///
/// Safe to call concurrently with other diagnostics — each sub-probe
/// either blocks in `spawn_blocking` or is async-safe.
pub async fn collect(
    last_scan: Option<&ScanResult>,
    pin_iface: Option<&str>,
) -> AvDiagnosticsResult {
    let pin = pin_iface
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("auto"))
        .map(|s| s.to_string());

    let pin_for_dante = pin.clone();
    let dante_handle = tokio::task::spawn_blocking(move || {
        dante::browse_blocking(MDNS_WINDOW, pin_for_dante.as_deref())
    });
    let multicast_handle = tokio::task::spawn_blocking(multicast::collect_blocking);

    let mut devices: Vec<DanteDevice> = dante_handle.await.unwrap_or_default();
    let multicast: Vec<InterfaceMulticast> = multicast_handle.await.unwrap_or_default();

    // Resolve the IPv4 of the pinned interface up-front so the on-Wi-Fi
    // cross-reference and the TCP probe both share one view.
    let pin_iface_info = pin
        .as_deref()
        .and_then(iface_probe::find_by_name);

    // Did the user explicitly pin a wired interface? If so the AV tab
    // should not infer any Wi-Fi involvement — the previous behaviour
    // of treating the pinned NIC's /24 as a Wi-Fi subnet would mark
    // every Dante endpoint on the wired audio VLAN as "on Wi-Fi".
    let pin_is_wired = pin_iface_info
        .as_ref()
        .and_then(|i| i.is_wireless)
        .map(|w| !w)
        .unwrap_or(false);

    // Augment each Dante device with TCP reachability + on-Wi-Fi flag.
    let wifi_subnet = if pin_is_wired {
        // Explicit wired pin — never flag devices on this subnet as
        // "on Wi-Fi". Fall through to whatever the scan reports for the
        // host's actual Wi-Fi interface, which may legitimately differ.
        wifi_subnet_from_scan(last_scan)
    } else {
        wifi_subnet_from_iface_or_scan(pin_iface_info.as_ref(), last_scan)
    };
    for device in devices.iter_mut() {
        device.control_ports_open =
            probe_dante_ports(&device.ip, pin.as_deref()).await;
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

    let warnings = build_warnings(&devices, &multicast, last_scan, pin.as_deref(), pin_is_wired);

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
///
/// When `pin_iface` is set, every probe is dispatched from a socket
/// pinned to that NIC (macOS `IP_BOUND_IF`, Linux `SO_BINDTODEVICE`),
/// so the kernel cannot silently route the probe out the Wi-Fi
/// interface instead of the wired audio VLAN.
async fn probe_dante_ports(ip: &str, pin_iface: Option<&str>) -> Vec<u16> {
    let mut open = Vec::new();
    for &port in DANTE_TCP_PORTS {
        if iface_probe::tcp_connect_via_iface(pin_iface, ip, port, TCP_CONNECT_TIMEOUT).await {
            open.push(port);
        }
    }
    open
}

/// Pick the subnet we'll use to flag Dante devices as "on Wi-Fi".
///
///   - If the caller pinned an interface AND that interface is itself
///     a wireless radio (or we couldn't classify it) AND it has an
///     IPv4, use its IP as the subnet hint (a /24). This is right for
///     the "I'm troubleshooting from this Wi-Fi host" workflow.
///   - Otherwise fall back to the gateway IP from the last Wi-Fi scan.
///
/// Callers that have already determined the pinned NIC is wired skip
/// this entirely and go straight to `wifi_subnet_from_scan` — the
/// pinned NIC's subnet is the AV VLAN, not a Wi-Fi subnet, and using
/// it here would incorrectly mark every wired Dante endpoint as
/// "on Wi-Fi".
fn wifi_subnet_from_iface_or_scan(
    pin: Option<&iface_probe::NetworkInterfaceInfo>,
    scan: Option<&ScanResult>,
) -> Option<(Ipv4Addr, u8)> {
    if let Some(info) = pin {
        let treat_as_wifi = info.is_wireless.unwrap_or(true);
        if treat_as_wifi {
            if let Some(ip) = info.ipv4.as_deref().and_then(|s| s.parse::<Ipv4Addr>().ok()) {
                return Some((ip, 24));
            }
        }
    }
    wifi_subnet_from_scan(scan)
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
    pin_iface: Option<&str>,
    pin_is_wired: bool,
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
    // remind that Dante's PoE-powered endpoints are normally wired —
    // unless the user already pinned the diagnostics to a wired NIC, in
    // which case the reminder is just noise. A wireless pin (or no pin
    // at all on a Wi-Fi-attached host) still warrants the advisory.
    if !pin_is_wired && pin_iface.is_none() {
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
