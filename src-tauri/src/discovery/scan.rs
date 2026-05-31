use crate::discovery::{arp, classify::classify, oui::vendor_for_mac};
use crate::probes::reachability::ping;
use crate::types::DeviceInfo;
use chrono::Utc;
use std::net::IpAddr;
use tokio::task::JoinSet;

/// Discover devices via ARP, enrich with vendor + classification, and run a
/// short per-device latency probe. Returns devices sorted by IP.
pub async fn discover_and_probe() -> Vec<DeviceInfo> {
    let entries = match arp::read_arp_table().await {
        Ok(e) => e,
        Err(_) => return vec![],
    };

    let mut set: JoinSet<DeviceInfo> = JoinSet::new();
    let now = Utc::now();
    for entry in entries {
        if is_multicast_or_broadcast(&entry.ip, &entry.mac) {
            continue;
        }
        set.spawn(async move {
            let vendor = vendor_for_mac(&entry.mac).map(|s| s.to_string());
            let hostname = entry.hostname_hint.clone();
            let class = classify(vendor.as_deref(), hostname.as_deref());
            // 2 quick pings so an offline device doesn't block the scan.
            let latency = ping(&entry.ip, 2).await;
            let online = latency.is_some();
            DeviceInfo {
                mac: entry.mac,
                ip: Some(entry.ip),
                hostname,
                vendor,
                class,
                first_seen: now,
                last_seen: now,
                online,
                latency_ms: latency,
            }
        });
    }

    let mut devices = Vec::new();
    while let Some(r) = set.join_next().await {
        if let Ok(d) = r {
            devices.push(d);
        }
    }
    devices.sort_by_key(ip_key);
    devices
}

fn ip_key(d: &DeviceInfo) -> Vec<u8> {
    d.ip.as_deref()
        .and_then(|s| s.parse::<IpAddr>().ok())
        .map(|ip| match ip {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        })
        .unwrap_or_default()
}

/// ARP tables include entries for multicast groups (224.0.0.0/4, 239.x, ff02::…)
/// and the subnet broadcast address — these aren't real "devices", so we drop
/// them from the device list.
fn is_multicast_or_broadcast(ip: &str, mac: &str) -> bool {
    if mac.eq_ignore_ascii_case("ff:ff:ff:ff:ff:ff") {
        return true;
    }
    if mac.starts_with("01:00:5e") || mac.starts_with("33:33:") {
        return true;
    }
    if let Ok(parsed) = ip.parse::<IpAddr>() {
        match parsed {
            IpAddr::V4(v4) => v4.is_multicast() || v4.is_broadcast(),
            IpAddr::V6(v6) => v6.is_multicast(),
        }
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_broadcast_mac() {
        assert!(is_multicast_or_broadcast(
            "192.168.1.255",
            "ff:ff:ff:ff:ff:ff"
        ));
    }

    #[test]
    fn filters_ipv4_multicast() {
        assert!(is_multicast_or_broadcast(
            "224.0.0.251",
            "01:00:5e:00:00:fb"
        ));
        assert!(is_multicast_or_broadcast(
            "239.255.255.250",
            "01:00:5e:7f:ff:fa"
        ));
    }

    #[test]
    fn filters_ipv6_multicast_mac() {
        assert!(is_multicast_or_broadcast("fe80::1", "33:33:00:00:00:01"));
    }

    #[test]
    fn keeps_regular_unicast() {
        assert!(!is_multicast_or_broadcast(
            "192.168.1.84",
            "d4:9d:c0:ce:50:84"
        ));
    }
}
