use crate::discovery::{arp, classify::classify, mdns, oui::vendor_for_mac};
use crate::probes::reachability::ping;
use crate::types::{DeviceClass, DeviceInfo};
use chrono::Utc;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;
use tokio::task::JoinSet;

/// Discover devices via ARP, enrich with vendor + mDNS info + classification, and
/// run a short per-device latency probe. Returns devices sorted by IP.
pub async fn discover_and_probe() -> Vec<DeviceInfo> {
    // Start mDNS browse concurrently with ARP (mDNS runs for 3s in a blocking thread).
    let mdns_handle = tokio::task::spawn_blocking(|| mdns::browse_blocking(Duration::from_secs(3)));

    let entries = match arp::read_arp_table().await {
        Ok(e) => e,
        Err(_) => {
            let _ = mdns_handle.await;
            return vec![];
        }
    };

    // Await mDNS results (will already be done or close to done by now).
    let mdns_map: HashMap<String, mdns::MdnsRecord> = mdns_handle.await.unwrap_or_default();

    let mut set: JoinSet<DeviceInfo> = JoinSet::new();
    let now = Utc::now();
    for entry in entries {
        if is_multicast_or_broadcast(&entry.ip, &entry.mac) {
            continue;
        }
        // Clone what we need for the async task.
        let mdns_record = entry
            .ip
            .parse::<IpAddr>()
            .ok()
            .and_then(|ip| mdns_map.get(&ip.to_string()).cloned());

        set.spawn(async move {
            let vendor = vendor_for_mac(&entry.mac).map(|s| s.to_string());

            // Prefer mDNS hostname; fall back to ARP hint.
            let hostname = mdns_record
                .as_ref()
                .map(|r| r.hostname.clone())
                .or_else(|| entry.hostname_hint.clone());

            // Base classification from vendor + hostname.
            let mut class = classify(vendor.as_deref(), hostname.as_deref());

            // Refine class using mDNS service types when the base class is Unknown.
            let services: Vec<String> = mdns_record
                .as_ref()
                .map(|r| r.services.clone())
                .unwrap_or_default();

            if matches!(class, DeviceClass::Unknown) {
                for svc in &services {
                    if let Some(hint) = mdns::service_class_hint(svc) {
                        class = refine_class(hint);
                        break;
                    }
                }
            }

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
                services,
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

fn refine_class(hint: &str) -> DeviceClass {
    match hint {
        "printer" => DeviceClass::Printer,
        "tv_streamer" => DeviceClass::TvStreamer,
        "smart_home" => DeviceClass::SmartHome,
        "nas" => DeviceClass::Nas,
        "laptop" => DeviceClass::Laptop,
        "phone" => DeviceClass::Phone,
        _ => DeviceClass::Unknown,
    }
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
