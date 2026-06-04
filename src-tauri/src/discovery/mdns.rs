use mdns_sd::{ServiceDaemon, ServiceEvent};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Information gathered about a device via mDNS.
#[derive(Debug, Clone)]
pub struct MdnsRecord {
    /// Hostname without trailing dot, e.g. `"kitchen-ipad.local"`.
    pub hostname: String,
    /// All IP addresses the record advertised.
    pub addresses: Vec<String>,
    /// Trimmed service type strings, e.g. `"_ipp._tcp"`.
    pub services: Vec<String>,
}

/// Service types we actively browse — ordered from most-specific to broadest.
///
/// Covering printers, POS devices, Apple ecosystem, Google/Chromecast, smart-home,
/// NAS/file-sharing, SSH servers, voice assistants, and streaming devices.
const BROWSE_TYPES: &[&str] = &[
    "_ipp._tcp.local.",
    "_ipps._tcp.local.",
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_googlecast._tcp.local.",
    "_homekit._tcp.local.",
    "_ssh._tcp.local.",
    "_smb._tcp.local.",
    "_afpovertcp._tcp.local.",
    "_http._tcp.local.",
    "_device-info._tcp.local.",
    "_companion-link._tcp.local.",
    "_sonos._tcp.local.",
    "_spotifyconnect._tcp.local.",
    "_printer._tcp.local.",
];

/// Browse mDNS for `window` duration and return a map from **lowercase IP address
/// string** → `MdnsRecord`.  Safe to call from a blocking thread (e.g.
/// `tokio::task::spawn_blocking`).
pub fn browse_blocking(window: Duration) -> HashMap<String, MdnsRecord> {
    let mdns = match ServiceDaemon::new() {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("mDNS daemon init failed: {e}");
            return HashMap::new();
        }
    };

    // Subscribe to each service type; ignore individual failures (interface may
    // not support a given type).
    let receivers: Vec<_> = BROWSE_TYPES
        .iter()
        .filter_map(|t| mdns.browse(t).ok())
        .collect();

    if receivers.is_empty() {
        let _ = mdns.shutdown();
        return HashMap::new();
    }

    // hostname → record (we'll deduplicate by IP at the end)
    let mut by_hostname: HashMap<String, MdnsRecord> = HashMap::new();
    let deadline = Instant::now() + window;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let poll = remaining.min(Duration::from_millis(50));

        let mut got_any = false;
        for rx in &receivers {
            while let Ok(event) = rx.recv_timeout(Duration::from_millis(1)) {
                got_any = true;
                if let ServiceEvent::ServiceResolved(info) = event {
                    let hostname = info.get_hostname().trim_end_matches('.').to_lowercase();
                    let svc = info
                        .get_type()
                        .trim_end_matches('.')
                        .trim_end_matches(".local")
                        .to_string();

                    let entry = by_hostname
                        .entry(hostname.clone())
                        .or_insert_with(|| MdnsRecord {
                            hostname: hostname.clone(),
                            addresses: vec![],
                            services: vec![],
                        });

                    for addr in info.get_addresses() {
                        let s = addr.to_string();
                        if !entry.addresses.contains(&s) {
                            entry.addresses.push(s);
                        }
                    }
                    if !entry.services.contains(&svc) {
                        entry.services.push(svc);
                    }
                }
            }
        }

        if !got_any {
            std::thread::sleep(poll);
        }
    }

    // Stop all browse requests
    for t in BROWSE_TYPES {
        let _ = mdns.stop_browse(t);
    }
    let _ = mdns.shutdown();

    // Build IP → record map (a device may have multiple IPs; index all of them)
    let mut by_ip: HashMap<String, MdnsRecord> = HashMap::new();
    for record in by_hostname.into_values() {
        for ip in &record.addresses {
            by_ip.insert(ip.clone(), record.clone());
        }
    }
    by_ip
}

/// Map an mDNS service type string (e.g. `"_airplay._tcp"`) to a device class
/// hint string that `classify::refine_with_services` understands.
pub fn service_class_hint(svc: &str) -> Option<&'static str> {
    match svc {
        s if s.contains("_ipp") || s.contains("_ipps") || s.contains("_printer") => Some("printer"),
        s if s.contains("_airplay") || s.contains("_raop") => Some("tv_streamer"),
        s if s.contains("_googlecast") => Some("tv_streamer"),
        s if s.contains("_homekit") => Some("smart_home"),
        s if s.contains("_sonos") || s.contains("_spotifyconnect") => Some("tv_streamer"),
        s if s.contains("_smb") || s.contains("_afpovertcp") => Some("nas"),
        s if s.contains("_ssh") => Some("laptop"),
        s if s.contains("_companion-link") => Some("phone"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_class_hints() {
        assert_eq!(service_class_hint("_ipp._tcp"), Some("printer"));
        assert_eq!(service_class_hint("_airplay._tcp"), Some("tv_streamer"));
        assert_eq!(service_class_hint("_googlecast._tcp"), Some("tv_streamer"));
        assert_eq!(service_class_hint("_homekit._tcp"), Some("smart_home"));
        assert_eq!(service_class_hint("_smb._tcp"), Some("nas"));
        assert_eq!(service_class_hint("_ssh._tcp"), Some("laptop"));
        assert_eq!(service_class_hint("_companion-link._tcp"), Some("phone"));
        assert_eq!(service_class_hint("_http._tcp"), None);
    }
}
