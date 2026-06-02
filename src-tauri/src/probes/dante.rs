//! Dante-specific mDNS discovery.
//!
//! Separate from the general `discovery/mdns.rs` browse because we need to
//! preserve the TXT-record properties (`tx=`, `rx=`, `sr=`, `model=`,
//! `latency=`) — the general browse drops them once classification is done.
//! Also browses a Dante-flavoured service-type list (Audinate's `_netaudio-*`
//! family, Dante Domain Manager `_ddm._tcp`, AES67 `_aes67._udp`).
//!
//! Returns a `Vec<DanteDevice>` with cross-referenced channel counts,
//! sample-rate, latency profile, and redundancy state (inferred from
//! whether the same device announces on more than one IP).

use mdns_sd::{IfKind, ServiceDaemon, ServiceEvent};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use crate::types::DanteDevice;

/// Audinate / AES67 service types we browse. Listed in priority order so
/// `_netaudio-arc` (the canonical control channel) shows up first in the
/// per-device service list.
const DANTE_TYPES: &[&str] = &[
    "_netaudio-arc._udp.local.",
    "_netaudio-cmc._udp.local.",
    "_netaudio-dbc._udp.local.",
    "_netaudio-chan._udp.local.",
    "_netaudio-eve._udp.local.",
    "_ddm._tcp.local.",
    "_aes67._udp.local.",
];

/// One raw observation before we collapse duplicates by hostname.
#[derive(Debug, Clone)]
struct Observation {
    hostname: String,
    addresses: Vec<String>,
    services: Vec<String>,
    props: HashMap<String, String>,
}

/// Browse Audinate / AES67 service types for `window`. Returns one
/// `DanteDevice` per distinct hostname (the only stable identifier across
/// Dante's redundant primary/secondary interfaces).
///
/// When `pin_iface` is `Some(name)` the underlying mDNS daemon is
/// restricted to that single NIC — typically a wired USB-Ethernet
/// adapter on the audio VLAN. Passing `None` (or an empty / "auto"
/// string) keeps the previous behaviour of browsing every up interface.
///
/// Safe to call from a blocking thread (e.g. `tokio::task::spawn_blocking`).
pub fn browse_blocking(window: Duration, pin_iface: Option<&str>) -> Vec<DanteDevice> {
    let mdns = match ServiceDaemon::new() {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("dante mDNS daemon init failed: {e}");
            return Vec::new();
        }
    };

    // Pin the daemon to a specific NIC when the caller asked for one. We
    // disable all interfaces first so the user's selection is the *only*
    // path Dante traffic crosses — critical when Dante lives on a
    // separate VLAN that's only reachable via a wired adapter.
    let pin = pin_iface
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("auto"));
    if let Some(name) = pin {
        if let Err(e) = mdns.disable_interface(IfKind::All) {
            tracing::warn!("dante mDNS: disable_interface(All) failed: {e}");
        }
        if let Err(e) = mdns.enable_interface(IfKind::Name(name.to_string())) {
            tracing::warn!("dante mDNS: enable_interface({name}) failed: {e}");
        }
    }

    let receivers: Vec<_> = DANTE_TYPES
        .iter()
        .filter_map(|t| mdns.browse(t).ok())
        .collect();

    if receivers.is_empty() {
        let _ = mdns.shutdown();
        return Vec::new();
    }

    let mut by_hostname: HashMap<String, Observation> = HashMap::new();
    let deadline = Instant::now() + window;

    while Instant::now() < deadline {
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
                    let hostname = info
                        .get_hostname()
                        .trim_end_matches('.')
                        .to_lowercase();
                    let svc = info
                        .get_type()
                        .trim_end_matches('.')
                        .trim_end_matches(".local")
                        .to_string();

                    let entry = by_hostname.entry(hostname.clone()).or_insert_with(|| {
                        Observation {
                            hostname: hostname.clone(),
                            addresses: vec![],
                            services: vec![],
                            props: HashMap::new(),
                        }
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

                    // Capture TXT properties — keys are normalised lower-case.
                    for prop in info.get_properties().iter() {
                        let k = prop.key().to_lowercase();
                        let v = prop.val_str().to_string();
                        if !v.is_empty() {
                            entry.props.entry(k).or_insert(v);
                        }
                    }
                }
            }
        }

        if !got_any {
            std::thread::sleep(poll);
        }
    }

    for t in DANTE_TYPES {
        let _ = mdns.stop_browse(t);
    }
    let _ = mdns.shutdown();

    // Build DanteDevice rows. Collapse same-hostname rows; multi-address
    // devices show as `redundancy="redundant"`.
    let mut out: Vec<DanteDevice> = Vec::with_capacity(by_hostname.len());
    for obs in by_hostname.into_values() {
        // Pick primary IP = lowest sorted (deterministic). Skip link-local
        // 169.254/16 addresses unless that's all we have.
        let mut addrs = obs.addresses.clone();
        addrs.sort();
        let mut non_ll: Vec<&String> = addrs.iter().filter(|a| !a.starts_with("169.254.")).collect();
        if non_ll.is_empty() {
            non_ll = addrs.iter().collect();
        }
        let primary = match non_ll.first() {
            Some(a) => (*a).clone(),
            None => continue,
        };

        let unique_subnets: HashSet<String> = addrs
            .iter()
            .filter_map(|a| {
                let parts: Vec<&str> = a.split('.').collect();
                if parts.len() == 4 {
                    Some(format!("{}.{}.{}", parts[0], parts[1], parts[2]))
                } else {
                    None
                }
            })
            .collect();

        let redundancy = match unique_subnets.len() {
            0 | 1 => {
                if addrs.len() > 1 {
                    "primary_only".to_string()
                } else {
                    "none".to_string()
                }
            }
            _ => "redundant".to_string(),
        };

        let model = obs
            .props
            .get("model")
            .cloned()
            .or_else(|| obs.props.get("md").cloned())
            // Heuristic fallback: many Dante hostnames embed the model name.
            .or_else(|| derive_model_from_hostname(&obs.hostname));

        let manufacturer = obs.props.get("mf").cloned().or_else(|| obs.props.get("manufacturer").cloned());

        let tx_channels = parse_chan_count(&obs.props, "tx");
        let rx_channels = parse_chan_count(&obs.props, "rx");
        let sample_rate_hz = parse_sample_rate(&obs.props);
        let latency_profile_ms = parse_latency(&obs.props);

        out.push(DanteDevice {
            ip: primary,
            hostname: Some(obs.hostname),
            model,
            manufacturer,
            services: obs.services,
            tx_channels,
            rx_channels,
            sample_rate_hz,
            latency_profile_ms,
            redundancy,
            on_interface: None, // backfilled by the orchestrator using addr_to_iface
            control_ports_open: Vec::new(), // backfilled by TCP probe
            on_wifi: false, // backfilled by Wi-Fi cross-ref
        });
    }
    out.sort_by(|a, b| a.ip.cmp(&b.ip));
    out
}

fn derive_model_from_hostname(host: &str) -> Option<String> {
    // Dante hostnames often look like "Y001-AVIO-USB-12345.local" or
    // "shure-mxa910-aa11bb22.local". Pluck the alpha-segment(s) between
    // the optional manufacturer prefix and the trailing serial.
    let base = host.trim_end_matches(".local").trim_end_matches(".local.");
    let parts: Vec<&str> = base.split('-').collect();
    if parts.len() < 2 {
        return None;
    }
    // Drop trailing all-hex serial-style chunks.
    let mut trimmed: Vec<&str> = parts
        .into_iter()
        .rev()
        .skip_while(|p| p.chars().all(|c| c.is_ascii_hexdigit()) && p.len() >= 6)
        .collect();
    trimmed.reverse();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.join("-"))
}

fn parse_chan_count(props: &HashMap<String, String>, key: &str) -> Option<u32> {
    props.get(key).and_then(|v| v.parse::<u32>().ok())
}

fn parse_sample_rate(props: &HashMap<String, String>) -> Option<u32> {
    for k in ["sr", "samplerate", "sample_rate", "rate"] {
        if let Some(v) = props.get(k).and_then(|v| v.parse::<u32>().ok()) {
            // Sanity bounds — Dante range is 44.1k–192k.
            if (44000..=200_000).contains(&v) {
                return Some(v);
            }
        }
    }
    None
}

fn parse_latency(props: &HashMap<String, String>) -> Option<f32> {
    for k in ["latency", "latency_ms", "lat"] {
        if let Some(v) = props.get(k).and_then(|s| s.parse::<f32>().ok()) {
            if (0.05..=20.0).contains(&v) {
                return Some(v);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_model_strips_hex_serial() {
        assert_eq!(
            derive_model_from_hostname("shure-mxa910-aa11bb22ccdd"),
            Some("shure-mxa910".to_string())
        );
        assert_eq!(
            derive_model_from_hostname("y001-avio-usb-deadbeef0123"),
            Some("y001-avio-usb".to_string())
        );
        // Short hostnames pass through unchanged.
        assert_eq!(
            derive_model_from_hostname("mixer-a"),
            Some("mixer-a".to_string())
        );
    }
}
