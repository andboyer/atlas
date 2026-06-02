//! Per-interface multicast group snapshot.
//!
//! Reads `netstat -gn` (BSD/macOS variant — always installed, no privileges
//! needed) and classifies each joined group into a `purpose` bucket so the
//! UI can colour-code it and the LLM gets cheap categorisation.
//!
//! Output is shaped for direct consumption by `probes::av::collect`.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::process::Command;

use crate::types::{InterfaceMulticast, MulticastGroup};

/// Run `netstat -gn` and return per-interface multicast snapshots.
///
/// On any failure (binary missing, parse error) returns an empty Vec —
/// the AV diagnostic falls back to "no multicast information available"
/// which is benign in the UI.
pub fn collect_blocking() -> Vec<InterfaceMulticast> {
    let out = match Command::new("netstat").args(["-gn"]).output() {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!("netstat -gn failed to spawn: {e}");
            return Vec::new();
        }
    };
    if !out.status.success() {
        tracing::warn!(
            "netstat -gn exited with status {:?}",
            out.status.code()
        );
        return Vec::new();
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    parse_netstat_g(&stdout)
}

/// Parse the BSD/macOS `netstat -gn` output. The relevant section looks
/// like:
///
/// ```text
/// IPv4 Multicast Group Memberships
/// Group               Link-layer Address  Netif
/// 224.0.0.1           <none>              en0
/// 224.0.0.251         1:0:5e:0:0:fb       en0
/// 239.255.255.250     1:0:5e:7f:ff:fa     en1
/// ```
///
/// We only care about IPv4 here — IPv6 multicast snapshot can be added
/// later if Dante/AVB IPv6 ever ships.
fn parse_netstat_g(stdout: &str) -> Vec<InterfaceMulticast> {
    let mut in_ipv4 = false;
    let mut header_seen = false;
    let mut by_iface: HashMap<String, Vec<MulticastGroup>> = HashMap::new();

    for raw in stdout.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }

        if line.contains("IPv4 Multicast Group Memberships")
            || line.contains("IPv4 Multicast Group")
        {
            in_ipv4 = true;
            header_seen = false;
            continue;
        }
        if line.contains("IPv6 Multicast Group") {
            in_ipv4 = false;
            continue;
        }
        if !in_ipv4 {
            continue;
        }
        if !header_seen {
            // The header row starts with "Group".
            if line.to_lowercase().starts_with("group") {
                header_seen = true;
            }
            continue;
        }

        // Tokenise on whitespace; expect 2 or 3 tokens (group, [link-layer], netif).
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 2 {
            continue;
        }
        let group_str = cols[0];
        let iface = cols[cols.len() - 1];
        let parsed: Option<Ipv4Addr> = group_str.parse().ok();
        if parsed.is_none() {
            continue;
        }
        let purpose = classify_group(group_str);
        by_iface
            .entry(iface.to_string())
            .or_default()
            .push(MulticastGroup {
                iface: iface.to_string(),
                group: group_str.to_string(),
                purpose,
            });
    }

    // Roll up counts.
    let mut out: Vec<InterfaceMulticast> = by_iface
        .into_iter()
        .map(|(iface, groups)| {
            let dante_audio_groups = groups
                .iter()
                .filter(|g| g.purpose == "dante_audio")
                .count() as u32;
            let ptp_groups = groups.iter().filter(|g| g.purpose == "ptp").count() as u32;
            InterfaceMulticast {
                iface,
                group_count: groups.len() as u32,
                dante_audio_groups,
                ptp_groups,
                groups,
            }
        })
        .collect();
    // Stable order — Wi-Fi (`en0`) usually first; then alpha.
    out.sort_by(|a, b| a.iface.cmp(&b.iface));
    out
}

/// Classify a multicast group address into one of our purpose buckets.
/// The buckets are tuned for AV-over-IP diagnosis and are coarser than
/// IANA assignments — e.g. all of 239/8 administratively-scoped is
/// `dante_audio` only inside the Dante default range (239.69.x.x),
/// everything else administratively-scoped is `other`.
pub fn classify_group(addr: &str) -> String {
    let Ok(ip): Result<Ipv4Addr, _> = addr.parse() else {
        return "other".to_string();
    };
    let octets = ip.octets();

    // Link-local control plane (224.0.0.0/24).
    if octets[0] == 224 && octets[1] == 0 && octets[2] == 0 {
        // PTP delay messages use 224.0.0.107 in PTPv2 peer-to-peer mode.
        if octets[3] == 107 {
            return "ptp".to_string();
        }
        if octets[3] == 251 {
            return "mdns".to_string();
        }
        return "link_local".to_string();
    }

    // PTPv1 / PTPv2 end-to-end (224.0.1.129 / 224.0.1.130-132).
    if octets[0] == 224 && octets[1] == 0 && octets[2] == 1 && (129..=132).contains(&octets[3]) {
        return "ptp".to_string();
    }

    // SSDP / UPnP.
    if octets == [239, 255, 255, 250] {
        return "ssdp".to_string();
    }

    // Dante default audio flow range is 239.69.x.x (audio + clocking).
    if octets[0] == 239 && octets[1] == 69 {
        return "dante_audio".to_string();
    }

    // mDNS.
    if octets == [224, 0, 0, 251] {
        return "mdns".to_string();
    }

    // Administratively-scoped 239/8 catch-all (often vendor-specific control).
    if octets[0] == 239 {
        return "control".to_string();
    }

    "other".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_well_known_groups() {
        assert_eq!(classify_group("224.0.0.1"), "link_local");
        assert_eq!(classify_group("224.0.0.251"), "mdns");
        assert_eq!(classify_group("224.0.0.107"), "ptp");
        assert_eq!(classify_group("224.0.1.129"), "ptp");
        assert_eq!(classify_group("239.69.10.5"), "dante_audio");
        assert_eq!(classify_group("239.255.255.250"), "ssdp");
        assert_eq!(classify_group("239.1.2.3"), "control");
        assert_eq!(classify_group("garbage"), "other");
    }

    #[test]
    fn parses_macos_netstat_output() {
        let sample = "\
Link-layer Multicast Group Memberships
Group                                      Link-layer Address  Netif
1:0:5e:0:0:1                               <none>              en0

IPv4 Multicast Group Memberships
Group               Link-layer Address  Netif
224.0.0.1           <none>              en0
224.0.0.251         1:0:5e:0:0:fb       en0
239.69.0.10         1:0:5e:45:0:a       en1
239.255.255.250     1:0:5e:7f:ff:fa     en0

IPv6 Multicast Group Memberships
Group                                      Link-layer Address  Netif
";
        let out = parse_netstat_g(sample);
        assert_eq!(out.len(), 2);
        let en0 = out.iter().find(|i| i.iface == "en0").unwrap();
        assert_eq!(en0.group_count, 3);
        assert!(en0.groups.iter().any(|g| g.purpose == "ssdp"));
        let en1 = out.iter().find(|i| i.iface == "en1").unwrap();
        assert_eq!(en1.dante_audio_groups, 1);
    }
}
