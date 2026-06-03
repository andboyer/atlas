//! LLDP / CDP neighbor discovery (ARP + OUI fallback variant).
//!
//! Proper LLDP/CDP capture would open a raw L2 socket (BPF on macOS,
//! AF_PACKET on Linux, Npcap on Windows) and parse 802.1AB TLVs to
//! identify the upstream switch's chassis, port, system name, and VLAN.
//! Shipping that across all three OSes is significant work — for v1 we
//! implement a useful subset:
//!
//!   * Enumerate the ARP table on the pinned interface.
//!   * Filter to entries on the same /24 (or whichever broadcast
//!     domain `iface` is on) — these are physically adjacent hosts.
//!   * Look up each MAC's OUI vendor via [`crate::oui::lookup`] and
//!     classify it as switch-class (Cisco, Aruba, Ubiquiti, Meraki,
//!     Ruckus, HPE, Juniper, Extreme) or leaf-class (everything else).
//!   * Report verdict:
//!     - `switch_identified` — at least one ARP neighbor's OUI matches
//!       a known switch vendor, suggesting the directly-attached switch
//!       has L3 management on this VLAN (very common in AV deployments).
//!     - `neighbors_only` — we see neighbors but none are switch-class,
//!       so we can't identify the switch from ARP alone.
//!     - `silent` — empty ARP table (cold cache, isolated VLAN).
//!     - `not_supported` — platform path failed to enumerate.
//!
//! Cross-platform mechanism:
//!   * macOS / Linux — shell `arp -a -n`, parse `(ip) at xx:xx:xx:xx:xx:xx`.
//!   * Windows — PowerShell `Get-NetNeighbor | ConvertTo-Json`.
//!
//! The L2 LLDP capture path can be added on top of this in a future
//! iteration without changing the public probe API — `mechanism` will
//! flip from `"arp_oui_fallback"` to `"l2_capture"` and the
//! `chassis_id` / `port_id` / `system_name` fields will be populated
//! from real TLV decoding.

use std::process::Command;

use crate::oui;
use crate::probes::iface as iface_probe;
use crate::types::{LldpNeighbor, LldpProbeResult};

const SWITCH_VENDOR_KEYWORDS: &[&str] = &[
    "cisco",
    "aruba",
    "ubiquiti",
    "meraki",
    "ruckus",
    "hpe",
    "hewlett",
    "juniper",
    "extreme",
    "netgear",
    "tp-link",
    "tplink",
    "huawei",
    "dell",
    "brocade",
    "mikrotik",
    "fortinet",
    "luxul",
    "zyxel",
    "linksys",
    "edgecore",
    "arista",
];

/// Synchronous blocking entrypoint — call from `tokio::task::spawn_blocking`.
pub fn run_blocking(iface: &str, listen_secs: u32) -> LldpProbeResult {
    let mut result = LldpProbeResult {
        iface: iface.to_string(),
        listen_secs,
        neighbors: Vec::new(),
        mechanism: "arp_oui_fallback".to_string(),
        verdict: "silent".to_string(),
        error: None,
    };

    let local_subnet = iface_probe::find_by_name(iface)
        .and_then(|i| i.ipv4)
        .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
        .map(|a| {
            let o = a.octets();
            // Assume /24 — good enough heuristic for "same broadcast
            // domain". Full netmask discovery would need platform-
            // specific code we already have elsewhere but not exposed.
            [o[0], o[1], o[2]]
        });

    #[cfg(target_os = "macos")]
    let raw = enum_arp_unix();
    #[cfg(target_os = "linux")]
    let raw = enum_arp_unix();
    #[cfg(target_os = "windows")]
    let raw = enum_arp_windows();
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let raw: Result<Vec<(String, String)>, String> =
        Err("platform not supported".to_string());

    let entries = match raw {
        Ok(v) => v,
        Err(e) => {
            result.mechanism = "none".to_string();
            result.verdict = "not_supported".to_string();
            result.error = Some(e);
            return result;
        }
    };

    let mut neighbors: Vec<LldpNeighbor> = Vec::new();
    let mut switch_seen = false;
    for (ip, mac) in entries {
        // Filter to same /24 if we can resolve the iface's subnet.
        if let Some(subnet) = local_subnet {
            if let Ok(parsed) = ip.parse::<std::net::Ipv4Addr>() {
                let o = parsed.octets();
                if !(o[0] == subnet[0] && o[1] == subnet[1] && o[2] == subnet[2]) {
                    continue;
                }
            }
        }
        let vendor = oui::lookup(&mac).map(|s| s.to_string());
        let is_switch = match vendor.as_deref() {
            Some(v) => {
                let lower = v.to_ascii_lowercase();
                SWITCH_VENDOR_KEYWORDS.iter().any(|k| lower.contains(k))
            }
            None => false,
        };
        if is_switch {
            switch_seen = true;
        }
        neighbors.push(LldpNeighbor {
            source_mac: mac,
            source_ip: Some(ip),
            via: "arp".to_string(),
            chassis_id: None,
            port_id: None,
            port_description: None,
            system_name: None,
            system_description: None,
            vlan_id: None,
            oui_vendor: vendor,
            capabilities: if is_switch {
                vec!["inferred-switch".to_string()]
            } else {
                Vec::new()
            },
        });
    }

    result.verdict = if neighbors.is_empty() {
        "silent".to_string()
    } else if switch_seen {
        "switch_identified".to_string()
    } else {
        "neighbors_only".to_string()
    };
    result.neighbors = neighbors;
    result
}

#[cfg(unix)]
fn enum_arp_unix() -> Result<Vec<(String, String)>, String> {
    // `arp -a -n` is portable across macOS and Linux. Output:
    //   ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
    //   ? (192.168.1.50) at (incomplete) on en0 ifscope [ethernet]
    let out = Command::new("arp").args(["-a", "-n"]).output();
    let out = match out {
        Ok(o) => o,
        Err(e) => return Err(format!("spawn arp: {e}")),
    };
    let s = String::from_utf8_lossy(&out.stdout);
    let mut entries = Vec::new();
    for line in s.lines() {
        if let Some((ip, mac)) = parse_arp_line(line) {
            entries.push((ip, mac));
        }
    }
    Ok(entries)
}

#[cfg(target_os = "windows")]
fn enum_arp_windows() -> Result<Vec<(String, String)>, String> {
    use crate::process_util::NoConsoleExt;
    let out = Command::new("powershell.exe")
        .no_console()
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | \
             Where-Object { $_.State -ne 'Unreachable' -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' -and $_.LinkLayerAddress -ne '' } | \
             Select-Object IPAddress,LinkLayerAddress | ConvertTo-Csv -NoTypeInformation",
        ])
        .output()
        .map_err(|e| format!("spawn powershell: {e}"))?;
    let s = String::from_utf8_lossy(&out.stdout);
    let mut lines = s.lines();
    let _ = lines.next(); // header
    let mut entries = Vec::new();
    for row in lines {
        let cells: Vec<&str> = row.split(',').map(|c| c.trim_matches('"').trim()).collect();
        if cells.len() < 2 {
            continue;
        }
        let ip = cells[0].to_string();
        // Windows formats MAC as XX-XX-XX-XX-XX-XX; normalise to colons.
        let mac = cells[1].replace('-', ":").to_ascii_lowercase();
        if !ip.is_empty() && !mac.is_empty() {
            entries.push((ip, mac));
        }
    }
    Ok(entries)
}

fn parse_arp_line(line: &str) -> Option<(String, String)> {
    // ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
    let open = line.find('(')?;
    let close = line.find(')')?;
    if close <= open + 1 {
        return None;
    }
    let ip = line[open + 1..close].trim().to_string();
    let at_idx = line.find(" at ")?;
    let after = &line[at_idx + 4..];
    let mac_token = after.split_whitespace().next()?;
    if mac_token == "(incomplete)" || !mac_token.contains(':') {
        return None;
    }
    // Some Linux arp -a outputs zero-padded "0:1:2:..." form — normalise.
    let mac_norm: String = mac_token
        .split(':')
        .map(|b| {
            if b.len() == 1 {
                format!("0{}", b)
            } else {
                b.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(":")
        .to_ascii_lowercase();
    Some((ip, mac_norm))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_macos_arp_line() {
        let line = "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]";
        let (ip, mac) = parse_arp_line(line).expect("parse");
        assert_eq!(ip, "192.168.1.1");
        assert_eq!(mac, "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn parses_short_mac_form() {
        let line = "router (10.0.0.1) at 0:1:2:3:4:5 on en0 [ethernet]";
        let (_ip, mac) = parse_arp_line(line).expect("parse");
        assert_eq!(mac, "00:01:02:03:04:05");
    }

    #[test]
    fn skips_incomplete_arp_entries() {
        let line = "? (192.168.1.50) at (incomplete) on en0 ifscope [ethernet]";
        assert!(parse_arp_line(line).is_none());
    }

    #[test]
    fn switch_vendor_match_is_case_insensitive() {
        let lower = "Cisco Meraki".to_ascii_lowercase();
        assert!(SWITCH_VENDOR_KEYWORDS.iter().any(|k| lower.contains(k)));
    }
}
