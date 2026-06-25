//! Active subnet sweep — the "IP Scanner".
//!
//! Unlike [`crate::discovery::scan::discover_and_probe`] (which only surfaces
//! hosts already present in the kernel ARP cache), this performs an *active*
//! sweep of every address in a CIDR range:
//!
//!  1. Concurrent ICMP ping sweep (count=1, NIC-pinned) to find responders and
//!     populate the ARP cache as a side effect.
//!  2. Read the ARP table to attach MACs (and catch ICMP-blocking hosts that
//!     still answered ARP within the scanned range).
//!  3. A short mDNS browse for friendly hostnames.
//!  4. A bounded TCP connect probe across a curated common-port list for every
//!     live host, so the table can show what services are exposed.
//!
//! The range is capped at 1024 addresses (prefix >= /22) so an accidental
//! `/16` can't spawn a 65k-host sweep.

use crate::discovery::{arp, mdns, oui};
use crate::probes::reachability;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;

/// Maximum number of host addresses a single sweep may probe. Guards against
/// an operator typing a `/16` (65k hosts) and hanging the app.
const MAX_HOSTS: u32 = 1024;
/// Concurrent ICMP pings in flight.
const PING_CONCURRENCY: usize = 128;
/// Concurrent TCP connect probes in flight (across all live hosts × ports).
const PORT_CONCURRENCY: usize = 256;
/// Per-connect TCP timeout for the first port probe pass.
const PORT_TIMEOUT: Duration = Duration::from_millis(1000);
/// Longer timeout for the retry pass (slow devices / SYN-rate-limited hosts).
const PORT_TIMEOUT_RETRY: Duration = Duration::from_millis(2000);
/// Target file-descriptor soft limit. The ping sweep spawns one subprocess
/// per host (each holding pipe fds) and the port probe opens hundreds of
/// sockets at once — on macOS the default `RLIMIT_NOFILE` soft limit is only
/// 256, so without raising it `connect()` starts failing with `EMFILE` and
/// genuinely-open ports get silently reported as closed.
const FD_SOFT_TARGET: u64 = 8192;

/// Curated TCP ports worth probing on a LAN host. Kept small so the port
/// sweep stays fast: SSH, telnet, DNS, web, SMB/NetBIOS, printers (IPP/RAW),
/// RDP, VNC, and a few NAS / hypervisor admin panels.
const COMMON_PORTS: &[u16] = &[
    22, 23, 53, 80, 139, 443, 445, 515, 631, 3389, 5000, 5900, 8006, 8080, 8443, 9100,
];

/// One host discovered by the sweep. Mirrors the `IpScanHost` TS interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpScanHost {
    pub ip: String,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    pub latency_ms: Option<f32>,
    pub online: bool,
    pub open_ports: Vec<u16>,
}

/// Aggregate result of a subnet sweep. Mirrors the `IpScanResult` TS interface.
#[derive(Debug, Clone, Serialize)]
pub struct IpScanResult {
    pub cidr: String,
    pub host_count: usize,
    pub online_count: usize,
    pub duration_ms: u128,
    pub hosts: Vec<IpScanHost>,
}

/// Derive a sensible default `/24` CIDR from an interface IPv4. Falls back to
/// `192.168.1.0/24` when the address can't be parsed.
pub fn default_cidr_for(ipv4: &str) -> String {
    match ipv4.parse::<Ipv4Addr>() {
        Ok(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        Err(_) => "192.168.1.0/24".to_string(),
    }
}

/// Parse a CIDR like `192.168.1.0/24` (or a bare `192.168.1.10`, treated as
/// `/24`). Returns `(network_u32, prefix)` with host bits cleared.
fn parse_cidr(cidr: &str) -> Result<(u32, u8), String> {
    let cidr = cidr.trim();
    let (ip_part, prefix) = match cidr.split_once('/') {
        Some((ip, p)) => {
            let prefix: u8 = p
                .trim()
                .parse()
                .map_err(|_| format!("invalid prefix in `{cidr}`"))?;
            (ip.trim(), prefix)
        }
        None => (cidr, 24),
    };
    if prefix > 32 {
        return Err(format!("prefix /{prefix} out of range (0-32)"));
    }
    let ip: Ipv4Addr = ip_part
        .parse()
        .map_err(|_| format!("invalid IPv4 address `{ip_part}`"))?;
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let network = u32::from(ip) & mask;
    Ok((network, prefix))
}

/// Expand a parsed CIDR into the list of host addresses to probe (network and
/// broadcast excluded for prefixes <= /30). Errors if the range exceeds
/// [`MAX_HOSTS`].
fn host_addresses(network: u32, prefix: u8) -> Result<Vec<Ipv4Addr>, String> {
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let broadcast = network | !mask;
    let (first, last) = if prefix >= 31 {
        (network, broadcast)
    } else {
        (network + 1, broadcast - 1)
    };
    let count = last.saturating_sub(first).saturating_add(1);
    if count > MAX_HOSTS {
        return Err(format!(
            "range too large: {count} addresses (max {MAX_HOSTS}). Use a smaller subnet (e.g. /24)."
        ));
    }
    Ok((first..=last).map(Ipv4Addr::from).collect())
}

fn in_subnet(ip: Ipv4Addr, network: u32, prefix: u8) -> bool {
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(ip) & mask) == network
}

/// Skip multicast / broadcast pseudo-entries that show up in the ARP table.
fn is_pseudo(ip: Ipv4Addr, mac: &str) -> bool {
    if mac.eq_ignore_ascii_case("ff:ff:ff:ff:ff:ff") {
        return true;
    }
    if mac.starts_with("01:00:5e") {
        return true;
    }
    ip.is_multicast() || ip.is_broadcast()
}

/// Outcome of a single TCP connect probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PortProbe {
    /// Connection succeeded — the port is open.
    Open,
    /// Connection was actively refused or timed out — treat as closed/filtered.
    Closed,
    /// A local resource error (e.g. `EMFILE`, `ENOBUFS`) prevented a verdict.
    /// These are retried rather than reported as closed.
    Inconclusive,
}

async fn tcp_probe(ip: Ipv4Addr, port: u16, dur: Duration) -> PortProbe {
    match timeout(dur, TcpStream::connect((ip, port))).await {
        Ok(Ok(_)) => PortProbe::Open,
        // Inside the timeout but the connect failed. A refusal is a definitive
        // "closed"; a local resource error (out of fds/buffers) is not.
        Ok(Err(e)) => {
            if e.kind() == std::io::ErrorKind::ConnectionRefused {
                PortProbe::Closed
            } else if is_resource_error(&e) {
                PortProbe::Inconclusive
            } else {
                PortProbe::Closed
            }
        }
        // Timed out — filtered or simply not listening.
        Err(_) => PortProbe::Closed,
    }
}

/// True for transient local errors that mean "we couldn't tell", not
/// "the port is closed" — chiefly `EMFILE`/`ENFILE` (too many open files)
/// and `ENOBUFS` (out of socket buffers) under heavy concurrent load.
fn is_resource_error(e: &std::io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::EMFILE) | Some(libc::ENFILE) | Some(libc::ENOBUFS) | Some(libc::EAGAIN)
    )
}

/// Best-effort bump of the process file-descriptor soft limit so the sweep
/// doesn't starve itself. Idempotent and silent on failure.
#[cfg(unix)]
fn raise_fd_limit() {
    unsafe {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) != 0 {
            return;
        }
        let want = FD_SOFT_TARGET.min(lim.rlim_max as u64);
        if (lim.rlim_cur as u64) < want {
            lim.rlim_cur = want as libc::rlim_t;
            let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &lim);
        }
    }
}

#[cfg(not(unix))]
fn raise_fd_limit() {}

/// Sweep `cidr`, optionally source-pinned to `iface`. Returns live hosts with
/// MAC / vendor / hostname / latency / open ports.
pub async fn scan_subnet(cidr: &str, iface: Option<String>) -> Result<IpScanResult, String> {
    let started = Instant::now();
    let (network, prefix) = parse_cidr(cidr)?;
    let canonical_cidr = format!("{}/{}", Ipv4Addr::from(network), prefix);
    let hosts = host_addresses(network, prefix)?;
    let host_count = hosts.len();

    // The sweep is fd-hungry (a ping subprocess per host + hundreds of
    // concurrent sockets). Bump the soft limit so probes don't fail with
    // `EMFILE` and report open ports as closed.
    raise_fd_limit();

    // Kick off the mDNS browse concurrently with the ping sweep.
    let mdns_handle =
        tokio::task::spawn_blocking(|| mdns::browse_blocking(Duration::from_secs(3)));

    // ── 1. Ping sweep ────────────────────────────────────────────────────
    let sem = Arc::new(Semaphore::new(PING_CONCURRENCY));
    let mut ping_set: JoinSet<(Ipv4Addr, Option<f32>)> = JoinSet::new();
    for ip in hosts.iter().copied() {
        let sem = sem.clone();
        let ifc = iface.clone();
        ping_set.spawn(async move {
            let _permit = sem.acquire_owned().await.ok();
            let latency = reachability::ping_via(&ip.to_string(), 1, ifc.as_deref()).await;
            (ip, latency)
        });
    }
    let mut latency_map: HashMap<Ipv4Addr, f32> = HashMap::new();
    let mut alive: BTreeSet<Ipv4Addr> = BTreeSet::new();
    while let Some(res) = ping_set.join_next().await {
        if let Ok((ip, Some(lat))) = res {
            latency_map.insert(ip, lat);
            alive.insert(ip);
        }
    }

    // ── 2. ARP enrichment (MAC + ICMP-blocking hosts) ────────────────────
    let mut mac_map: HashMap<Ipv4Addr, String> = HashMap::new();
    let mut arp_hint: HashMap<Ipv4Addr, String> = HashMap::new();
    if let Ok(entries) = arp::read_arp_table().await {
        for e in entries {
            if let Ok(ip) = e.ip.parse::<Ipv4Addr>() {
                if in_subnet(ip, network, prefix) && !is_pseudo(ip, &e.mac) {
                    mac_map.insert(ip, e.mac.clone());
                    if let Some(h) = e.hostname_hint {
                        arp_hint.insert(ip, h);
                    }
                    alive.insert(ip);
                }
            }
        }
    }

    let mdns_map = mdns_handle.await.unwrap_or_default();

    // ── 3. Port probe live hosts ─────────────────────────────────────────
    // First pass: probe every (host, port). Ports that come back Inconclusive
    // (a transient local resource error rather than a refusal/timeout) are
    // collected and retried once with a longer timeout so a momentary fd/
    // buffer pinch doesn't make a genuinely-open port look closed.
    let psem = Arc::new(Semaphore::new(PORT_CONCURRENCY));
    let mut port_set: JoinSet<(Ipv4Addr, u16, PortProbe)> = JoinSet::new();
    for ip in alive.iter().copied() {
        for &port in COMMON_PORTS {
            let psem = psem.clone();
            port_set.spawn(async move {
                let _permit = psem.acquire_owned().await.ok();
                (ip, port, tcp_probe(ip, port, PORT_TIMEOUT).await)
            });
        }
    }
    let mut ports_map: HashMap<Ipv4Addr, Vec<u16>> = HashMap::new();
    let mut retry: Vec<(Ipv4Addr, u16)> = Vec::new();
    while let Some(res) = port_set.join_next().await {
        if let Ok((ip, port, probe)) = res {
            match probe {
                PortProbe::Open => ports_map.entry(ip).or_default().push(port),
                PortProbe::Inconclusive => retry.push((ip, port)),
                PortProbe::Closed => {}
            }
        }
    }

    if !retry.is_empty() {
        let rsem = Arc::new(Semaphore::new(PORT_CONCURRENCY / 2));
        let mut retry_set: JoinSet<(Ipv4Addr, u16, PortProbe)> = JoinSet::new();
        for (ip, port) in retry {
            let rsem = rsem.clone();
            retry_set.spawn(async move {
                let _permit = rsem.acquire_owned().await.ok();
                (ip, port, tcp_probe(ip, port, PORT_TIMEOUT_RETRY).await)
            });
        }
        while let Some(res) = retry_set.join_next().await {
            if let Ok((ip, port, PortProbe::Open)) = res {
                ports_map.entry(ip).or_default().push(port);
            }
        }
    }

    // ── 4. Assemble ──────────────────────────────────────────────────────
    let mut out: Vec<IpScanHost> = alive
        .iter()
        .map(|&ip| {
            let mac = mac_map.get(&ip).cloned();
            let vendor = mac
                .as_deref()
                .and_then(oui::vendor_for_mac)
                .map(|s| s.to_string());
            let hostname = mdns_map
                .get(&ip.to_string())
                .map(|r| r.hostname.clone())
                .or_else(|| arp_hint.get(&ip).cloned());
            let mut open_ports = ports_map.get(&ip).cloned().unwrap_or_default();
            open_ports.sort_unstable();
            IpScanHost {
                ip: ip.to_string(),
                mac,
                vendor,
                hostname,
                latency_ms: latency_map.get(&ip).copied(),
                online: true,
                open_ports,
            }
        })
        .collect();
    out.sort_by_key(|h| {
        h.ip.parse::<Ipv4Addr>()
            .map(|v| v.octets())
            .unwrap_or([0, 0, 0, 0])
    });

    Ok(IpScanResult {
        cidr: canonical_cidr,
        host_count,
        online_count: out.len(),
        duration_ms: started.elapsed().as_millis(),
        hosts: out,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cidr_and_clears_host_bits() {
        let (net, prefix) = parse_cidr("192.168.1.50/24").unwrap();
        assert_eq!(Ipv4Addr::from(net), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(prefix, 24);
    }

    #[test]
    fn bare_ip_defaults_to_24() {
        let (net, prefix) = parse_cidr("10.0.0.7").unwrap();
        assert_eq!(Ipv4Addr::from(net), Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(prefix, 24);
    }

    #[test]
    fn slash24_yields_254_hosts_excluding_net_and_broadcast() {
        let (net, prefix) = parse_cidr("192.168.1.0/24").unwrap();
        let hosts = host_addresses(net, prefix).unwrap();
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(hosts[253], Ipv4Addr::new(192, 168, 1, 254));
    }

    #[test]
    fn rejects_oversized_ranges() {
        let (net, prefix) = parse_cidr("10.0.0.0/16").unwrap();
        assert!(host_addresses(net, prefix).is_err());
    }

    #[test]
    fn in_subnet_membership() {
        let (net, prefix) = parse_cidr("192.168.1.0/24").unwrap();
        assert!(in_subnet(Ipv4Addr::new(192, 168, 1, 200), net, prefix));
        assert!(!in_subnet(Ipv4Addr::new(192, 168, 2, 1), net, prefix));
    }
}
