//! Privileged probe dispatcher.
//!
//! The privileged half of AV diagnostics (currently: IGMP querier listen)
//! needs raw IPv4 sockets, which on macOS require root. Rather than ship
//! a separate signed helper binary, we re-exec the *current* binary with
//! `--probe <kind>` args via:
//!
//! ```text
//! osascript -e 'do shell script "/path/to/wifi-troubleshooter --probe igmp-listen --iface en0 --secs 12" with administrator privileges'
//! ```
//!
//! macOS pops its native auth prompt (cached ~5 min) and our binary runs
//! as root long enough to perform one probe + print JSON to stdout + exit.
//! The parent process parses the JSON and surfaces it in
//! `AvDiagnosticsResult.deep_probe`.
//!
//! `dispatch` is invoked from `main.rs` BEFORE the Tauri GUI initialises,
//! so the GUI code path is never taken when the binary is invoked as a
//! privileged helper.
//!
//! ## Currently shipping
//!   - `--probe igmp-listen` — passive raw-socket observer of IGMP v1/v2/v3
//!     queries, reports, and leaves on a specific interface. Never sends a
//!     packet, so cannot win the IGMP querier election or otherwise alter
//!     the network's multicast posture.
//!
//! ## Output channel
//!   - By default the JSON `IgmpProbeResult` is printed to stdout.
//!   - If `--probe-out <path>` is supplied, the JSON is written to that
//!     file instead. This is required on Windows where `Start-Process
//!     -Verb RunAs` cannot pipe stdout back to the parent process.

use std::ffi::CString;
use std::io::ErrorKind;
use std::mem::MaybeUninit;
use std::net::Ipv4Addr;
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

use crate::types::{IgmpProbeResult, IgmpQuerier};

/// If `args` contain `--probe <kind>` run the matching probe and return
/// the process exit code. Otherwise return `None` (the main binary then
/// proceeds to launch the Tauri GUI as normal).
pub fn try_dispatch(args: &[String]) -> Option<i32> {
    let probe_idx = args.iter().position(|a| a == "--probe")?;
    let kind = args.get(probe_idx + 1)?;
    match kind.as_str() {
        "igmp-listen" => Some(run_igmp_listen(args)),
        other => {
            eprintln!("unknown probe kind: {other}");
            Some(2)
        }
    }
}

fn arg_value(args: &[String], key: &str) -> Option<String> {
    let idx = args.iter().position(|a| a == key)?;
    args.get(idx + 1).cloned()
}

fn run_igmp_listen(args: &[String]) -> i32 {
    let iface = arg_value(args, "--iface").unwrap_or_else(|| "en0".to_string());
    let listen_secs: u32 = arg_value(args, "--secs")
        .and_then(|s| s.parse().ok())
        .unwrap_or(12)
        .clamp(1, 60);

    let result = match listen_for_igmp(&iface, listen_secs) {
        Ok(r) => r,
        Err(e) => IgmpProbeResult {
            iface: iface.clone(),
            listen_secs,
            queriers_seen: Vec::new(),
            reports_seen: 0,
            leaves_seen: 0,
            verdict: "error".to_string(),
            error: Some(e.to_string()),
        },
    };

    let json = match serde_json::to_string(&result) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("serialise IgmpProbeResult: {e}");
            return 1;
        }
    };
    if let Some(path) = arg_value(args, "--probe-out") {
        if let Err(e) = std::fs::write(&path, &json) {
            eprintln!("write probe output to {path}: {e}");
            return 1;
        }
    } else {
        println!("{json}");
    }
    0
}

/// Open a raw IPv4 socket bound to the specified interface and passively
/// observe IGMP packets for `listen_secs` seconds. We **never** send any
/// packets — listening only — so we cannot win the IGMP querier election
/// or otherwise alter the network's multicast posture.
///
/// Returns a populated `IgmpProbeResult`. Errors only when socket setup
/// fails (e.g. not root, or interface doesn't exist); a successful
/// listen with zero observed packets is a valid result (`verdict =
/// "silent"`).
fn listen_for_igmp(iface: &str, listen_secs: u32) -> anyhow::Result<IgmpProbeResult> {
    let socket = Socket::new(
        Domain::IPV4,
        Type::RAW,
        Some(Protocol::from(libc::IPPROTO_IGMP)),
    )?;
    // Short per-read timeout so we can stop promptly on `listen_secs`.
    socket.set_read_timeout(Some(Duration::from_millis(500)))?;
    // Windows raw sockets must be bound to a local address before they
    // can receive; on macOS this is harmless. INADDR_ANY is fine for
    // listen-only — we never send.
    let bind_addr: std::net::SocketAddr =
        std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0));
    socket.bind(&bind_addr.into())?;
    bind_to_interface(&socket, iface)?;

    let deadline = Instant::now() + Duration::from_secs(listen_secs as u64);
    let mut queriers: Vec<IgmpQuerier> = Vec::new();
    let mut reports: u32 = 0;
    let mut leaves: u32 = 0;
    let mut buf = [MaybeUninit::<u8>::uninit(); 2048];

    while Instant::now() < deadline {
        match socket.recv(&mut buf) {
            Ok(n) => {
                // SAFETY: socket2 guarantees the first `n` bytes are initialised on
                // a successful `recv`.
                let data: &[u8] =
                    unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
                if let Some(pkt) = parse_ip_igmp(data) {
                    match pkt.msg_type {
                        // Membership Query (v1/v2/v3) — sent by the querier.
                        0x11 => queriers.push(IgmpQuerier {
                            from: pkt.src.to_string(),
                            version: pkt.version,
                            max_resp_ds: pkt.max_resp as u32,
                            group: pkt.group.to_string(),
                        }),
                        // Membership Reports (v1/v2/v3).
                        0x12 | 0x16 | 0x22 => reports = reports.saturating_add(1),
                        // Leave Group (v2 only).
                        0x17 => leaves = leaves.saturating_add(1),
                        _ => {}
                    }
                }
            }
            Err(e)
                if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }

    // Dedup: a healthy querier emits ~1 General Query / 125 s, so we
    // usually see at most one entry per (src, group). Defensive against
    // bursty multi-router test environments and against the same querier
    // re-sending during the listen window.
    queriers.sort_by(|a, b| a.from.cmp(&b.from).then(a.group.cmp(&b.group)));
    queriers.dedup_by(|a, b| a.from == b.from && a.group == b.group);

    let verdict = if !queriers.is_empty() {
        "querier_present"
    } else if reports > 0 || leaves > 0 {
        // Reports/leaves observed without a querier → IGMP snooping
        // without a querier, or the querier election is broken. In both
        // cases AVoIP traffic will stall as soon as the snooping timer
        // ages out the multicast groups (~5 min on most switches).
        "no_querier_observed"
    } else {
        "silent"
    };

    Ok(IgmpProbeResult {
        iface: iface.to_string(),
        listen_secs,
        queriers_seen: queriers,
        reports_seen: reports,
        leaves_seen: leaves,
        verdict: verdict.to_string(),
        error: None,
    })
}

/// Parsed IPv4 + IGMP packet view.
struct ParsedIgmp {
    src: Ipv4Addr,
    msg_type: u8,
    version: u8,
    max_resp: u8,
    group: Ipv4Addr,
}

/// macOS raw IPv4 sockets deliver packets with the IP header still
/// attached; we have to strip it ourselves. (Linux differs but we only
/// ship this code path on macOS via the `--probe` arg.)
fn parse_ip_igmp(data: &[u8]) -> Option<ParsedIgmp> {
    if data.len() < 20 {
        return None;
    }
    let ihl_bytes = ((data[0] & 0x0f) as usize) * 4;
    if ihl_bytes < 20 || data.len() < ihl_bytes + 8 {
        return None;
    }
    let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let igmp = &data[ihl_bytes..];
    let msg_type = igmp[0];
    let max_resp = igmp[1];
    // Version heuristic per RFC 3376 §7.1:
    //   Query: type 0x11
    //     len >= 12          → v3 (S/QRV/QQIC fields trailing)
    //     len == 8, MRT == 0 → v1
    //     len == 8, MRT != 0 → v2
    //   Reports: type 0x12 = v1, 0x16 = v2, 0x22 = v3
    //   Leave:   type 0x17 = v2
    let version = match msg_type {
        0x11 if igmp.len() >= 12 => 3,
        0x11 if max_resp == 0 => 1,
        0x11 => 2,
        0x12 => 1,
        0x16 | 0x17 => 2,
        0x22 => 3,
        _ => 0,
    };
    let group = Ipv4Addr::new(igmp[4], igmp[5], igmp[6], igmp[7]);
    Some(ParsedIgmp {
        src,
        msg_type,
        version,
        max_resp,
        group,
    })
}

/// macOS `IP_BOUND_IF`. Restricts the socket to a single interface so a
/// multihomed Mac (e.g. en0 Wi-Fi + en4 USB-Ethernet to a Dante VLAN)
/// can pick which network to probe.
#[cfg(target_os = "macos")]
fn bind_to_interface(sock: &Socket, iface: &str) -> std::io::Result<()> {
    const IP_BOUND_IF: libc::c_int = 25;
    // "0.0.0.0" / "any" / empty → don't pin to a specific interface; let
    // the kernel deliver IGMP from whichever interface receives it.
    if iface.is_empty() || iface == "0.0.0.0" || iface.eq_ignore_ascii_case("any") {
        return Ok(());
    }
    let cname = CString::new(iface)
        .map_err(|_| std::io::Error::new(ErrorKind::InvalidInput, "iface contains NUL"))?;
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        return Err(std::io::Error::new(
            ErrorKind::NotFound,
            format!("interface {iface} not found"),
        ));
    }
    let ret = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_IP,
            IP_BOUND_IF,
            &idx as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn bind_to_interface(_sock: &Socket, _iface: &str) -> std::io::Result<()> {
    // Windows: per-interface raw-socket binding uses `bind()` against a
    // local interface IP (not a setsockopt). For v1 we accept any
    // interface and let the kernel pick \u2014 most consumer/SMB Windows
    // boxes have only one routable interface anyway. Multihomed support
    // is a follow-up.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip_header(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        // Minimal IHL=5 IPv4 header. Fields we don't read are zero.
        let mut h = vec![0u8; 20];
        h[0] = 0x45; // version=4, IHL=5
        h[12..16].copy_from_slice(&src);
        h[16..20].copy_from_slice(&dst);
        h
    }

    #[test]
    fn parses_v2_general_query() {
        // Type=0x11, MRT=100 (10s), checksum=0, group=0.0.0.0 (general query)
        let mut pkt = ip_header([192, 168, 1, 1], [224, 0, 0, 1]);
        pkt.extend_from_slice(&[0x11, 100, 0, 0, 0, 0, 0, 0]);
        let parsed = parse_ip_igmp(&pkt).expect("parse");
        assert_eq!(parsed.src, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(parsed.msg_type, 0x11);
        assert_eq!(parsed.version, 2);
        assert_eq!(parsed.max_resp, 100);
        assert_eq!(parsed.group, Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn parses_v3_query() {
        let mut pkt = ip_header([10, 0, 0, 1], [224, 0, 0, 1]);
        // 12-byte v3 query: type, MRT, checksum, group, Resv/S/QRV, QQIC, n_srcs
        pkt.extend_from_slice(&[0x11, 50, 0, 0, 0, 0, 0, 0, 0x02, 125, 0, 0]);
        let parsed = parse_ip_igmp(&pkt).expect("parse");
        assert_eq!(parsed.version, 3);
    }

    #[test]
    fn parses_v2_report_and_leave() {
        let mut report = ip_header([192, 168, 1, 50], [239, 69, 1, 1]);
        report.extend_from_slice(&[0x16, 0, 0, 0, 239, 69, 1, 1]);
        let p = parse_ip_igmp(&report).expect("report");
        assert_eq!(p.msg_type, 0x16);
        assert_eq!(p.version, 2);
        assert_eq!(p.group, Ipv4Addr::new(239, 69, 1, 1));

        let mut leave = ip_header([192, 168, 1, 50], [224, 0, 0, 2]);
        leave.extend_from_slice(&[0x17, 0, 0, 0, 239, 69, 1, 1]);
        let p = parse_ip_igmp(&leave).expect("leave");
        assert_eq!(p.msg_type, 0x17);
    }

    #[test]
    fn rejects_truncated_packets() {
        assert!(parse_ip_igmp(&[]).is_none());
        assert!(parse_ip_igmp(&[0x45, 0, 0, 0]).is_none());
        // Valid IP header but no IGMP payload bytes
        let pkt = ip_header([1, 2, 3, 4], [224, 0, 0, 1]);
        assert!(parse_ip_igmp(&pkt).is_none());
    }
}
