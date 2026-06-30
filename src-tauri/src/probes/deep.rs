//! Privileged probe dispatcher.
//!
//! The privileged half of AV diagnostics (currently: IGMP querier listen)
//! needs raw IPv4 sockets, which on macOS require root. Rather than ship
//! a separate signed helper binary, we re-exec the *current* binary with
//! `--probe <kind>` args via:
//!
//! ```text
//! osascript -e 'do shell script "/path/to/atlas --probe igmp-listen --iface en0 --secs 12" with administrator privileges'
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

#[cfg(target_os = "macos")]
use std::ffi::CString;
use std::io::ErrorKind;
#[cfg(not(target_os = "macos"))]
use std::mem::MaybeUninit;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

#[cfg(not(target_os = "macos"))]
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
        "ptp-listen" => Some(run_ptp_listen(args)),
        #[cfg(target_os = "windows")]
        "dscp-audit" => Some(run_dscp_audit(args)),
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

#[cfg(target_os = "windows")]
fn run_dscp_audit(args: &[String]) -> i32 {
    let iface = arg_value(args, "--iface").unwrap_or_default();
    let listen_secs: u32 = arg_value(args, "--secs")
        .and_then(|s| s.parse().ok())
        .unwrap_or(12)
        .clamp(1, 60);
    let result = crate::probes::dscp::run_blocking(&iface, listen_secs);
    let json = match serde_json::to_string(&result) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("serialise DscpProbeResult: {e}");
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

fn run_igmp_listen(args: &[String]) -> i32 {
    let iface = arg_value(args, "--iface").unwrap_or_else(|| "en0".to_string());
    // Upper-bound 300s so a thorough listen reliably catches an RFC-3376
    // default querier (125s General Query interval) even when the listen
    // starts just after a query — a single 125s interval leaves no margin,
    // so the default is ~2x (260s). Lower bound 1s for unit-test friendliness.
    let listen_secs: u32 = arg_value(args, "--secs")
        .and_then(|s| s.parse().ok())
        .unwrap_or(260)
        .clamp(1, 300);

    let result = match listen_for_igmp(&iface, listen_secs) {
        Ok(r) => r,
        Err(e) => IgmpProbeResult {
            iface: iface.clone(),
            listen_secs,
            queriers_seen: Vec::new(),
            reports_seen: 0,
            leaves_seen: 0,
            verdict: "error".to_string(),
            detail: None,
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

/// Run the PTP listener as the (elevated) probe binary. Binding UDP 319/320
/// for the L3 listen works unprivileged, but the L2 (ethertype 0x88F7)
/// capture inside `ptp::run_blocking` needs root to open `/dev/bpf` — so the
/// app routes this kind through the elevation helper on macOS to observe
/// PTP-over-Ethernet (SMPTE 2110 / AVB gPTP) in addition to PTP-over-UDP.
fn run_ptp_listen(args: &[String]) -> i32 {
    let iface = arg_value(args, "--iface").unwrap_or_else(|| "en0".to_string());
    // PTP Announce/Sync arrive every 1-2s, so a short window suffices.
    let listen_secs: u32 = arg_value(args, "--secs")
        .and_then(|s| s.parse().ok())
        .unwrap_or(12)
        .clamp(1, 60);

    let result = crate::probes::ptp::run_blocking(&iface, listen_secs);

    let json = match serde_json::to_string(&result) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("serialise PtpProbeResult: {e}");
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

/// Passively observe IGMP for `listen_secs` seconds and classify what we see
/// into an `IgmpProbeResult`. We **never** send any packets — listening only
/// — so we cannot win the IGMP querier election or otherwise alter the
/// network's multicast posture.
///
/// The capture mechanism is platform-specific (`capture_igmp`): BPF on macOS
/// (the kernel does not deliver inbound IGMP to raw sockets there), and a raw
/// `IPPROTO_IGMP` socket on Linux/Windows.
///
/// Errors only when capture setup fails (e.g. not root, or interface doesn't
/// exist); a successful listen with zero observed packets is a valid result
/// (`verdict = "silent"`).
fn listen_for_igmp(iface: &str, listen_secs: u32) -> anyhow::Result<IgmpProbeResult> {
    let (mut queriers, reports, leaves) = capture_igmp(iface, listen_secs)?;

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

    let detail = build_igmp_detail(iface, verdict, &queriers, listen_secs);

    Ok(IgmpProbeResult {
        iface: iface.to_string(),
        listen_secs,
        queriers_seen: queriers,
        reports_seen: reports,
        leaves_seen: leaves,
        verdict: verdict.to_string(),
        detail,
        error: None,
    })
}

/// Build a segment-aware, human-readable interpretation of the IGMP verdict
/// by correlating it with the routed/scoped multicast groups this host has
/// joined on `iface`. Link-local `224.0.0.0/24` groups are excluded because
/// they are always flooded and never depend on a querier — so seeing them
/// (Dante ConMon, mDNS) does not imply audio/PTP is being delivered.
///
/// This turns a bare `silent` / `no_querier_observed` verdict into an
/// actionable finding: a host can join Dante audio + PTP groups yet receive
/// nothing because the only querier lives on a different VLAN.
fn build_igmp_detail(
    iface: &str,
    verdict: &str,
    queriers: &[IgmpQuerier],
    listen_secs: u32,
) -> Option<String> {
    // Joined groups on this interface that REQUIRE a querier to be forwarded
    // (everything outside link-local 224.0.0.0/24).
    let scoped: Vec<(String, String)> = crate::probes::multicast::collect_blocking()
        .into_iter()
        .filter(|m| m.iface == iface)
        .flat_map(|m| m.groups)
        .filter(|g| {
            g.group
                .parse::<Ipv4Addr>()
                .map(|ip| {
                    let o = ip.octets();
                    !(o[0] == 224 && o[1] == 0 && o[2] == 0)
                })
                .unwrap_or(false)
        })
        .map(|g| (g.group, g.purpose))
        .collect();

    let audio_n = scoped
        .iter()
        .filter(|(_, p)| crate::probes::multicast::is_audio_purpose(p))
        .count();
    let sample = scoped
        .iter()
        .take(4)
        .map(|(g, p)| format!("{g} [{p}]"))
        .collect::<Vec<_>>()
        .join(", ");

    match verdict {
        "querier_present" => {
            let who = queriers
                .first()
                .map(|q| q.from.clone())
                .unwrap_or_else(|| "?".to_string());
            Some(format!(
                "IGMP querier {who} is active on {iface}; snooping switches will keep the \
                 {} joined scoped group(s) forwarded to this port.",
                scoped.len()
            ))
        }
        "no_querier_observed" | "silent" if !scoped.is_empty() => Some(format!(
            "No IGMP querier seen on {iface} during {listen_secs}s, yet this host has joined {} \
             routed/scoped multicast group(s){} ({sample}). If there is genuinely no querier on \
             THIS segment, IGMP snooping ages these out (~260s) and stops delivering them to the \
             port — AVoIP audio/PTP will drop even though the control plane (mDNS / Dante ConMon) \
             looks healthy. This is a passive listen, so confirm on the VLAN's L3 device (or the \
             switch acting as querier) before changing config; note a querier on a different \
             VLAN/group does not serve this segment.",
            scoped.len(),
            if audio_n > 0 {
                format!(" ({audio_n} carrying audio)")
            } else {
                String::new()
            }
        )),
        "no_querier_observed" => Some(format!(
            "IGMP reports/leaves were seen on {iface} but no General Query in {listen_secs}s — the \
             querier election is missing or broken on this segment. Any scoped multicast joined \
             later will be pruned by snooping."
        )),
        "silent" => Some(format!(
            "No IGMP traffic and no routed/scoped multicast joins on {iface} during {listen_secs}s. \
             If this is the AV NIC, confirm it is the correct interface and attached to the audio \
             VLAN; otherwise the segment simply has no multicast subscribers yet."
        )),
        _ => None,
    }
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

/// Tally a parsed IGMP packet into the running query/report/leave counters.
fn classify_igmp(
    pkt: &ParsedIgmp,
    queriers: &mut Vec<IgmpQuerier>,
    reports: &mut u32,
    leaves: &mut u32,
) {
    match pkt.msg_type {
        // Membership Query (v1/v2/v3) — sent by the querier.
        0x11 => queriers.push(IgmpQuerier {
            from: pkt.src.to_string(),
            version: pkt.version,
            max_resp_ds: pkt.max_resp as u32,
            group: pkt.group.to_string(),
        }),
        // Membership Reports (v1/v2/v3).
        0x12 | 0x16 | 0x22 => *reports = reports.saturating_add(1),
        // Leave Group (v2 only).
        0x17 => *leaves = leaves.saturating_add(1),
        _ => {}
    }
}

/// Linux & Windows deliver inbound IGMP to a raw `IPPROTO_IGMP` socket, so we
/// capture there with socket2. (macOS does NOT — see the BPF variant below.)
#[cfg(not(target_os = "macos"))]
fn capture_igmp(iface: &str, listen_secs: u32) -> anyhow::Result<(Vec<IgmpQuerier>, u32, u32)> {
    let socket = Socket::new(
        Domain::IPV4,
        Type::RAW,
        // IGMP IANA protocol number is 2 (RFC 3232 / IANA assignment).
        // Using a literal avoids libc::IPPROTO_IGMP, which is not defined on Windows.
        Some(Protocol::from(2)),
    )?;
    // Short per-read timeout so we can stop promptly on `listen_secs`.
    socket.set_read_timeout(Some(Duration::from_millis(500)))?;
    // Linux pins via SO_BINDTODEVICE; Windows binds the iface IPv4 and enables
    // SIO_RCVALL so the raw socket sees queries it isn't directly addressed by.
    bind_for_igmp(&socket, iface)?;

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
                    classify_igmp(&pkt, &mut queriers, &mut reports, &mut leaves);
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok((queriers, reports, leaves))
}

/// macOS does not deliver inbound IGMP to a raw `IPPROTO_IGMP` socket — the
/// kernel's `igmp_input` consumes membership queries to drive the host state
/// machine and never copies them to raw sockets (verified empirically: a raw
/// socket sees zero IGMP while BPF/tcpdump on the same NIC sees the queries).
/// So we capture at the datalink layer via BPF, exactly like tcpdump, with a
/// kernel-side "IGMP only" filter to stay off the audio-multicast hot path.
#[cfg(target_os = "macos")]
fn capture_igmp(iface: &str, listen_secs: u32) -> anyhow::Result<(Vec<IgmpQuerier>, u32, u32)> {
    use anyhow::Context;

    // BPF ioctls (<net/bpf.h>) for group 'B' (0x42), encoded via the BSD
    // _IOR/_IOW macros: inout | ((sizeof & 0x1fff) << 16) | (g << 8) | num.
    const BIOCGBLEN: libc::c_ulong = 0x4004_4266; // _IOR('B',102,u_int)
    const BIOCSETIF: libc::c_ulong = 0x8020_426c; // _IOW('B',108,struct ifreq)
    const BIOCIMMEDIATE: libc::c_ulong = 0x8004_4270; // _IOW('B',112,u_int)
    const BIOCSETF: libc::c_ulong = 0x8010_4267; // _IOW('B',103,struct bpf_program)

    let fd = open_bpf().context("open /dev/bpf")?;
    let _guard = BpfFd(fd);

    // Bind the BPF device to the requested interface. struct ifreq is 32 bytes
    // on macOS (16-byte name + 16-byte ifr_ifru union); BIOCSETIF only reads
    // the name, so a local repr(C) twin avoids depending on libc::ifreq.
    #[repr(C)]
    struct IfReq {
        ifr_name: [libc::c_char; 16],
        _ifr_ifru: [u8; 16],
    }
    let mut ifr = IfReq {
        ifr_name: [0; 16],
        _ifr_ifru: [0; 16],
    };
    let nbytes = iface.as_bytes();
    if nbytes.len() >= ifr.ifr_name.len() {
        anyhow::bail!("interface name too long: {iface}");
    }
    for (i, b) in nbytes.iter().enumerate() {
        ifr.ifr_name[i] = *b as libc::c_char;
    }
    if unsafe { libc::ioctl(fd, BIOCSETIF, &ifr) } < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("BIOCSETIF {iface}"));
    }

    // Immediate mode: hand us each packet as it arrives instead of buffering.
    let one: libc::c_uint = 1;
    if unsafe { libc::ioctl(fd, BIOCIMMEDIATE, &one) } < 0 {
        return Err(std::io::Error::last_os_error()).context("BIOCIMMEDIATE");
    }

    // Kernel-side filter: Ethernet ethertype == IPv4 && IP protocol == 2.
    install_igmp_filter(fd, BIOCSETF)?;

    // Reads must be sized to the kernel's BPF buffer.
    let mut blen: libc::c_uint = 0;
    if unsafe { libc::ioctl(fd, BIOCGBLEN, &mut blen) } < 0 {
        return Err(std::io::Error::last_os_error()).context("BIOCGBLEN");
    }
    let blen = if blen == 0 { 4096 } else { blen as usize };
    let mut buf = vec![0u8; blen];

    let deadline = Instant::now() + Duration::from_secs(listen_secs as u64);
    let mut queriers: Vec<IgmpQuerier> = Vec::new();
    let mut reports: u32 = 0;
    let mut leaves: u32 = 0;

    while Instant::now() < deadline {
        // Wait up to 500ms for readability so we periodically re-check the deadline.
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let pr = unsafe { libc::poll(&mut pfd, 1, 500) };
        if pr < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(e).context("poll(bpf)");
        }
        if pr == 0 {
            continue;
        }
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) {
                continue;
            }
            return Err(e).context("read(bpf)");
        }
        let n = n as usize;

        // Walk the BPF records packed into the buffer.
        let mut p = 0usize;
        while p + 18 <= n {
            // struct bpf_hdr: bh_tstamp(8) | bh_caplen@8 | bh_datalen@12 | bh_hdrlen@16(u16).
            let caplen = u32::from_ne_bytes(buf[p + 8..p + 12].try_into().unwrap()) as usize;
            let hdrlen = u16::from_ne_bytes(buf[p + 16..p + 18].try_into().unwrap()) as usize;
            if hdrlen == 0 {
                break;
            }
            let start = p + hdrlen;
            let end = start + caplen;
            if end > n {
                break;
            }
            if let Some(pkt) = parse_eth_ip_igmp(&buf[start..end]) {
                classify_igmp(&pkt, &mut queriers, &mut reports, &mut leaves);
            }
            // Records are padded to BPF_ALIGNMENT (sizeof(int32_t) = 4) on macOS.
            p += (hdrlen + caplen + 3) & !3;
        }
    }
    Ok((queriers, reports, leaves))
}

/// Open the first available BPF device (modern macOS clones `/dev/bpf`; older
/// systems expose numbered minors `/dev/bpf0..255`). Requires root.
#[cfg(target_os = "macos")]
fn open_bpf() -> std::io::Result<libc::c_int> {
    let mut candidates: Vec<String> = vec!["/dev/bpf".to_string()];
    for i in 0..256 {
        candidates.push(format!("/dev/bpf{i}"));
    }
    let mut last = std::io::Error::new(ErrorKind::NotFound, "no /dev/bpf device available");
    for path in candidates {
        let Ok(c) = CString::new(path) else { continue };
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDWR) };
        if fd >= 0 {
            return Ok(fd);
        }
        // EBUSY → minor in use, try the next; other errors we also skip past.
        last = std::io::Error::last_os_error();
    }
    Err(last)
}

/// Install a classic-BPF program accepting only Ethernet-framed IPv4 IGMP —
/// the same filter tcpdump compiles for `igmp` on a DLT_EN10MB link.
#[cfg(target_os = "macos")]
fn install_igmp_filter(fd: libc::c_int, biocsetf: libc::c_ulong) -> std::io::Result<()> {
    #[repr(C)]
    struct BpfInsn {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }
    #[repr(C)]
    struct BpfProgram {
        bf_len: libc::c_uint,
        bf_insns: *const BpfInsn,
    }
    //   ldh [12]               ; ethertype
    //   jeq #0x0800, +0, +3    ; IPv4? else REJECT
    //   ldb [23]               ; IPv4 protocol byte
    //   jeq #0x02,  +0, +1     ; IGMP? else REJECT
    //   ret #262144            ; ACCEPT
    //   ret #0                 ; REJECT
    let prog = [
        BpfInsn {
            code: 0x28,
            jt: 0,
            jf: 0,
            k: 12,
        },
        BpfInsn {
            code: 0x15,
            jt: 0,
            jf: 3,
            k: 0x0800,
        },
        BpfInsn {
            code: 0x30,
            jt: 0,
            jf: 0,
            k: 23,
        },
        BpfInsn {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: 2,
        },
        BpfInsn {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x0004_0000,
        },
        BpfInsn {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0,
        },
    ];
    let bp = BpfProgram {
        bf_len: prog.len() as libc::c_uint,
        bf_insns: prog.as_ptr(),
    };
    if unsafe { libc::ioctl(fd, biocsetf, &bp) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Strip the Ethernet (and optional single 802.1Q tag) header, then hand the
/// IPv4 payload to `parse_ip_igmp`.
#[cfg(target_os = "macos")]
fn parse_eth_ip_igmp(frame: &[u8]) -> Option<ParsedIgmp> {
    if frame.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let ip_off = match ethertype {
        0x0800 => 14,
        0x8100 => {
            if frame.len() < 18 || u16::from_be_bytes([frame[16], frame[17]]) != 0x0800 {
                return None;
            }
            18
        }
        _ => return None,
    };
    parse_ip_igmp(&frame[ip_off..])
}

/// RAII guard closing the BPF file descriptor.
#[cfg(target_os = "macos")]
struct BpfFd(libc::c_int);
#[cfg(target_os = "macos")]
impl Drop for BpfFd {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

/// Linux: bind to INADDR_ANY then pin via `SO_BINDTODEVICE` (requires
/// CAP_NET_RAW already since we're on a raw socket; bind-by-name needs
/// CAP_NET_RAW or CAP_NET_BIND_SERVICE).
#[cfg(target_os = "linux")]
fn bind_for_igmp(sock: &Socket, iface: &str) -> std::io::Result<()> {
    let any: std::net::SocketAddr =
        std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0));
    sock.bind(&any.into())?;
    if iface.is_empty() || iface == "0.0.0.0" || iface.eq_ignore_ascii_case("any") {
        return Ok(());
    }
    sock.bind_device(Some(iface.as_bytes()))?;
    Ok(())
}

/// Windows: raw IPv4 sockets receive only what's destined to the bound
/// IP. To see *multicast* IGMP packets that aren't directly addressed
/// to us we must (a) bind to the iface's IPv4 address (not INADDR_ANY),
/// and (b) put the socket in receive-everything mode via an IOCTL.
///
/// We try `SIO_RCVALL` first (the same IOCTL Wireshark / Microsoft
/// Network Monitor use) because `SIO_RCVALL_IGMPMCAST` is known to
/// under-deliver on Windows 10/11 — it only surfaces IGMP packets the
/// local host participates in, not external queriers. The raw socket's
/// `IPPROTO_IGMP` protocol filter still narrows what reaches user-mode
/// to IGMP, so SIO_RCVALL doesn't flood us with TCP/UDP. If SIO_RCVALL
/// is denied (e.g. unusual firewall policy) we fall back to
/// SIO_RCVALL_IGMPMCAST. Both require admin — `commands.rs` already
/// elevates via `Start-Process -Verb RunAs`.
#[cfg(target_os = "windows")]
fn bind_for_igmp(sock: &Socket, iface: &str) -> std::io::Result<()> {
    use std::os::raw::c_void;
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{WSAIoctl, SOCKET};

    // IOCTL codes from <mstcpip.h>; windows-sys doesn't expose them as
    // typed constants.
    //   #define SIO_RCVALL            _WSAIOW(IOC_VENDOR,1) = 0x98000001
    //   #define SIO_RCVALL_IGMPMCAST  _WSAIOW(IOC_VENDOR,2) = 0x98000002
    const SIO_RCVALL: u32 = 0x9800_0001;
    const SIO_RCVALL_IGMPMCAST: u32 = 0x9800_0002;

    // Resolve the iface's IPv4 via our enumeration helper. Empty/any
    // falls back to INADDR_ANY; that won't get us multicast on Windows
    // but it's still a valid (degenerate) listen — the user will see
    // "silent" rather than an error.
    let bind_v4 = if iface.is_empty() || iface == "0.0.0.0" || iface.eq_ignore_ascii_case("any") {
        std::net::Ipv4Addr::UNSPECIFIED
    } else {
        let info = crate::probes::iface::find_by_name(iface).ok_or_else(|| {
            std::io::Error::new(ErrorKind::NotFound, format!("interface {iface} not found"))
        })?;
        info.ipv4
            .as_deref()
            .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
            .ok_or_else(|| {
                std::io::Error::new(
                    ErrorKind::AddrNotAvailable,
                    format!("interface {iface} has no IPv4 address"),
                )
            })?
    };
    let bind_addr: std::net::SocketAddr = std::net::SocketAddr::from((bind_v4, 0));
    sock.bind(&bind_addr.into())?;

    if bind_v4.is_unspecified() {
        // Nothing more to do — no iface to apply RCVALL to.
        return Ok(());
    }

    let s = sock.as_raw_socket() as SOCKET;
    let on: u32 = 1;
    let mut bytes_returned: u32 = 0;

    // Attempt SIO_RCVALL first (full promisc; matches Wireshark).
    let ret = unsafe {
        WSAIoctl(
            s,
            SIO_RCVALL,
            &on as *const _ as *const c_void,
            std::mem::size_of::<u32>() as u32,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
            None,
        )
    };
    if ret == 0 {
        return Ok(());
    }
    let rcvall_err = std::io::Error::last_os_error();

    // Fallback: SIO_RCVALL_IGMPMCAST. Some hardened Windows configs
    // (Defender ATP / certain GPOs) block SIO_RCVALL but still permit
    // the narrower IGMP-only IOCTL.
    let ret = unsafe {
        WSAIoctl(
            s,
            SIO_RCVALL_IGMPMCAST,
            &on as *const _ as *const c_void,
            std::mem::size_of::<u32>() as u32,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
            None,
        )
    };
    if ret == 0 {
        return Ok(());
    }
    // Surface BOTH IOCTL failures so the user can tell whether the
    // firewall, an EDR, or a missing privilege is the cause.
    let igmpmcast_err = std::io::Error::last_os_error();
    Err(std::io::Error::other(format!(
        "SIO_RCVALL failed ({rcvall_err}); SIO_RCVALL_IGMPMCAST also failed ({igmpmcast_err}) — \
             check Windows Defender Firewall inbound rules for Atlas and ensure the helper is running elevated"
    )))
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn bind_for_igmp(sock: &Socket, _iface: &str) -> std::io::Result<()> {
    let any: std::net::SocketAddr =
        std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0));
    sock.bind(&any.into())?;
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
