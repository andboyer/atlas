//! PTP active sampler.
//!
//! Joins the PTPv1 (`224.0.1.129`) and PTPv2 (`224.0.1.129` event +
//! `224.0.1.130` general) multicast groups on UDP 319 / 320, plus the
//! peer-to-peer Pdelay group `224.0.0.107`, and parses Announce + Sync
//! headers per IEEE 1588-2008 §13. Reports per-domain:
//!   * grandmaster identity, priority1/2, clockClass, clockAccuracy
//!   * PTPv1 vs PTPv2 (Dante defaults to v1; AES67 requires v2)
//!   * sync arrival jitter (the single best "is PTP healthy" signal)
//!   * count of distinct grandmasters seen (>1 = election storm)
//!
//! Unprivileged on every platform — UDP multicast joins require no root.
//! Cross-platform interface pinning uses the existing
//! [`probes::iface::find_by_name`] helper to resolve the iface IPv4
//! (macOS/Linux) or kernel index (Windows) and then sets
//! `IP_MULTICAST_IF` so the joins land on the correct NIC.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
use std::ffi::CString;
#[cfg(target_os = "macos")]
use std::io::ErrorKind;

use socket2::{Domain, Protocol, Socket, Type};

use crate::probes::iface as iface_probe;
use crate::types::{PtpDomain, PtpGrandmaster, PtpProbeResult};

/// IANA PTP event channel — Sync, Delay_Req, Pdelay_Req, Pdelay_Resp.
const PTP_PORT_EVENT: u16 = 319;
/// IANA PTP general channel — Announce, Follow_Up, Delay_Resp,
/// Pdelay_Resp_Follow_Up, management, signaling.
const PTP_PORT_GENERAL: u16 = 320;

/// PTP end-to-end multicast groups (both v1 and v2 use 224.0.1.129;
/// v2 also uses 224.0.1.130-132 for other purposes).
const PTP_GROUPS_E2E: &[Ipv4Addr] = &[
    Ipv4Addr::new(224, 0, 1, 129),
    Ipv4Addr::new(224, 0, 1, 130),
    Ipv4Addr::new(224, 0, 1, 131),
    Ipv4Addr::new(224, 0, 1, 132),
];

/// PTPv2 peer-delay multicast group (used in P2P delay mechanism).
const PTP_GROUP_P2P: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 107);

/// Synchronous blocking entrypoint — call from `tokio::task::spawn_blocking`.
pub fn run_blocking(iface: &str, listen_secs: u32) -> PtpProbeResult {
    match listen_for_ptp(iface, listen_secs) {
        Ok(r) => r,
        Err(e) => PtpProbeResult {
            iface: iface.to_string(),
            listen_secs,
            domains: Vec::new(),
            grandmaster_count: 0,
            competing_gm_observed: false,
            verdict: "error".to_string(),
            error: Some(e.to_string()),
        },
    }
}

fn listen_for_ptp(iface: &str, listen_secs: u32) -> anyhow::Result<PtpProbeResult> {
    let iface_v4 = resolve_iface_v4(iface);

    let event = open_udp_socket(PTP_PORT_EVENT, iface_v4)?;
    let general = open_udp_socket(PTP_PORT_GENERAL, iface_v4)?;

    // Join PTP groups on both channels. We deliberately use IPv4 (not v6
    // / l2) — IPv4 multicast is the universal Dante/AES67 PTP transport.
    for grp in PTP_GROUPS_E2E.iter().chain(std::iter::once(&PTP_GROUP_P2P)) {
        let _ = event.join_multicast_v4(grp, &iface_v4);
        let _ = general.join_multicast_v4(grp, &iface_v4);
    }

    // Concurrently capture L2 PTP (IEEE-1588 over Ethernet, ethertype
    // 0x88F7 — used by SMPTE 2110 / AVB gPTP) via BPF on macOS. The UDP
    // sockets above only see PTP-over-UDP, so without this an L2-only
    // grandmaster would be invisible. Best-effort: opening /dev/bpf needs
    // root, so an unprivileged probe simply yields no L2 records and falls
    // back to the L3 path alone.
    #[cfg(target_os = "macos")]
    let l2_handle = {
        let iface = iface.to_string();
        std::thread::spawn(move || capture_l2_ptp(&iface, listen_secs))
    };

    // Per-channel-per-(domain,version) accumulator.
    let mut by_key: BTreeMap<(u8, u8), DomainAcc> = BTreeMap::new();

    let deadline = Instant::now() + Duration::from_secs(listen_secs as u64);
    let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 2048];

    while Instant::now() < deadline {
        for (sock, is_event) in [(&event, true), (&general, false)] {
            let _ = sock.set_read_timeout(Some(Duration::from_millis(250)));
            match sock.recv_from(&mut buf) {
                Ok((n, from)) => {
                    let data: &[u8] =
                        unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
                    if let Some(msg) = parse_ptp(data) {
                        let src_ip = match from.as_socket_ipv4() {
                            Some(addr) => addr.ip().to_string(),
                            None => "?".to_string(),
                        };
                        record_ptp(&mut by_key, &msg, is_event, src_ip, Instant::now());
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    continue;
                }
                Err(_) => continue,
            }
        }
    }

    // Fold in any L2 PTP messages the BPF thread captured (macOS).
    #[cfg(target_os = "macos")]
    if let Ok(records) = l2_handle.join() {
        for rec in records {
            record_ptp(&mut by_key, &rec.msg, rec.is_event, rec.src, rec.at);
        }
    }

    // Build domains.
    let mut domains: Vec<PtpDomain> = Vec::new();
    let mut total_gm = 0u32;
    let mut competing = false;
    for (_, acc) in by_key {
        let gm_count = acc.grandmasters.len();
        if gm_count > 1 {
            competing = true;
        }
        total_gm += gm_count as u32;

        let jitter_us = sync_jitter_us(&acc.sync_arrivals);
        let grandmasters: Vec<PtpGrandmaster> = acc
            .grandmasters
            .into_values()
            .map(|g| PtpGrandmaster {
                clock_identity: format_clock_id(g.clock_identity),
                priority1: g.priority1,
                priority2: g.priority2,
                clock_class: g.clock_class,
                clock_accuracy: g.clock_accuracy,
                announces_seen: g.announces_seen,
                source_ip: g.source_ip,
            })
            .collect();

        let profile = classify_profile(acc.version, acc.log_announce, acc.log_sync);
        // PTPv2 over UDP always presents as `ipv4_multicast` in this probe;
        // distinguishing P2P vs E2E delay mechanism is captured separately.
        let transport = "ipv4_multicast";

        domains.push(PtpDomain {
            domain_number: acc.domain,
            version: acc.version,
            profile,
            grandmasters,
            announce_interval_log2: acc.log_announce,
            sync_interval_log2: acc.log_sync,
            sync_arrivals: acc.sync_arrivals.len() as u32,
            sync_jitter_us: jitter_us,
            transport: transport.to_string(),
        });
    }

    let verdict = if domains.is_empty() {
        "no_ptp".to_string()
    } else if competing {
        "multiple_gms".to_string()
    } else if domains
        .iter()
        .any(|d| d.sync_jitter_us.is_some_and(|j| j > 1000.0))
    {
        "jittery_sync".to_string()
    } else if total_gm > 0 {
        "stable_gm".to_string()
    } else {
        // PTP packets seen but no Announce — switch is forwarding Sync
        // without Announce or we missed the slow channel. Treat as silent.
        "silent".to_string()
    };

    Ok(PtpProbeResult {
        iface: iface.to_string(),
        listen_secs,
        domains,
        grandmaster_count: total_gm,
        competing_gm_observed: competing,
        verdict,
        error: None,
    })
}

/// Resolve the interface's IPv4 address; falls back to 0.0.0.0 when
/// the iface is unknown so the join uses the kernel's default route.
fn resolve_iface_v4(iface: &str) -> Ipv4Addr {
    if iface.is_empty() || iface.eq_ignore_ascii_case("auto") || iface == "0.0.0.0" {
        return Ipv4Addr::UNSPECIFIED;
    }
    iface_probe::find_by_name(iface)
        .and_then(|i| i.ipv4)
        .and_then(|s| s.parse::<Ipv4Addr>().ok())
        .unwrap_or(Ipv4Addr::UNSPECIFIED)
}

fn open_udp_socket(port: u16, iface_v4: Ipv4Addr) -> std::io::Result<Socket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    {
        sock.set_reuse_port(true)?;
    }
    let bind: SocketAddr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into();
    sock.bind(&bind.into())?;
    sock.set_multicast_loop_v4(false)?;
    if !iface_v4.is_unspecified() {
        sock.set_multicast_if_v4(&iface_v4)?;
    }
    Ok(sock)
}

/// Fold a parsed PTP message into the per-(domain,version) accumulator.
/// Shared by the L3 UDP listener and the macOS L2 (ethertype 0x88F7) BPF
/// capture so both transports populate the same domains / grandmasters.
fn record_ptp(
    by_key: &mut BTreeMap<(u8, u8), DomainAcc>,
    msg: &ParsedPtp,
    is_event: bool,
    src_ip: String,
    now: Instant,
) {
    let key = (msg.domain, msg.version);
    let entry = by_key.entry(key).or_insert_with(|| DomainAcc {
        domain: msg.domain,
        version: msg.version,
        log_announce: 1,
        log_sync: 0,
        sync_arrivals: Vec::new(),
        grandmasters: BTreeMap::new(),
        saw_p2p: false,
        saw_e2e: false,
    });
    match msg.kind {
        PtpKind::Sync if is_event => {
            entry.sync_arrivals.push(now);
            entry.log_sync = msg.log_message_interval;
            if msg.dst_is_p2p {
                entry.saw_p2p = true;
            } else {
                entry.saw_e2e = true;
            }
        }
        PtpKind::Announce { gm } => {
            entry.log_announce = msg.log_message_interval;
            let id = entry
                .grandmasters
                .entry(gm.clock_identity)
                .or_insert_with(|| GmAcc {
                    clock_identity: gm.clock_identity,
                    priority1: gm.priority1,
                    priority2: gm.priority2,
                    clock_class: gm.clock_class,
                    clock_accuracy: gm.clock_accuracy,
                    announces_seen: 0,
                    source_ip: src_ip.clone(),
                });
            id.announces_seen = id.announces_seen.saturating_add(1);
            // Keep priority/class fresh in case of churn.
            id.priority1 = gm.priority1;
            id.priority2 = gm.priority2;
            id.clock_class = gm.clock_class;
            id.clock_accuracy = gm.clock_accuracy;
        }
        _ => {}
    }
}

/// Stddev of consecutive Sync inter-arrival gaps, in microseconds.
fn sync_jitter_us(arrivals: &[Instant]) -> Option<f32> {
    if arrivals.len() < 3 {
        return None;
    }
    let gaps_us: Vec<f64> = arrivals
        .windows(2)
        .map(|w| w[1].duration_since(w[0]).as_micros() as f64)
        .collect();
    let n = gaps_us.len() as f64;
    let mean = gaps_us.iter().sum::<f64>() / n;
    let var = gaps_us.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    Some(var.sqrt() as f32)
}

fn classify_profile(version: u8, log_announce: i8, log_sync: i8) -> String {
    // SMPTE 2059-2 / AES67 media profile: fast Sync (log -3 = 125ms,
    // log -4 = 62.5ms) and fast Announce (log -2 = 250ms, log -1 = 500ms).
    if version == 2 && log_sync <= -2 && log_announce <= 0 {
        "media".to_string()
    } else if version == 1 || version == 2 {
        "default".to_string()
    } else {
        "unknown".to_string()
    }
}

fn format_clock_id(id: [u8; 8]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        id[0], id[1], id[2], id[3], id[4], id[5], id[6], id[7]
    )
}

// ─── PTP parsing ─────────────────────────────────────────────────────

/// Per-(domain, version) accumulator used during listen.
struct DomainAcc {
    domain: u8,
    version: u8,
    log_announce: i8,
    log_sync: i8,
    sync_arrivals: Vec<Instant>,
    grandmasters: BTreeMap<[u8; 8], GmAcc>,
    saw_p2p: bool,
    saw_e2e: bool,
}

/// Per-grandmaster accumulator (keyed by clockIdentity).
struct GmAcc {
    clock_identity: [u8; 8],
    priority1: u8,
    priority2: u8,
    clock_class: u8,
    clock_accuracy: u8,
    announces_seen: u32,
    source_ip: String,
}

#[derive(Debug, Clone, Copy)]
struct GmFields {
    clock_identity: [u8; 8],
    priority1: u8,
    priority2: u8,
    clock_class: u8,
    clock_accuracy: u8,
}

#[derive(Debug, Clone, Copy)]
enum PtpKind {
    Sync,
    Announce { gm: GmFields },
    Other,
}

#[derive(Debug, Clone, Copy)]
struct ParsedPtp {
    version: u8,
    domain: u8,
    log_message_interval: i8,
    kind: PtpKind,
    /// True if the packet was destined for the PTP peer-to-peer group
    /// (only meaningful for Sync messages).
    dst_is_p2p: bool,
}

/// Parse a PTPv1 or PTPv2 header off a UDP payload. Returns None for
/// malformed / unrelated packets.
fn parse_ptp(data: &[u8]) -> Option<ParsedPtp> {
    if data.len() < 34 {
        return None;
    }
    // PTP version is in the low 4 bits of byte 1 (per IEEE 1588-2008
    // §13.3.2.2). v1 and v2 share this header layout.
    let version = data[1] & 0x0f;
    if version != 1 && version != 2 {
        return None;
    }

    let message_type = data[0] & 0x0f;
    let domain = data[4];
    let log_message_interval = data[33] as i8;

    let kind = match message_type {
        // Sync
        0x00 => PtpKind::Sync,
        // Announce — grandmaster fields start at offset 47 for v2.
        // Layout per IEEE 1588-2008 §13.5:
        //   off 47: grandmaster priority1 (u8)
        //   off 48: grandmaster clock quality {clockClass u8,
        //           clockAccuracy u8, offsetScaledLogVariance u16}
        //   off 52: grandmaster priority2 (u8)
        //   off 53: grandmaster identity (u64 = 8 bytes)
        //   off 61: stepsRemoved u16
        //   off 63: timeSource u8
        0x0b if data.len() >= 64 && version == 2 => {
            let mut clock_identity = [0u8; 8];
            clock_identity.copy_from_slice(&data[53..61]);
            PtpKind::Announce {
                gm: GmFields {
                    clock_identity,
                    priority1: data[47],
                    priority2: data[52],
                    clock_class: data[48],
                    clock_accuracy: data[49],
                },
            }
        }
        // PTPv1 Sync/Delay_Req carries grandmaster fields differently
        // (offsets defined in §A.7.4 of IEEE 1588-2002); for v1 we only
        // record domain + version and rely on the Sync arrival jitter.
        _ => PtpKind::Other,
    };

    Some(ParsedPtp {
        version,
        domain,
        log_message_interval,
        kind,
        dst_is_p2p: false,
    })
}

// ─── macOS L2 PTP (ethertype 0x88F7) capture via BPF ─────────────────────
//
// PTP can run directly over Ethernet (IEEE 1588 Annex F / IEEE 802.1AS
// gPTP) instead of UDP/IPv4 — common on SMPTE 2110 / AVB media networks.
// The UDP sockets in `listen_for_ptp` can't see those frames, so on macOS
// we also capture at the datalink layer with a kernel-side "ethertype ==
// 0x88F7" BPF filter (exactly what tcpdump compiles for `ether proto
// 0x88f7`). Requires root to open /dev/bpf; unprivileged callers get no
// L2 records and rely on the L3 path alone.

#[cfg(target_os = "macos")]
struct L2Record {
    msg: ParsedPtp,
    at: Instant,
    src: String,
    is_event: bool,
}

#[cfg(target_os = "macos")]
fn capture_l2_ptp(iface: &str, listen_secs: u32) -> Vec<L2Record> {
    // Best-effort: /dev/bpf is root-only on stock macOS, so an unprivileged
    // probe yields no L2 records (the L3 UDP path still runs).
    capture_l2_ptp_inner(iface, listen_secs).unwrap_or_default()
}

#[cfg(target_os = "macos")]
fn capture_l2_ptp_inner(iface: &str, listen_secs: u32) -> anyhow::Result<Vec<L2Record>> {
    use anyhow::Context;

    // BPF ioctls (<net/bpf.h>), group 'B' (0x42), BSD _IOR/_IOW encoding:
    // inout | ((sizeof & 0x1fff) << 16) | (g << 8) | num.
    const BIOCGBLEN: libc::c_ulong = 0x4004_4266; // _IOR('B',102,u_int)
    const BIOCSETIF: libc::c_ulong = 0x8020_426c; // _IOW('B',108,struct ifreq)
    const BIOCIMMEDIATE: libc::c_ulong = 0x8004_4270; // _IOW('B',112,u_int)
    const BIOCSETF: libc::c_ulong = 0x8010_4267; // _IOW('B',103,struct bpf_program)

    let fd = open_bpf().context("open /dev/bpf")?;
    let _guard = BpfFd(fd);

    // struct ifreq is 32 bytes on macOS (16-byte name + 16-byte ifr_ifru
    // union); BIOCSETIF only reads the name.
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
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("BIOCSETIF {iface}"));
    }

    // Immediate mode: hand us each frame as it arrives instead of buffering.
    let one: libc::c_uint = 1;
    if unsafe { libc::ioctl(fd, BIOCIMMEDIATE, &one) } < 0 {
        return Err(std::io::Error::last_os_error()).context("BIOCIMMEDIATE");
    }

    install_ptp_l2_filter(fd, BIOCSETF)?;

    let mut blen: libc::c_uint = 0;
    if unsafe { libc::ioctl(fd, BIOCGBLEN, &mut blen) } < 0 {
        return Err(std::io::Error::last_os_error()).context("BIOCGBLEN");
    }
    let blen = if blen == 0 { 4096 } else { blen as usize };
    let mut buf = vec![0u8; blen];

    let deadline = Instant::now() + Duration::from_secs(listen_secs as u64);
    let mut records: Vec<L2Record> = Vec::new();

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
            if let Some((msg, src)) = parse_l2_ptp(&buf[start..end]) {
                let is_event = matches!(msg.kind, PtpKind::Sync);
                records.push(L2Record {
                    msg,
                    at: Instant::now(),
                    src,
                    is_event,
                });
            }
            // Records are padded to BPF_ALIGNMENT (sizeof(int32_t) = 4) on macOS.
            p += (hdrlen + caplen + 3) & !3;
        }
    }
    Ok(records)
}

/// Open the first available BPF device. Requires root on stock macOS, so
/// `EACCES` short-circuits (trying further minors is pointless).
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
        let err = std::io::Error::last_os_error();
        if err.kind() == ErrorKind::PermissionDenied {
            return Err(err);
        }
        // EBUSY → minor in use, try the next.
        last = err;
    }
    Err(last)
}

/// Install a classic-BPF program accepting only Ethernet-framed PTP
/// (ethertype 0x88F7), including a single 802.1Q VLAN tag.
#[cfg(target_os = "macos")]
fn install_ptp_l2_filter(fd: libc::c_int, biocsetf: libc::c_ulong) -> std::io::Result<()> {
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
    //   ldh [12]                 ; ethertype
    //   jeq #0x88f7, ACCEPT, +0  ; PTP-over-Ethernet (untagged)?
    //   jeq #0x8100, +0, REJECT  ; 802.1Q VLAN tag?
    //   ldh [16]                 ; inner ethertype
    //   jeq #0x88f7, ACCEPT, +0  ; PTP (tagged)?
    //   ret #0                   ; REJECT
    //   ret #262144              ; ACCEPT
    let prog = [
        BpfInsn { code: 0x28, jt: 0, jf: 0, k: 12 },
        BpfInsn { code: 0x15, jt: 4, jf: 0, k: 0x88f7 },
        BpfInsn { code: 0x15, jt: 0, jf: 2, k: 0x8100 },
        BpfInsn { code: 0x28, jt: 0, jf: 0, k: 16 },
        BpfInsn { code: 0x15, jt: 1, jf: 0, k: 0x88f7 },
        BpfInsn { code: 0x06, jt: 0, jf: 0, k: 0 },
        BpfInsn { code: 0x06, jt: 0, jf: 0, k: 0x0004_0000 },
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

/// Strip the Ethernet (and optional single 802.1Q tag) header and parse
/// the PTP header that follows. Returns the parsed message plus the
/// sender's MAC formatted as the source identity.
#[cfg(target_os = "macos")]
fn parse_l2_ptp(frame: &[u8]) -> Option<(ParsedPtp, String)> {
    if frame.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let ptp_off = match ethertype {
        0x88f7 => 14,
        0x8100 => {
            if frame.len() < 18 || u16::from_be_bytes([frame[16], frame[17]]) != 0x88f7 {
                return None;
            }
            18
        }
        _ => return None,
    };
    let msg = parse_ptp(frame.get(ptp_off..)?)?;
    let src = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        frame[6], frame[7], frame[8], frame[9], frame[10], frame[11]
    );
    Some((msg, src))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_announce(domain: u8) -> Vec<u8> {
        // Build a 64-byte v2 Announce with known grandmaster fields.
        let mut pkt = vec![0u8; 64];
        pkt[0] = 0x0b; // message type Announce
        pkt[1] = 0x02; // version 2
        pkt[4] = domain;
        pkt[33] = 1; // log_message_interval = 1 (Announce every 2s)
        pkt[47] = 128; // priority1
        pkt[48] = 6; // clockClass = locked PRC
        pkt[49] = 0x21; // clockAccuracy
        pkt[52] = 128; // priority2
        pkt[53..61].copy_from_slice(&[0x00, 0x1d, 0xc1, 0xff, 0xfe, 0x08, 0x00, 0x42]);
        pkt
    }

    fn make_sync(domain: u8) -> Vec<u8> {
        let mut pkt = vec![0u8; 44];
        pkt[0] = 0x00;
        pkt[1] = 0x02;
        pkt[4] = domain;
        pkt[33] = 0;
        pkt
    }

    #[test]
    fn parses_announce_v2() {
        let pkt = make_announce(0);
        let parsed = parse_ptp(&pkt).expect("parse");
        assert_eq!(parsed.version, 2);
        assert_eq!(parsed.domain, 0);
        match parsed.kind {
            PtpKind::Announce { gm } => {
                assert_eq!(gm.priority1, 128);
                assert_eq!(gm.clock_class, 6);
                assert_eq!(
                    gm.clock_identity,
                    [0x00, 0x1d, 0xc1, 0xff, 0xfe, 0x08, 0x00, 0x42]
                );
            }
            _ => panic!("expected Announce"),
        }
    }

    #[test]
    fn parses_sync_v2() {
        let pkt = make_sync(1);
        let parsed = parse_ptp(&pkt).expect("parse");
        assert!(matches!(parsed.kind, PtpKind::Sync));
        assert_eq!(parsed.domain, 1);
    }

    #[test]
    fn rejects_short() {
        assert!(parse_ptp(&[]).is_none());
        assert!(parse_ptp(&[0u8; 20]).is_none());
    }

    #[test]
    fn jitter_returns_none_below_three_samples() {
        let now = Instant::now();
        assert!(sync_jitter_us(&[]).is_none());
        assert!(sync_jitter_us(&[now]).is_none());
        assert!(sync_jitter_us(&[now, now]).is_none());
    }

    #[test]
    fn classify_profile_media() {
        // PTPv2 with Sync every 125ms (log -3) is the AES67 media profile.
        assert_eq!(classify_profile(2, 0, -3), "media");
        assert_eq!(classify_profile(2, 1, 0), "default");
        assert_eq!(classify_profile(1, 1, 0), "default");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parses_l2_announce_untagged() {
        // Ethernet header (14 bytes) + ethertype 0x88F7 + Announce payload.
        let mut frame = vec![0u8; 14];
        frame[6..12].copy_from_slice(&[0x00, 0x1d, 0xc1, 0x11, 0x22, 0x33]);
        frame[12] = 0x88;
        frame[13] = 0xf7;
        frame.extend_from_slice(&make_announce(4));
        let (msg, src) = parse_l2_ptp(&frame).expect("parse l2 announce");
        assert_eq!(msg.domain, 4);
        assert!(matches!(msg.kind, PtpKind::Announce { .. }));
        assert_eq!(src, "00:1d:c1:11:22:33");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parses_l2_sync_vlan_tagged() {
        // Ethernet header + 802.1Q tag (0x8100 + TCI) + inner 0x88F7 + Sync.
        let mut frame = vec![0u8; 12];
        frame[6..12].copy_from_slice(&[0x00, 0x1d, 0xc1, 0x44, 0x55, 0x66]);
        frame.extend_from_slice(&[0x81, 0x00, 0x00, 0x05]); // 802.1Q, VLAN 5
        frame.extend_from_slice(&[0x88, 0xf7]); // inner ethertype = PTP
        frame.extend_from_slice(&make_sync(2));
        let (msg, src) = parse_l2_ptp(&frame).expect("parse l2 vlan sync");
        assert_eq!(msg.domain, 2);
        assert!(matches!(msg.kind, PtpKind::Sync));
        assert_eq!(src, "00:1d:c1:44:55:66");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn rejects_non_ptp_l2() {
        // IPv4 ethertype 0x0800 is not PTP and must be ignored.
        let mut frame = vec![0u8; 14];
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame.extend_from_slice(&[0u8; 64]);
        assert!(parse_l2_ptp(&frame).is_none());
        // Too short to even hold an Ethernet header.
        assert!(parse_l2_ptp(&[0u8; 10]).is_none());
    }
}
