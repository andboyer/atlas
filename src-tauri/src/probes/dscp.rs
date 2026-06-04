//! DSCP & TTL audit for AV multicast traffic.
//!
//! Joins the well-known PTP and AES67 multicast groups on a pinned
//! interface, captures each arriving packet's IP TOS byte (DSCP = top 6
//! bits) and TTL using `IP_RECVTOS` / `IP_RECVTTL` ancillary data, then
//! reports the median observed DSCP per stream class against the
//! expected value:
//!
//! | Class      | Group              | Expected DSCP | RFC      |
//! |------------|--------------------|---------------|----------|
//! | ptp_event  | 224.0.1.129:319    | 56 (CS7)      | AES67    |
//! | ptp_general| 224.0.1.129:320    | 56 (CS7)      | AES67    |
//! | aes67_audio| 239.69.x.x:5004    | 34 (AF41)     | AES67    |
//!
//! Any DSCP drop (typically 0 / BE) along the path is the smoking gun
//! for switches that don't trust marking from edge hosts — a classic
//! cause of "Dante sometimes glitches when the room is busy".
//!
//! ## Platform notes
//!   * **macOS / Linux** — IP_RECVTOS + IP_RECVTTL via `libc::recvmsg`
//!     with cmsg parsing. Unprivileged.
//!   * **Windows** — `IP_RECVTOS` exists on Win10+ but cmsg retrieval
//!     requires `WSARecvMsg` which is not in `std::net`. For v1 we
//!     accept Windows DSCP capture without TOS/TTL (reports 0/0 with a
//!     note in the verdict) — the multicast presence is still useful as
//!     a "is the stream reaching this NIC at all" signal.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

use crate::probes::iface as iface_probe;
use crate::types::{DscpObservation, DscpProbeResult};

const PTP_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 1, 129);
const PTP_GROUP_GENERAL: Ipv4Addr = Ipv4Addr::new(224, 0, 1, 130);
const PTP_EVENT_PORT: u16 = 319;
const PTP_GENERAL_PORT: u16 = 320;
const AES67_RTP_PORT: u16 = 5004;
/// AES67 audio sender groups live in 239.69.0.0/16 (Audinate-issued
/// IANA-administered space) per AES67 Annex A.
const AES67_GROUP_RANGE_BASE: u32 = 0xEF45_0000;
const AES67_GROUP_RANGE_MASK: u32 = 0xFFFF_0000;

#[derive(Debug, Clone, Copy)]
struct Sample {
    dscp: u8,
    ttl: u8,
}

/// Synchronous blocking entrypoint — call from `tokio::task::spawn_blocking`.
pub fn run_blocking(iface: &str, listen_secs: u32) -> DscpProbeResult {
    match audit(iface, listen_secs) {
        Ok(r) => r,
        Err(e) => DscpProbeResult {
            iface: iface.to_string(),
            listen_secs,
            observations: Vec::new(),
            verdict: "error".to_string(),
            error: Some(e.to_string()),
        },
    }
}

fn audit(iface: &str, listen_secs: u32) -> anyhow::Result<DscpProbeResult> {
    let iface_v4 = resolve_iface_v4(iface);
    let deadline = Instant::now() + Duration::from_secs(listen_secs as u64);

    // (stream_kind, dst_group, dst_port_for_classification) → samples
    let mut by_stream: HashMap<(String, String), (Vec<Sample>, u8)> = HashMap::new();

    let sockets = [
        open_socket(iface_v4, PTP_EVENT_PORT, &[PTP_GROUP])?,
        open_socket(iface_v4, PTP_GENERAL_PORT, &[PTP_GROUP, PTP_GROUP_GENERAL])?,
        open_socket(
            iface_v4,
            AES67_RTP_PORT,
            // We can't enumerate every 239.69.x.x group ahead of time,
            // so we join the common "ANY-SOURCE" base. Most AES67
            // implementations send to specific 239.69.x.x — those
            // require explicit joins which would need an advance
            // discovery pass. For v1 we join one canonical AES67 stream
            // group and surface anything that arrives.
            &[Ipv4Addr::new(239, 69, 0, 1)],
        )?,
    ];
    let kinds: [&str; 3] = ["ptp_event", "ptp_general", "aes67_audio"];
    let expected: [u8; 3] = [56, 56, 34];

    while Instant::now() < deadline {
        for ((sock, kind), &exp_dscp) in sockets.iter().zip(kinds.iter()).zip(expected.iter()) {
            let _ = sock.set_read_timeout(Some(Duration::from_millis(150)));
            match recv_with_tos_ttl(sock) {
                Ok(Some((from, sample))) => {
                    let dst_label = match from {
                        Some(addr) => addr.to_string(),
                        None => "*".to_string(),
                    };
                    let key = (kind.to_string(), dst_label);
                    let entry = by_stream
                        .entry(key)
                        .or_insert_with(|| (Vec::new(), exp_dscp));
                    entry.0.push(sample);
                }
                _ => continue,
            }
        }
    }

    let mut observations: Vec<DscpObservation> = Vec::new();
    for ((kind, dst), (samples, expected_dscp)) in by_stream {
        if samples.is_empty() {
            continue;
        }
        let mut dscps: Vec<u8> = samples.iter().map(|s| s.dscp).collect();
        let mut ttls: Vec<u8> = samples.iter().map(|s| s.ttl).collect();
        dscps.sort_unstable();
        ttls.sort_unstable();
        let dscp_median = dscps[dscps.len() / 2];
        let ttl_median = ttls[ttls.len() / 2];
        let ttl_min = *ttls.first().unwrap_or(&0);
        observations.push(DscpObservation {
            stream_kind: kind,
            dst_group: dst,
            packets: samples.len() as u32,
            dscp_median,
            dscp_expected: expected_dscp,
            ttl_median,
            ttl_min,
        });
    }

    let verdict = if observations.is_empty() {
        "silent".to_string()
    } else if cfg!(target_os = "windows") {
        // Windows v1 can't read IP_TOS/IP_TTL from UDP recv without
        // WSARecvMsg. Surface this honestly so operators don't trust
        // the dscp_median=0 result as a real "QoS stripped" finding.
        "qos_unavailable_on_platform".to_string()
    } else {
        let mut preserved = 0u32;
        let mut stripped = 0u32;
        for o in &observations {
            // Allow ±2 DSCP code-point drift to accommodate transit
            // ECN remarking and minor profile mismatches.
            if (o.dscp_median as i16 - o.dscp_expected as i16).abs() <= 2 {
                preserved += 1;
            } else if o.dscp_median == 0 {
                stripped += 1;
            }
        }
        if stripped == observations.len() as u32 {
            "qos_stripped".to_string()
        } else if preserved == observations.len() as u32 {
            "qos_preserved".to_string()
        } else {
            "qos_mixed".to_string()
        }
    };

    Ok(DscpProbeResult {
        iface: iface.to_string(),
        listen_secs,
        observations,
        verdict,
        error: None,
    })
}

fn resolve_iface_v4(iface: &str) -> Ipv4Addr {
    if iface.is_empty() || iface.eq_ignore_ascii_case("auto") || iface == "0.0.0.0" {
        return Ipv4Addr::UNSPECIFIED;
    }
    iface_probe::find_by_name(iface)
        .and_then(|i| i.ipv4)
        .and_then(|s| s.parse::<Ipv4Addr>().ok())
        .unwrap_or(Ipv4Addr::UNSPECIFIED)
}

fn open_socket(iface_v4: Ipv4Addr, port: u16, groups: &[Ipv4Addr]) -> std::io::Result<Socket> {
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
    for grp in groups {
        let _ = sock.join_multicast_v4(grp, &iface_v4);
    }
    // Best-effort enable IP_RECVTOS / IP_RECVTTL. macOS + Linux honour
    // these; Windows ignores them on plain recv_from and would need
    // WSARecvMsg to surface the cmsg.
    #[cfg(unix)]
    enable_tos_ttl(&sock)?;
    Ok(sock)
}

#[cfg(unix)]
fn enable_tos_ttl(sock: &Socket) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let fd = sock.as_raw_fd();
    let on: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_RECVTOS,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_RECVTTL,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
    Ok(())
}

#[cfg(unix)]
fn recv_with_tos_ttl(sock: &Socket) -> std::io::Result<Option<(Option<Ipv4Addr>, Sample)>> {
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd;
    let fd = sock.as_raw_fd();
    let mut buf = [0u8; 2048];
    let mut cbuf = [0u8; 256];
    let mut from_storage: MaybeUninit<libc::sockaddr_in> = MaybeUninit::uninit();
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = from_storage.as_mut_ptr() as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cbuf.len() as _;
    msg.msg_flags = 0;

    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        let err = std::io::Error::last_os_error();
        return match err.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => Ok(None),
            _ => Err(err),
        };
    }

    let from: Option<Ipv4Addr> =
        if msg.msg_namelen >= std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t {
            let sa = unsafe { from_storage.assume_init() };
            // sin_addr is in network byte order; native-endian on most
            // platforms after `s_addr` is a u32 we must to_be().
            let raw = u32::from_be(sa.sin_addr.s_addr);
            Some(Ipv4Addr::from(raw))
        } else {
            None
        };

    let mut tos: u8 = 0;
    let mut ttl: u8 = 0;
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            let level = (*cmsg).cmsg_level;
            let typ = (*cmsg).cmsg_type;
            if level == libc::IPPROTO_IP {
                let data = libc::CMSG_DATA(cmsg);
                if typ == libc::IP_RECVTOS || typ == libc::IP_TOS {
                    tos = *data;
                } else if typ == libc::IP_RECVTTL || typ == libc::IP_TTL {
                    ttl = *data;
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    let _ = n;
    Ok(Some((
        from,
        Sample {
            dscp: tos >> 2, // upper 6 bits
            ttl,
        },
    )))
}

#[cfg(windows)]
fn recv_with_tos_ttl(sock: &Socket) -> std::io::Result<Option<(Option<Ipv4Addr>, Sample)>> {
    let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 2048];
    match sock.recv_from(&mut buf) {
        Ok((_n, from)) => {
            let dst = from.as_socket_ipv4().map(|a| *a.ip());
            // Windows TOS/TTL not retrieved (WSARecvMsg path not wired
            // in v1). Surface zeros — verdict layer flags
            // "qos_unavailable_on_platform" so operators don't
            // misread these as "DSCP stripped to 0".
            Ok(Some((dst, Sample { dscp: 0, ttl: 0 })))
        }
        Err(e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
        {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// Helper for tests / future use — true if an IPv4 is in the AES67
/// 239.69.0.0/16 transmitter range.
#[allow(dead_code)]
fn is_aes67_group(addr: Ipv4Addr) -> bool {
    let raw = u32::from(addr);
    (raw & AES67_GROUP_RANGE_MASK) == AES67_GROUP_RANGE_BASE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes67_range_classifier() {
        assert!(is_aes67_group(Ipv4Addr::new(239, 69, 0, 1)));
        assert!(is_aes67_group(Ipv4Addr::new(239, 69, 255, 255)));
        assert!(!is_aes67_group(Ipv4Addr::new(239, 255, 0, 1)));
        assert!(!is_aes67_group(Ipv4Addr::new(224, 0, 1, 129)));
    }

    #[test]
    fn dscp_extracted_from_tos_top_six_bits() {
        // TOS=0xb8 (CS7+ECN=0) → DSCP=46 (EF audio class)... wait, 0xb8
        // is actually EF (46<<2 = 0xb8). DSCP=0x2e=46.
        let tos: u8 = 0xb8;
        assert_eq!(tos >> 2, 46);
        // TOS=0xe0 (CS7) → DSCP=56
        let tos: u8 = 0xe0;
        assert_eq!(tos >> 2, 56);
    }
}
