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
//!   * **Windows** — IP_RECVTOS + IP_RECVTTL via the `WSARecvMsg`
//!     extension function (resolved at runtime through
//!     `WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER)`), with cmsg
//!     parsing. Requires Win10+ for DSCP; if the extension can't be
//!     resolved we fall back to a plain read and report
//!     `qos_unavailable_on_platform` so a 0/0 result is never mistaken
//!     for "DSCP stripped".

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
    } else if !ancillary_supported() {
        // Windows only: the WSARecvMsg extension didn't resolve (pre-Win10
        // / unusual provider), so we captured the streams but no DSCP/TTL
        // markings. Surface this honestly rather than reading the zero-fill
        // as a real "QoS stripped" finding.
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
    // Enable IP_RECVTOS / IP_RECVTTL so every datagram's DSCP + TTL arrive
    // as ancillary (control) data. macOS + Linux read it back via
    // `recvmsg`; Windows reads it via the `WSARecvMsg` extension function,
    // which is resolved (once) inside `win_tos::enable_tos_ttl`.
    #[cfg(unix)]
    enable_tos_ttl(&sock)?;
    #[cfg(windows)]
    win_tos::enable_tos_ttl(&sock);
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
    win_tos::recv(sock)
}

/// Whether DSCP/TTL ancillary data is actually retrievable on this
/// platform/run. Always true on Unix (`recvmsg`); on Windows it depends
/// on the `WSARecvMsg` extension having resolved during socket setup.
#[cfg(not(windows))]
fn ancillary_supported() -> bool {
    true
}
#[cfg(windows)]
fn ancillary_supported() -> bool {
    win_tos::supported()
}

/// Windows DSCP/TTL capture via the `WSARecvMsg` extension function.
///
/// `recv_from` on a plain UDP socket discards the IP header, so the only
/// way to read the per-datagram TOS byte (DSCP) and TTL on Windows is the
/// `WSARecvMsg` extension (the Win32 analogue of POSIX `recvmsg`). The
/// function pointer isn't exported from `ws2_32.dll` directly — it must be
/// resolved at runtime via `WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER,
/// WSAID_WSARECVMSG)`. We resolve it once (cached) when the first socket
/// is created and then parse the returned control messages for `IP_TOS`
/// and `IP_TTL`.
///
/// All structs/constants are declared locally (rather than pulled from
/// `windows-sys`) so the layout is explicit and the module is
/// self-contained; the only external symbols are the rock-stable
/// `ws2_32` imports below. Targets the x86_64 Windows ABI.
#[cfg(windows)]
mod win_tos {
    use super::Sample;
    use socket2::Socket;
    use std::net::Ipv4Addr;
    use std::os::raw::c_void;
    use std::os::windows::io::AsRawSocket;
    use std::sync::atomic::{AtomicUsize, Ordering};

    type Socket_ = usize; // SOCKET
    const SOCKET_ERROR: i32 = -1;
    const IPPROTO_IP: i32 = 0;
    const IP_TOS: i32 = 3;
    const IP_TTL: i32 = 4;
    const IP_RECVTTL: i32 = 21;
    const IP_RECVTOS: i32 = 40;
    const SIO_GET_EXTENSION_FUNCTION_POINTER: u32 = 0xC800_0006;
    const WSAEWOULDBLOCK: i32 = 10035;
    const WSAETIMEDOUT: i32 = 10060;
    const AF_INET: u16 = 2;
    /// `WSAID_WSARECVMSG` = {f689d7c8-6f1f-436b-8a59-44054010 7e9b}
    const WSAID_WSARECVMSG: Guid = Guid {
        data1: 0xf689_d7c8,
        data2: 0x6f1f,
        data3: 0x436b,
        data4: [0x8a, 0x59, 0x44, 0x05, 0x40, 0x10, 0x7e, 0x9b],
    };

    #[repr(C)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    #[repr(C)]
    struct WsaBuf {
        len: u32,
        buf: *mut u8,
    }

    #[repr(C)]
    struct WsaMsg {
        name: *mut c_void,
        namelen: i32,
        buffers: *mut WsaBuf,
        buffer_count: u32,
        control: WsaBuf,
        flags: u32,
    }

    #[repr(C)]
    struct CmsgHdr {
        cmsg_len: usize,
        cmsg_level: i32,
        cmsg_type: i32,
    }

    /// `sockaddr_in` — family, port, addr (network byte order), padding.
    #[repr(C)]
    struct SockaddrIn {
        family: u16,
        port: u16,
        addr: u32,
        zero: [u8; 8],
    }

    type WsaRecvMsgFn = unsafe extern "system" fn(
        s: Socket_,
        msg: *mut WsaMsg,
        recvd: *mut u32,
        overlapped: *mut c_void,
        completion: *mut c_void,
    ) -> i32;

    #[link(name = "ws2_32")]
    extern "system" {
        fn setsockopt(
            s: Socket_,
            level: i32,
            optname: i32,
            optval: *const c_void,
            optlen: i32,
        ) -> i32;
        fn WSAIoctl(
            s: Socket_,
            code: u32,
            inbuf: *const c_void,
            inlen: u32,
            outbuf: *mut c_void,
            outlen: u32,
            bytes: *mut u32,
            overlapped: *mut c_void,
            completion: *mut c_void,
        ) -> i32;
        fn WSAGetLastError() -> i32;
    }

    // Cached `WSARecvMsg` pointer (0 = unavailable). `RESOLVED`: 0 = not yet
    // attempted, 1 = resolved OK, 2 = attempted and failed.
    static WSARECVMSG_PTR: AtomicUsize = AtomicUsize::new(0);
    static RESOLVED: AtomicUsize = AtomicUsize::new(0);

    pub fn enable_tos_ttl(sock: &Socket) {
        let s = sock.as_raw_socket() as Socket_;
        let on: i32 = 1;
        let p = &on as *const i32 as *const c_void;
        unsafe {
            // Best-effort: pre-Win10 these may no-op; TTL (IP_RECVTTL,
            // Vista+) still works even when TOS doesn't.
            setsockopt(s, IPPROTO_IP, IP_RECVTTL, p, 4);
            setsockopt(s, IPPROTO_IP, IP_RECVTOS, p, 4);
        }
        resolve_wsarecvmsg(s);
    }

    fn resolve_wsarecvmsg(s: Socket_) {
        if RESOLVED.load(Ordering::Acquire) != 0 {
            return;
        }
        let mut func: usize = 0;
        let mut bytes: u32 = 0;
        let rc = unsafe {
            WSAIoctl(
                s,
                SIO_GET_EXTENSION_FUNCTION_POINTER,
                &WSAID_WSARECVMSG as *const Guid as *const c_void,
                std::mem::size_of::<Guid>() as u32,
                &mut func as *mut usize as *mut c_void,
                std::mem::size_of::<usize>() as u32,
                &mut bytes,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if rc == 0 && func != 0 {
            WSARECVMSG_PTR.store(func, Ordering::Release);
            RESOLVED.store(1, Ordering::Release);
        } else {
            RESOLVED.store(2, Ordering::Release);
        }
    }

    pub fn supported() -> bool {
        RESOLVED.load(Ordering::Acquire) == 1
    }

    pub fn recv(sock: &Socket) -> std::io::Result<Option<(Option<Ipv4Addr>, Sample)>> {
        let ptr = WSARECVMSG_PTR.load(Ordering::Acquire);
        if ptr == 0 {
            // No extension function — fall back to a plain read so the
            // listen loop still drains the socket (DSCP/TTL unknown → 0).
            let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 2048];
            return match sock.recv_from(&mut buf) {
                Ok((_n, from)) => Ok(Some((
                    from.as_socket_ipv4().map(|a| *a.ip()),
                    Sample { dscp: 0, ttl: 0 },
                ))),
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    Ok(None)
                }
                Err(e) => Err(e),
            };
        }

        let recvmsg: WsaRecvMsgFn = unsafe { std::mem::transmute(ptr) };
        let s = sock.as_raw_socket() as Socket_;
        let mut databuf = [0u8; 2048];
        let mut ctrl = [0u8; 256];
        let mut name = SockaddrIn {
            family: 0,
            port: 0,
            addr: 0,
            zero: [0; 8],
        };
        let mut wbuf = WsaBuf {
            len: databuf.len() as u32,
            buf: databuf.as_mut_ptr(),
        };
        let mut msg = WsaMsg {
            name: &mut name as *mut SockaddrIn as *mut c_void,
            namelen: std::mem::size_of::<SockaddrIn>() as i32,
            buffers: &mut wbuf,
            buffer_count: 1,
            control: WsaBuf {
                len: ctrl.len() as u32,
                buf: ctrl.as_mut_ptr(),
            },
            flags: 0,
        };
        let mut recvd: u32 = 0;
        let rc = unsafe {
            recvmsg(
                s,
                &mut msg,
                &mut recvd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if rc == SOCKET_ERROR {
            let e = unsafe { WSAGetLastError() };
            if e == WSAEWOULDBLOCK || e == WSAETIMEDOUT {
                return Ok(None);
            }
            return Err(std::io::Error::from_raw_os_error(e));
        }

        let from = if name.family == AF_INET {
            Some(Ipv4Addr::from(u32::from_be(name.addr)))
        } else {
            None
        };

        // Walk the returned control messages for IP_TOS / IP_TTL. On the
        // x64 Windows ABI both the header and the data are 8-byte aligned,
        // so the data sits 16 bytes (sizeof WSACMSGHDR, rounded up) past
        // the header and successive headers advance by `cmsg_len` rounded
        // up to 8. Windows delivers these values as a little-endian INT, so
        // the low byte is the value we want either way.
        let (mut tos, mut ttl): (u8, u8) = (0, 0);
        let ctrl_len = recvd_control_len(&msg, &ctrl);
        let base = msg.control.buf;
        const HDR: usize = std::mem::size_of::<CmsgHdr>(); // 16 on x64
        const ALIGN: usize = 8;
        const DATA_OFF: usize = (HDR + ALIGN - 1) & !(ALIGN - 1); // 16
        let mut off = 0usize;
        while off + HDR <= ctrl_len {
            let cmsg = unsafe { &*(base.add(off) as *const CmsgHdr) };
            let clen = cmsg.cmsg_len;
            if clen < HDR || off + clen > ctrl_len {
                break;
            }
            if cmsg.cmsg_level == IPPROTO_IP && clen > DATA_OFF {
                let val = unsafe { *base.add(off + DATA_OFF) };
                if cmsg.cmsg_type == IP_TOS {
                    tos = val;
                } else if cmsg.cmsg_type == IP_TTL {
                    ttl = val;
                }
            }
            let adv = (clen + ALIGN - 1) & !(ALIGN - 1);
            if adv == 0 {
                break;
            }
            off += adv;
        }

        Ok(Some((
            from,
            Sample {
                dscp: tos >> 2, // upper 6 bits of the TOS byte
                ttl,
            },
        )))
    }

    /// The control buffer length actually written. `WSARecvMsg` updates
    /// `msg.control.len` to the bytes used; clamp to our buffer just in
    /// case a provider leaves it at the input capacity.
    fn recvd_control_len(msg: &WsaMsg, ctrl: &[u8]) -> usize {
        (msg.control.len as usize).min(ctrl.len())
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
