//! Network-interface enumeration + per-interface socket binding helpers.
//!
//! Lets the user pin AV-over-IP probes (Dante mDNS browse, control-port
//! TCP probe, IGMP listen) to a specific NIC — typically a USB-Ethernet
//! adapter cabled into the audio VLAN — instead of the kernel's default
//! routing-table pick (usually Wi-Fi, where Dante is unreliable).
//!
//! ## Binding strategy
//!   - **macOS** — `setsockopt(IP_BOUND_IF=25)`. Same mechanism the
//!     existing IGMP listener in `probes::deep` uses; the kernel routes
//!     every packet on that socket through the chosen interface index
//!     regardless of the routing table.
//!   - **Linux** — `SO_BINDTODEVICE` via socket2's `bind_device()`.
//!   - **Other (Windows / unknown)** — best-effort source-IP bind: we
//!     `bind()` the socket to the interface's IPv4 address and let the
//!     routing table do its job. Works for the common case of distinct
//!     subnets per NIC.

use std::collections::HashMap;
use std::ffi::CStr;
#[cfg(unix)]
use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

/// One usable network interface as seen by the host kernel. Surfaced to
/// the UI so the user can pick which NIC the AV probes should ride on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterfaceInfo {
    /// Kernel name, e.g. `en0`, `en4`, `eth0`, `utun3`. This is the only
    /// stable identifier we round-trip through Settings.
    pub name: String,
    /// First IPv4 address bound on this interface, if any (string form
    /// for cheap JSON transport).
    pub ipv4: Option<String>,
    /// Interface is administratively up.
    pub is_up: bool,
    /// Loopback (`lo0` / `lo`). The picker should filter these out.
    pub is_loopback: bool,
}

/// Enumerate every interface the kernel knows about, with one row per
/// distinct name (multiple IPv4 aliases on the same NIC collapse to the
/// first address).
///
/// Returns an empty Vec on platforms / hosts where `getifaddrs` is
/// unavailable. Never blocks long enough to need spawn_blocking.
pub fn list_interfaces() -> Vec<NetworkInterfaceInfo> {
    #[cfg(unix)]
    {
        list_unix()
    }
    #[cfg(not(unix))]
    {
        // Windows path can be added later via GetAdaptersAddresses; for
        // now the UI simply gets an empty list and falls back to "Auto".
        Vec::new()
    }
}

#[cfg(unix)]
fn list_unix() -> Vec<NetworkInterfaceInfo> {
    let mut by_name: HashMap<String, NetworkInterfaceInfo> = HashMap::new();
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return Vec::new();
        }
        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_name.is_null() {
                let name = CStr::from_ptr(ifa.ifa_name).to_string_lossy().into_owned();
                let flags = ifa.ifa_flags as i32;
                let is_up = (flags & libc::IFF_UP as i32) != 0;
                let is_loopback = (flags & libc::IFF_LOOPBACK as i32) != 0;
                let entry = by_name
                    .entry(name.clone())
                    .or_insert_with(|| NetworkInterfaceInfo {
                        name: name.clone(),
                        ipv4: None,
                        is_up,
                        is_loopback,
                    });
                entry.is_up = entry.is_up || is_up;
                entry.is_loopback = entry.is_loopback || is_loopback;
                if entry.ipv4.is_none() && !ifa.ifa_addr.is_null() {
                    let sa = &*ifa.ifa_addr;
                    if sa.sa_family as i32 == libc::AF_INET {
                        let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                        let raw = sin.sin_addr.s_addr;
                        // `s_addr` is in network byte order on every Unix
                        // we support; convert through Ipv4Addr's
                        // u32-from-octets path to stay endian-safe.
                        let octets = raw.to_ne_bytes();
                        let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
                        entry.ipv4 = Some(ip.to_string());
                    }
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    let mut v: Vec<NetworkInterfaceInfo> = by_name.into_values().collect();
    // Stable order: en0 / en1 / ..., then alphabetical.
    v.sort_by(|a, b| a.name.cmp(&b.name));
    v
}

/// Look up an interface row by name. Returns `None` if the name doesn't
/// match any current NIC (the picker selection is stale, or the user
/// unplugged the USB-Ethernet adapter between scans).
pub fn find_by_name(name: &str) -> Option<NetworkInterfaceInfo> {
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    list_interfaces().into_iter().find(|i| i.name == name)
}

/// Attempt a TCP connection to `(ip, port)` from the given interface,
/// honouring `timeout`. Returns `true` on a successful three-way handshake.
///
/// When `iface` is `None` (or empty / "auto"), behaves like the previous
/// kernel-default async connect. When it's set, runs the connect in a
/// blocking thread with a per-interface socket so the kernel cannot
/// silently route the probe out the Wi-Fi interface instead.
pub async fn tcp_connect_via_iface(
    iface: Option<&str>,
    ip: &str,
    port: u16,
    timeout: Duration,
) -> bool {
    let pinned = iface
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("auto"));

    if pinned.is_none() {
        let addr = format!("{ip}:{port}");
        return tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr))
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false);
    }

    let iface = pinned.unwrap().to_string();
    let ip_owned = ip.to_string();
    tokio::task::spawn_blocking(move || connect_blocking(&iface, &ip_owned, port, timeout))
        .await
        .unwrap_or(false)
}

fn connect_blocking(iface: &str, ip: &str, port: u16, timeout: Duration) -> bool {
    let Ok(addr) = ip.parse::<IpAddr>() else {
        return false;
    };
    let domain = match addr {
        IpAddr::V4(_) => Domain::IPV4,
        IpAddr::V6(_) => Domain::IPV6,
    };
    let socket = match Socket::new(domain, Type::STREAM, Some(Protocol::TCP)) {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!("iface probe: socket create failed: {e}");
            return false;
        }
    };
    if let Err(e) = bind_socket_to_iface(&socket, addr, iface) {
        tracing::debug!("iface probe: bind to {iface} failed: {e}");
        return false;
    }
    let sa: SockAddr = SocketAddr::new(addr, port).into();
    socket.connect_timeout(&sa, timeout).is_ok()
}

/// Pin a socket to a specific interface so all of its traffic flows out
/// (and is accepted on) that NIC. The fallback path also source-binds to
/// the interface's IPv4 address, which on Windows / unknown Unixes
/// achieves the same routing outcome for the common case.
#[cfg(target_os = "macos")]
fn bind_socket_to_iface(sock: &Socket, addr: IpAddr, iface: &str) -> std::io::Result<()> {
    // The userland header that exposes IP_BOUND_IF / IPV6_BOUND_IF lives
    // in <netinet/in.h>; libc's `IP_BOUND_IF` constant is gated behind
    // macOS-only features that aren't always enabled, so we hard-code the
    // documented values (stable since 10.5).
    const IP_BOUND_IF: libc::c_int = 25;
    const IPV6_BOUND_IF: libc::c_int = 125;

    let cname = CString::new(iface)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "iface contains NUL"))?;
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("interface {iface} not found"),
        ));
    }
    let (level, name) = match addr {
        IpAddr::V4(_) => (libc::IPPROTO_IP, IP_BOUND_IF),
        IpAddr::V6(_) => (libc::IPPROTO_IPV6, IPV6_BOUND_IF),
    };
    let ret = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            level,
            name,
            &idx as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn bind_socket_to_iface(sock: &Socket, _addr: IpAddr, iface: &str) -> std::io::Result<()> {
    sock.bind_device(Some(iface.as_bytes()))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn bind_socket_to_iface(sock: &Socket, addr: IpAddr, iface: &str) -> std::io::Result<()> {
    // Best-effort: bind the connection's source IP to the interface's
    // first matching address. The routing table then picks the iface
    // because there's only one egress that owns that source.
    let info = find_by_name(iface).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("interface {iface} not found"),
        )
    })?;
    let ipv4 = info
        .ipv4
        .as_deref()
        .and_then(|s| s.parse::<Ipv4Addr>().ok());
    let src: IpAddr = match (addr, ipv4) {
        (IpAddr::V4(_), Some(v4)) => IpAddr::V4(v4),
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "per-interface bind requires an IPv4 address on this platform",
            ))
        }
    };
    let sa: SockAddr = SocketAddr::new(src, 0).into();
    sock.bind(&sa)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_interfaces_returns_loopback() {
        // Every Unix host has a loopback. If this fires on CI the
        // platform abstraction is broken.
        let list = list_interfaces();
        if cfg!(unix) {
            assert!(
                list.iter().any(|i| i.is_loopback),
                "expected at least one loopback iface, got {list:?}"
            );
        }
    }

    #[test]
    fn find_by_name_handles_unknown() {
        assert!(find_by_name("definitely-not-a-real-iface-zzz").is_none());
        assert!(find_by_name("   ").is_none());
        assert!(find_by_name("").is_none());
    }
}
