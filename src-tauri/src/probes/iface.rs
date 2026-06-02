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
//!   - **Windows** — `setsockopt(IP_UNICAST_IF)` with the interface
//!     index in network byte order (per WinSock docs). The kernel then
//!     routes the socket's traffic through that NIC regardless of the
//!     routing table — exact semantic match for macOS's IP_BOUND_IF.

use std::collections::HashMap;
use std::ffi::CStr;
#[cfg(unix)]
use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
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
    /// Heuristic: this is a real physical NIC (Ethernet / Wi-Fi / USB-
    /// Ethernet) that can carry IPv4 traffic, as opposed to a virtual
    /// pseudo-interface (utun / awdl / bridge / docker / veth / …).
    /// Computed from the kernel name; the picker uses it to hide the
    /// dozen-or-so virtual interfaces macOS / Linux create by default.
    pub is_physical: bool,
    /// Kernel interface index (1-based on every supported OS). Required
    /// for `IP_UNICAST_IF` on Windows and `IP_BOUND_IF` on macOS; we
    /// stash it on the row so callers don't have to do a second lookup.
    /// `None` when the index wasn't resolvable (very rare; means the
    /// adapter just disappeared between enumeration and the read).
    #[serde(default)]
    pub index: Option<u32>,
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
    #[cfg(windows)]
    {
        list_windows().unwrap_or_default()
    }
    #[cfg(not(any(unix, windows)))]
    {
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
                let is_physical = is_physical_name(&name);
                let entry = by_name
                    .entry(name.clone())
                    .or_insert_with(|| NetworkInterfaceInfo {
                        name: name.clone(),
                        ipv4: None,
                        is_up,
                        is_loopback,
                        is_physical,
                        index: None,
                    });
                entry.is_up = entry.is_up || is_up;
                entry.is_loopback = entry.is_loopback || is_loopback;
                if entry.index.is_none() {
                    if let Ok(cname) = CString::new(name.as_str()) {
                        let idx = libc::if_nametoindex(cname.as_ptr());
                        if idx != 0 {
                            entry.index = Some(idx);
                        }
                    }
                }
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

/// Windows NIC enumeration via `GetAdaptersAddresses`. Returns one row
/// per adapter, populated with the friendly name (e.g. "Ethernet 3"),
/// first IPv4 unicast address, oper-status, and adapter index.
///
/// We treat `IF_TYPE_ETHERNET_CSMACD` (6) and `IF_TYPE_IEEE80211` (71)
/// as physical for the AV picker; everything else (tunnels, loopback,
/// software bridges) is flagged virtual.
#[cfg(windows)]
fn list_windows() -> Option<Vec<NetworkInterfaceInfo>> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_PREFIX, GAA_FLAG_SKIP_ANYCAST,
        GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IF_TYPE_ETHERNET_CSMACD,
        IF_TYPE_IEEE80211, IF_TYPE_SOFTWARE_LOOPBACK, IP_ADAPTER_ADDRESSES_LH,
        IP_ADAPTER_UNICAST_ADDRESS_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_UNSPEC, SOCKADDR_IN};

    const IF_OPER_STATUS_UP: u32 = 1;
    // GetAdaptersAddresses needs a buffer; first call with size=0 returns
    // the required size in `size`. 15 KB is enough for ~30 adapters; we
    // grow up to 256 KB just in case.
    let mut size: u32 = 15 * 1024;
    let mut buf: Vec<u8> = Vec::new();
    let mut adapters: *mut IP_ADAPTER_ADDRESSES_LH = std::ptr::null_mut();
    let flags = GAA_FLAG_INCLUDE_PREFIX
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER;
    for _ in 0..4 {
        buf.resize(size as usize, 0);
        adapters = buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
        let ret = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                flags,
                std::ptr::null_mut(),
                adapters,
                &mut size,
            )
        };
        const ERROR_SUCCESS: u32 = 0;
        const ERROR_BUFFER_OVERFLOW: u32 = 111;
        if ret == ERROR_SUCCESS {
            break;
        }
        if ret == ERROR_BUFFER_OVERFLOW {
            // `size` was updated to the required value; retry.
            continue;
        }
        // Any other error: empty Vec (caller treats this the same as no
        // physical NICs being available).
        return None;
    }

    let mut out: Vec<NetworkInterfaceInfo> = Vec::new();
    let mut cur = adapters;
    while !cur.is_null() {
        let adapter = unsafe { &*cur };
        let name = read_wide(adapter.FriendlyName);
        // `AdapterName` is the GUID; not user-facing. Keep FriendlyName as
        // the stable identifier the UI persists in settings — same as
        // PowerShell's `Get-NetAdapter -Name`.
        let if_type = adapter.IfType;
        let if_index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
        let oper_status = adapter.OperStatus as u32;
        let is_up = oper_status == IF_OPER_STATUS_UP;
        let is_loopback = if_type == IF_TYPE_SOFTWARE_LOOPBACK;
        let is_physical = matches!(if_type, IF_TYPE_ETHERNET_CSMACD | IF_TYPE_IEEE80211);

        // Walk the unicast-address list for the first IPv4.
        let mut ipv4: Option<String> = None;
        let mut ua: *mut IP_ADAPTER_UNICAST_ADDRESS_LH = adapter.FirstUnicastAddress;
        while !ua.is_null() {
            let entry = unsafe { &*ua };
            let sa = entry.Address.lpSockaddr;
            if !sa.is_null() && unsafe { (*sa).sa_family } == windows_sys::Win32::Networking::WinSock::AF_INET {
                let sin = sa as *const SOCKADDR_IN;
                let raw = unsafe { (*sin).sin_addr.S_un.S_addr };
                let octets = raw.to_ne_bytes();
                let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
                ipv4 = Some(ip.to_string());
                break;
            }
            ua = entry.Next;
        }

        if !name.is_empty() {
            out.push(NetworkInterfaceInfo {
                name,
                ipv4,
                is_up,
                is_loopback,
                is_physical,
                index: Some(if_index),
            });
        }
        cur = adapter.Next;
    }
    // Stable, predictable order for the picker dropdown.
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Some(out)
}

/// Decode a NUL-terminated wide string from a Win32 struct.
#[cfg(windows)]
fn read_wide(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    unsafe {
        let mut len = 0usize;
        while *ptr.add(len) != 0 {
            len += 1;
            // Defensive: friendly names are <= 256 chars per WinSock docs.
            if len > 1024 {
                break;
            }
        }
        let slice = std::slice::from_raw_parts(ptr, len);
        String::from_utf16_lossy(slice)
    }
}

/// Heuristic for "this kernel name belongs to a real physical NIC that
/// can carry IPv4 traffic". Blacklist-based because macOS / Linux both
/// invent new virtual-interface prefixes (`anpi*`, `llw*`, `vmenet*`,
/// `cilium_*`, …) faster than we can whitelist real ones. Anything not
/// matching a known virtual prefix is treated as physical.
///
/// Windows doesn't use this — `GetAdaptersAddresses` exposes
/// `IfType` directly, which is a much more reliable signal than the
/// Win32 friendly name.
///
/// Known virtual prefixes:
///   - macOS: `lo`, `utun`, `awdl`, `llw`, `anpi`, `gif`, `stf`,
///     `bridge`, `ap` (AirDrop / softAP), `pktap`, `vmenet`, `XHC`,
///     `pdp_ip` (cellular tether), `feth`.
///   - Linux: `lo`, `docker`, `br-`, `virbr`, `veth`, `tun`, `tap`,
///     `vnet`, `vmnet`, `kube`, `cni`, `flannel`, `cali`, `weave`,
///     `cilium`, `wg` (WireGuard).
#[cfg(unix)]
fn is_physical_name(name: &str) -> bool {
    const VIRTUAL_PREFIXES: &[&str] = &[
        // macOS
        "lo", "utun", "awdl", "llw", "anpi", "gif", "stf", "bridge", "ap", "pktap",
        "vmenet", "XHC", "pdp_ip", "feth",
        // Linux
        "docker", "br-", "virbr", "veth", "tun", "tap", "vnet", "vmnet", "kube", "cni",
        "flannel", "cali", "weave", "cilium", "wg",
    ];
    // Match on prefix-then-digit-or-delimiter (or exact match) so we
    // don't catch unrelated names that just happen to share a leading
    // substring (e.g. `enp3s0` is a real Linux NIC and must NOT match a
    // hypothetical `en` virtual prefix). Prefixes that already end in a
    // delimiter (`br-`) accept any remainder.
    for &pfx in VIRTUAL_PREFIXES {
        let Some(rest) = name.strip_prefix(pfx) else { continue };
        if rest.is_empty() {
            return false;
        }
        if pfx.ends_with('-') || pfx.ends_with('_') {
            return false;
        }
        if rest
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit() || c == '-' || c == '_')
        {
            return false;
        }
    }
    true
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

#[cfg(target_os = "windows")]
fn bind_socket_to_iface(sock: &Socket, addr: IpAddr, iface: &str) -> std::io::Result<()> {
    // WinSock `IP_UNICAST_IF` (RFC 3493 §5.2 equivalent, MS-only spelling).
    // Documented at:
    //   https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
    //
    // Quirk: the v4 form takes the interface index in **network byte
    // order**; the v6 form takes it in host byte order. We only do v4
    // here, so byte-swap once.
    use std::os::raw::c_void;
    use windows_sys::Win32::Networking::WinSock::{
        setsockopt, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, IP_UNICAST_IF, SOCKET,
    };

    let info = find_by_name(iface).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("interface {iface} not found"),
        )
    })?;
    let idx = info.index.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("interface {iface} has no kernel index"),
        )
    })?;
    let sock_handle = sock.as_raw_socket() as SOCKET;
    let (level, name, value_be): (i32, i32, u32) = match addr {
        IpAddr::V4(_) => (IPPROTO_IP as i32, IP_UNICAST_IF as i32, idx.to_be()),
        IpAddr::V6(_) => (IPPROTO_IPV6 as i32, IPV6_UNICAST_IF as i32, idx),
    };
    let ret = unsafe {
        setsockopt(
            sock_handle,
            level,
            name,
            &value_be as *const u32 as *const u8 as *const _,
            std::mem::size_of::<u32>() as i32,
        )
    };
    // setsockopt returns 0 on success, SOCKET_ERROR (-1) on failure.
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Belt-and-braces: also source-bind to the iface's IPv4 so unicast
    // routes are unambiguous. IP_UNICAST_IF alone is sufficient on
    // modern Windows (≥10), but adding the source bind is harmless and
    // gives sensible behavior on the rare older box.
    if let (IpAddr::V4(_), Some(v4)) = (
        addr,
        info.ipv4.as_deref().and_then(|s| s.parse::<Ipv4Addr>().ok()),
    ) {
        let _ = sock.bind(&SocketAddr::new(IpAddr::V4(v4), 0).into());
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
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

    #[cfg(unix)]
    #[test]
    fn physical_name_classifier_macos() {
        // Real macOS NICs (Ethernet / Wi-Fi / USB-Ethernet / Thunderbolt).
        assert!(is_physical_name("en0"));
        assert!(is_physical_name("en4"));
        assert!(is_physical_name("en10"));
        // macOS virtual.
        assert!(!is_physical_name("lo0"));
        assert!(!is_physical_name("utun0"));
        assert!(!is_physical_name("utun15"));
        assert!(!is_physical_name("awdl0"));
        assert!(!is_physical_name("llw0"));
        assert!(!is_physical_name("anpi0"));
        assert!(!is_physical_name("bridge0"));
        assert!(!is_physical_name("ap1"));
        assert!(!is_physical_name("gif0"));
        assert!(!is_physical_name("stf0"));
        assert!(!is_physical_name("pdp_ip0"));
    }

    #[cfg(unix)]
    #[test]
    fn physical_name_classifier_linux() {
        // Real Linux NICs.
        assert!(is_physical_name("eth0"));
        assert!(is_physical_name("enp3s0"));
        assert!(is_physical_name("wlp2s0"));
        assert!(is_physical_name("eno1"));
        // Linux virtual.
        assert!(!is_physical_name("lo"));
        assert!(!is_physical_name("docker0"));
        assert!(!is_physical_name("br-1234567890ab"));
        assert!(!is_physical_name("virbr0"));
        assert!(!is_physical_name("veth1234abc"));
        assert!(!is_physical_name("tun0"));
        assert!(!is_physical_name("wg0"));
    }
}
