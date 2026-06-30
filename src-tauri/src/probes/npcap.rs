//! Minimal, runtime-loaded Npcap (`wpcap.dll`) wrapper for layer-2 frame
//! capture on Windows.
//!
//! This is the Windows counterpart to the macOS `/dev/bpf` capture used by
//! the PTP and (future) LLDP probes: it lets us see raw Ethernet frames —
//! e.g. PTP-over-Ethernet (gPTP, ethertype `0x88F7`) used by SMPTE 2110 /
//! AVB media networks — which a UDP socket can never observe.
//!
//! `wpcap.dll` is loaded **dynamically** (`LoadLibrary` / `GetProcAddress`)
//! rather than linked at build time, so:
//!   * the binary builds without the Npcap SDK, and
//!   * the binary runs without Npcap installed — capture is simply
//!     unavailable (returns an error the caller treats as "no L2 records",
//!     exactly like an unprivileged BPF open on macOS).
//!
//! All struct/ABI assumptions target the x86_64 Windows ABI. The pcap API
//! is `cdecl`, which is identical to the x64 calling convention, so the
//! `extern "C"` function-pointer types below are correct on x64.

#![cfg(target_os = "windows")]

use std::ffi::CString;
use std::net::Ipv4Addr;
use std::os::raw::{c_char, c_int, c_void};
use std::time::{Duration, Instant};

type Hmodule = isize;

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryA(name: *const u8) -> Hmodule;
    fn GetProcAddress(module: Hmodule, name: *const u8) -> *const c_void;
    fn FreeLibrary(module: Hmodule) -> c_int;
}

const PCAP_ERRBUF_SIZE: usize = 256;
const AF_INET: u16 = 2;

/// Opaque `pcap_t` handle.
#[repr(C)]
struct PcapT {
    _private: [u8; 0],
}

#[repr(C)]
struct BpfProgram {
    bf_len: u32,
    bf_insns: *mut c_void,
}

/// `pcap_pkthdr`. On Windows `long` is 32-bit, so `timeval` is two i32s and
/// the whole header is 16 bytes with `caplen` at offset 8.
#[repr(C)]
struct PcapPkthdr {
    ts_sec: i32,
    ts_usec: i32,
    caplen: u32,
    len: u32,
}

#[repr(C)]
struct PcapIf {
    next: *mut PcapIf,
    name: *const c_char,
    description: *const c_char,
    addresses: *mut PcapAddr,
    flags: u32,
}

#[repr(C)]
struct PcapAddr {
    next: *mut PcapAddr,
    addr: *mut Sockaddr,
    netmask: *mut Sockaddr,
    broadaddr: *mut Sockaddr,
    dstaddr: *mut Sockaddr,
}

#[repr(C)]
struct Sockaddr {
    sa_family: u16,
    sa_data: [u8; 14],
}

type FnFindAllDevs = extern "C" fn(*mut *mut PcapIf, *mut u8) -> c_int;
type FnFreeAllDevs = extern "C" fn(*mut PcapIf);
type FnOpenLive = extern "C" fn(*const c_char, c_int, c_int, c_int, *mut u8) -> *mut PcapT;
type FnCompile = extern "C" fn(*mut PcapT, *mut BpfProgram, *const c_char, c_int, u32) -> c_int;
type FnSetFilter = extern "C" fn(*mut PcapT, *mut BpfProgram) -> c_int;
type FnFreeCode = extern "C" fn(*mut BpfProgram);
type FnNextEx = extern "C" fn(*mut PcapT, *mut *mut PcapPkthdr, *mut *const u8) -> c_int;
type FnClose = extern "C" fn(*mut PcapT);

/// Resolved `wpcap.dll` entry points. The module handle is freed on drop.
struct Lib {
    module: Hmodule,
    find_all_devs: FnFindAllDevs,
    free_all_devs: FnFreeAllDevs,
    open_live: FnOpenLive,
    compile: FnCompile,
    set_filter: FnSetFilter,
    free_code: FnFreeCode,
    next_ex: FnNextEx,
    close: FnClose,
}

impl Drop for Lib {
    fn drop(&mut self) {
        unsafe {
            FreeLibrary(self.module);
        }
    }
}

unsafe fn resolve<T>(module: Hmodule, name: &str) -> Option<T> {
    let c = CString::new(name).ok()?;
    let p = GetProcAddress(module, c.as_ptr() as *const u8);
    if p.is_null() {
        None
    } else {
        // T is always a same-sized fn pointer; copy the raw address bits.
        Some(std::mem::transmute_copy::<*const c_void, T>(&p))
    }
}

fn load() -> Option<Lib> {
    unsafe {
        let module = LoadLibraryA(c"wpcap.dll".as_ptr() as *const u8);
        if module == 0 {
            return None;
        }
        Some(Lib {
            module,
            find_all_devs: resolve(module, "pcap_findalldevs")?,
            free_all_devs: resolve(module, "pcap_freealldevs")?,
            open_live: resolve(module, "pcap_open_live")?,
            compile: resolve(module, "pcap_compile")?,
            set_filter: resolve(module, "pcap_setfilter")?,
            free_code: resolve(module, "pcap_freecode")?,
            next_ex: resolve(module, "pcap_next_ex")?,
            close: resolve(module, "pcap_close")?,
        })
    }
}

/// Capture L2 frames matching `filter` (a libpcap filter expression) on the
/// interface bound to `iface_ipv4`, calling `on_frame` for each captured
/// frame until `listen_secs` elapses.
///
/// Best-effort: returns an error if Npcap isn't installed or the device
/// can't be opened. The interface is matched by its bound IPv4 address
/// (the only stable cross-reference between our enumeration and pcap's
/// `\Device\NPF_{GUID}` names).
pub fn capture_l2<F: FnMut(&[u8])>(
    iface_ipv4: Option<Ipv4Addr>,
    filter: &str,
    listen_secs: u32,
    mut on_frame: F,
) -> anyhow::Result<()> {
    let lib = load().ok_or_else(|| anyhow::anyhow!("Npcap (wpcap.dll) not available"))?;

    let dev_name = find_device(&lib, iface_ipv4)?;
    let dev_c = CString::new(dev_name).map_err(|_| anyhow::anyhow!("device name had NUL"))?;

    let mut errbuf = [0u8; PCAP_ERRBUF_SIZE];
    // snaplen 65536, promisc = 1 (catch multicast gPTP), read timeout 250ms
    // so `pcap_next_ex` returns periodically and we can re-check the deadline.
    let handle = (lib.open_live)(dev_c.as_ptr(), 65536, 1, 250, errbuf.as_mut_ptr());
    if handle.is_null() {
        anyhow::bail!("pcap_open_live failed: {}", errbuf_to_string(&errbuf));
    }

    // RAII close.
    struct OpenHandle<'a> {
        lib: &'a Lib,
        handle: *mut PcapT,
    }
    impl Drop for OpenHandle<'_> {
        fn drop(&mut self) {
            (self.lib.close)(self.handle);
        }
    }
    let _open = OpenHandle { lib: &lib, handle };

    // Compile + install the BPF filter. If compilation fails we still
    // capture (the per-frame parser rejects non-matching frames), just
    // less efficiently.
    let mut prog = BpfProgram {
        bf_len: 0,
        bf_insns: std::ptr::null_mut(),
    };
    if let Ok(filt_c) = CString::new(filter) {
        const PCAP_NETMASK_UNKNOWN: u32 = 0xffff_ffff;
        if (lib.compile)(handle, &mut prog, filt_c.as_ptr(), 1, PCAP_NETMASK_UNKNOWN) == 0 {
            (lib.set_filter)(handle, &mut prog);
            (lib.free_code)(&mut prog);
        }
    }

    let deadline = Instant::now() + Duration::from_secs(listen_secs as u64);
    while Instant::now() < deadline {
        let mut header: *mut PcapPkthdr = std::ptr::null_mut();
        let mut data: *const u8 = std::ptr::null();
        let rc = (lib.next_ex)(handle, &mut header, &mut data);
        match rc {
            1 => {
                if header.is_null() || data.is_null() {
                    continue;
                }
                let caplen = unsafe { (*header).caplen as usize };
                if caplen == 0 {
                    continue;
                }
                let frame = unsafe { std::slice::from_raw_parts(data, caplen) };
                on_frame(frame);
            }
            0 => continue, // read timeout — loop to re-check the deadline
            _ => break,    // -1 error, -2 EOF (savefile only)
        }
    }
    Ok(())
}

/// Find the pcap device whose bound IPv4 matches `iface_ipv4`. Falls back to
/// the first enumerated device when no match (or no address) is available.
fn find_device(lib: &Lib, iface_ipv4: Option<Ipv4Addr>) -> anyhow::Result<String> {
    let mut alldevs: *mut PcapIf = std::ptr::null_mut();
    let mut errbuf = [0u8; PCAP_ERRBUF_SIZE];
    if (lib.find_all_devs)(&mut alldevs, errbuf.as_mut_ptr()) != 0 || alldevs.is_null() {
        anyhow::bail!("pcap_findalldevs failed: {}", errbuf_to_string(&errbuf));
    }

    struct DevList<'a> {
        lib: &'a Lib,
        head: *mut PcapIf,
    }
    impl Drop for DevList<'_> {
        fn drop(&mut self) {
            (self.lib.free_all_devs)(self.head);
        }
    }
    let _list = DevList { lib, head: alldevs };

    let mut first: Option<String> = None;
    let mut matched: Option<String> = None;

    let mut cur = alldevs;
    unsafe {
        while !cur.is_null() {
            let name = cstr_to_string((*cur).name);
            if first.is_none() {
                first = name.clone();
            }
            if let Some(want) = iface_ipv4 {
                let mut addr = (*cur).addresses;
                while !addr.is_null() {
                    let sa = (*addr).addr;
                    if !sa.is_null() && (*sa).sa_family == AF_INET {
                        // sockaddr_in: family(0..2) port(2..4) sin_addr(4..8).
                        // sa_data starts at byte 2, so the address bytes are
                        // sa_data[2..6] in network byte order.
                        let d = &(*sa).sa_data;
                        let ip = Ipv4Addr::new(d[2], d[3], d[4], d[5]);
                        if ip == want {
                            matched = name.clone();
                            break;
                        }
                    }
                    addr = (*addr).next;
                }
            }
            if matched.is_some() {
                break;
            }
            cur = (*cur).next;
        }
    }

    matched
        .or(first)
        .ok_or_else(|| anyhow::anyhow!("no Npcap capture devices found"))
}

unsafe fn cstr_to_string(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let bytes = std::ffi::CStr::from_ptr(p).to_bytes();
    Some(String::from_utf8_lossy(bytes).into_owned())
}

fn errbuf_to_string(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}
