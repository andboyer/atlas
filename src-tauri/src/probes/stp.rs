//! Passive Spanning-Tree (STP/RSTP/MSTP/PVST+) listener and L2 loop detector.
//!
//! A switching loop and an unstable spanning tree are two of the most
//! disruptive — and hardest to pin down — faults on an AV / LAN segment: they
//! manifest as random dropouts, devices "falling off", and saturated links.
//! From a single host's NIC we can passively gather strong evidence without
//! ever transmitting a frame (so we can't make a storm worse):
//!
//!   * **STP BPDUs** (dst MAC `01:80:C2:00:00:00`, or Cisco PVST+
//!     `01:00:0C:CC:CC:CD`) tell us the spanning-tree version, the root
//!     bridge(s), and — via the Topology-Change flag / TCN BPDUs — how often
//!     the tree is re-converging. Frequent topology changes, multiple root
//!     bridges, or legacy 802.1D STP (30–50 s convergence) are all findings.
//!   * **Broadcast rate** — a sustained flood of broadcast frames is the
//!     classic signature of an active L2 loop.
//!   * **Duplicate frames** — a loop replays the *same* frame within
//!     milliseconds; a high duplicate ratio is a direct loop fingerprint.
//!
//! ## Important caveat
//! Most managed switches do **not** forward BPDUs out edge/access ports
//! (PortFast + BPDU Guard), so a host plugged into an access port may see
//! **zero** BPDUs on a perfectly healthy network. "No BPDUs observed" is
//! therefore reported as *inconclusive*, not "STP disabled"; the loop signals
//! (broadcast rate, duplicates) remain valid on any port.
//!
//! ## Capture mechanism
//!   * **macOS** — `/dev/bpf` with a kernel filter accepting only
//!     multicast/broadcast frames (the group bit), root-gated.
//!   * **Windows** — Npcap (`wpcap.dll`) via [`crate::probes::npcap`].
//!   * **Linux/other** — not implemented (datalink capture would need
//!     AF_PACKET); returns verdict `not_supported`.

use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
use std::ffi::CString;
#[cfg(target_os = "macos")]
use std::io::ErrorKind;
#[cfg(target_os = "windows")]
use std::net::Ipv4Addr;

#[cfg(target_os = "windows")]
use crate::probes::iface as iface_probe;
use crate::types::{StpProbeResult, StpRootBridge};

/// Spanning-tree reserved bridge-group address — STP/RSTP/MSTP BPDUs.
const MAC_STP: [u8; 6] = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x00];
/// Cisco Per-VLAN Spanning Tree Plus (PVST+/Rapid-PVST+) BPDU address.
const MAC_PVST: [u8; 6] = [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcd];
/// Ethernet broadcast.
const MAC_BROADCAST: [u8; 6] = [0xff; 6];

/// Peak broadcast frames/second above which we suspect an L2 loop. A healthy
/// segment sits in the low tens of broadcasts/s; a loop drives this into the
/// hundreds-to-thousands almost immediately.
const STORM_PPS: f32 = 800.0;
/// Fraction of captured frames that are byte-identical replays (within
/// `DUP_WINDOW`) above which we suspect a loop.
const DUP_RATIO_LOOP: f32 = 0.20;
/// Two identical frames closer together than this are treated as a loop
/// replay rather than legitimate retransmission.
const DUP_WINDOW: Duration = Duration::from_millis(50);
/// Topology-change events within the listen window above which the tree is
/// considered unstable (a flapping link or forming/breaking loop).
const TC_UNSTABLE: u32 = 5;

/// Synchronous blocking entrypoint — call from `tokio::task::spawn_blocking`.
pub fn run_blocking(iface: &str, listen_secs: u32) -> StpProbeResult {
    let mut acc = Acc::new();
    let captured = capture(iface, listen_secs, |frame| acc.on_frame(frame));
    let mut result = acc.finish(iface, listen_secs);

    if let Err(e) = captured {
        // anyhow's plain Display shows only the outermost context (e.g.
        // "open /dev/bpf"); the `:#` alternate form appends the source chain
        // ("…: Permission denied (os error 13)") so the EACCES/EPERM checks
        // below actually match an unprivileged capture and surface the
        // friendly "needs admin" nudge instead of a raw error.
        let msg = format!("{e:#}");
        let lower = msg.to_lowercase();
        if lower.contains("not supported") {
            result.verdict = "not_supported".to_string();
            result.detail = Some(
                "L2 capture for STP/loop detection isn't implemented on this platform yet."
                    .to_string(),
            );
        } else if lower.contains("npcap") {
            result.verdict = "silent".to_string();
            result.detail = Some(
                "Install Npcap (the WinPcap-compatible capture driver) to enable STP / loop detection."
                    .to_string(),
            );
        } else if result.frames_seen == 0
            && (lower.contains("permission denied")
                || lower.contains("operation not permitted")
                || lower.contains("os error 13")
                || lower.contains("os error 1"))
        {
            result.verdict = "silent".to_string();
            result.detail = Some(
                "Raw L2 capture needs administrator privileges — run the STP / loop test to grant it."
                    .to_string(),
            );
        } else if result.frames_seen == 0 {
            result.verdict = "error".to_string();
            result.error = Some(msg);
        }
    }

    result
}

// ─── capture (per-OS) ────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn capture<F: FnMut(&[u8])>(iface: &str, listen_secs: u32, on_frame: F) -> anyhow::Result<()> {
    capture_bpf(iface, listen_secs, on_frame)
}

#[cfg(target_os = "windows")]
fn capture<F: FnMut(&[u8])>(iface: &str, listen_secs: u32, on_frame: F) -> anyhow::Result<()> {
    let iface_ipv4 = iface_probe::find_by_name(iface)
        .and_then(|i| i.ipv4)
        .and_then(|s| s.parse::<Ipv4Addr>().ok());
    // libpcap `ether multicast` matches every frame with the group bit set,
    // which includes broadcast — exactly the BPDU + broadcast-storm traffic
    // we want, while skipping unicast.
    crate::probes::npcap::capture_l2(iface_ipv4, "ether multicast", listen_secs, on_frame)
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn capture<F: FnMut(&[u8])>(_iface: &str, _listen_secs: u32, _on_frame: F) -> anyhow::Result<()> {
    anyhow::bail!("stp probe not supported on this platform")
}

// ─── accumulator ─────────────────────────────────────────────────────────

struct RootAcc {
    priority: u16,
    mac: [u8; 6],
    root_path_cost: u32,
    version: u8,
    is_pvst: bool,
    announces: u32,
}

struct Acc {
    start: Instant,
    frames: u32,
    bpdus: u32,
    topology_changes: u32,
    /// elapsed-second bucket → (broadcast count, multicast count).
    per_sec: HashMap<u64, (u32, u32)>,
    /// Rolling window of recent frame hashes for duplicate detection.
    recent: VecDeque<(Instant, u64)>,
    duplicates: u32,
    roots: BTreeMap<(u16, [u8; 6]), RootAcc>,
    versions: BTreeSet<u8>,
    saw_pvst: bool,
}

impl Acc {
    fn new() -> Self {
        Acc {
            start: Instant::now(),
            frames: 0,
            bpdus: 0,
            topology_changes: 0,
            per_sec: HashMap::new(),
            recent: VecDeque::new(),
            duplicates: 0,
            roots: BTreeMap::new(),
            versions: BTreeSet::new(),
            saw_pvst: false,
        }
    }

    fn on_frame(&mut self, frame: &[u8]) {
        if frame.len() < 14 {
            return;
        }
        self.frames += 1;
        let now = Instant::now();
        let sec = now.duration_since(self.start).as_secs();

        // Duplicate detection: a loop replays the identical frame within a few
        // milliseconds. Hash the (snaplen-truncated) frame and look for the
        // same hash inside the rolling window.
        let mut hasher = DefaultHasher::new();
        frame.hash(&mut hasher);
        let hv = hasher.finish();
        while let Some(&(t, _)) = self.recent.front() {
            if now.duration_since(t) > DUP_WINDOW {
                self.recent.pop_front();
            } else {
                break;
            }
        }
        if self.recent.iter().any(|&(_, h)| h == hv) {
            self.duplicates += 1;
        }
        self.recent.push_back((now, hv));

        // Per-second broadcast / multicast tallies for peak-rate reporting.
        let bucket = self.per_sec.entry(sec).or_insert((0, 0));
        if dst_is(frame, MAC_BROADCAST) {
            bucket.0 += 1;
        } else if frame[0] & 0x01 != 0 {
            bucket.1 += 1;
        }

        if let Some(bpdu) = parse_bpdu(frame) {
            self.bpdus += 1;
            if bpdu.is_tcn || bpdu.tc_flag {
                self.topology_changes += 1;
            }
            if bpdu.is_pvst {
                self.saw_pvst = true;
            } else {
                self.versions.insert(bpdu.version);
            }
            if !bpdu.is_tcn {
                let entry = self
                    .roots
                    .entry((bpdu.root_priority, bpdu.root_mac))
                    .or_insert(RootAcc {
                        priority: bpdu.root_priority,
                        mac: bpdu.root_mac,
                        root_path_cost: bpdu.root_path_cost,
                        version: bpdu.version,
                        is_pvst: bpdu.is_pvst,
                        announces: 0,
                    });
                entry.announces += 1;
                entry.root_path_cost = bpdu.root_path_cost;
            }
        }
    }

    fn finish(&self, iface: &str, listen_secs: u32) -> StpProbeResult {
        let (bcast_peak, mcast_peak) = self
            .per_sec
            .values()
            .fold((0u32, 0u32), |(b, m), &(bb, mm)| (b.max(bb), m.max(mm)));
        let dup_ratio = if self.frames > 0 {
            self.duplicates as f32 / self.frames as f32
        } else {
            0.0
        };

        let root_bridges: Vec<StpRootBridge> = self
            .roots
            .values()
            .map(|r| StpRootBridge {
                bridge_id: format!("{}.{}", r.priority, mac_str(&r.mac)),
                priority: r.priority,
                mac: mac_str(&r.mac),
                root_path_cost: r.root_path_cost,
                version: version_label(r.version, r.is_pvst).to_string(),
                announces_seen: r.announces,
            })
            .collect();

        let stp_version = self.version_summary();
        let legacy = self.versions.contains(&0);
        let verdict = compute_verdict(
            self.frames,
            self.bpdus,
            self.topology_changes,
            bcast_peak as f32,
            dup_ratio,
            root_bridges.len(),
            legacy,
        );
        let detail = Some(build_detail(
            &verdict,
            listen_secs,
            self.topology_changes,
            bcast_peak,
            dup_ratio,
            &root_bridges,
            stp_version.as_deref(),
        ));

        StpProbeResult {
            iface: iface.to_string(),
            listen_secs,
            frames_seen: self.frames,
            bpdus_seen: self.bpdus,
            topology_changes: self.topology_changes,
            broadcast_pps_peak: bcast_peak as f32,
            multicast_pps_peak: mcast_peak as f32,
            duplicate_frame_ratio: dup_ratio,
            stp_version,
            root_bridges,
            verdict,
            detail,
            error: None,
        }
    }

    fn version_summary(&self) -> Option<String> {
        let mut parts: Vec<String> = self
            .versions
            .iter()
            .map(|v| version_label(*v, false).to_string())
            .collect();
        if self.saw_pvst {
            parts.push("pvst+".to_string());
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join(" / "))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn compute_verdict(
    frames: u32,
    bpdus: u32,
    topology_changes: u32,
    bcast_peak: f32,
    dup_ratio: f32,
    root_count: usize,
    legacy: bool,
) -> String {
    if frames == 0 {
        "silent"
    } else if bcast_peak >= STORM_PPS || dup_ratio >= DUP_RATIO_LOOP {
        "loop_suspected"
    } else if topology_changes >= TC_UNSTABLE {
        "topology_unstable"
    } else if root_count > 1 {
        "multiple_roots"
    } else if bpdus > 0 && legacy {
        "legacy_stp"
    } else if bpdus > 0 {
        "stp_healthy"
    } else {
        "no_bpdus_observed"
    }
    .to_string()
}

fn build_detail(
    verdict: &str,
    listen_secs: u32,
    topology_changes: u32,
    bcast_peak: u32,
    dup_ratio: f32,
    roots: &[StpRootBridge],
    stp_version: Option<&str>,
) -> String {
    let dup_pct = (dup_ratio * 100.0).round() as u32;
    match verdict {
        "loop_suspected" => format!(
            "Possible L2 loop: peak {bcast_peak} broadcast frames/s and {dup_pct}% duplicate frames. \
             Check for a cabling loop or a port that should be blocking but isn't."
        ),
        "topology_unstable" => format!(
            "{topology_changes} spanning-tree topology changes in {listen_secs}s — a flapping link \
             or intermittent loop is forcing constant re-convergence (expect brief dropouts)."
        ),
        "multiple_roots" => format!(
            "{} distinct STP root bridges seen on this segment — likely two spanning-tree domains \
             bridged together, or a misconfigured root.",
            roots.len()
        ),
        "legacy_stp" => {
            let root = roots.first().map(|r| r.bridge_id.as_str()).unwrap_or("?");
            format!(
                "Legacy 802.1D STP detected (root {root}); 30–50 s convergence will drop AV streams \
                 on any topology change. Move to RSTP/MSTP."
            )
        }
        "stp_healthy" => {
            let root = roots.first().map(|r| r.bridge_id.as_str()).unwrap_or("?");
            format!(
                "Spanning tree healthy: {} root {root}, {topology_changes} topology change(s) in {listen_secs}s.",
                stp_version.unwrap_or("STP")
            )
        }
        "no_bpdus_observed" => format!(
            "No BPDUs seen in {listen_secs}s. Edge ports with BPDU Guard/PortFast don't forward them, \
             so this is inconclusive for STP. Broadcast peak was {bcast_peak}/s."
        ),
        "silent" => "No multicast or broadcast frames captured on this interface.".to_string(),
        "not_supported" => {
            "STP / loop capture isn't available on this platform.".to_string()
        }
        _ => "STP / loop probe completed.".to_string(),
    }
}

// ─── BPDU parsing ────────────────────────────────────────────────────────

struct Bpdu {
    version: u8,
    is_tcn: bool,
    tc_flag: bool,
    root_priority: u16,
    root_mac: [u8; 6],
    root_path_cost: u32,
    is_pvst: bool,
}

/// True if the frame's destination MAC equals `mac`.
fn dst_is(frame: &[u8], mac: [u8; 6]) -> bool {
    frame.len() >= 6 && frame[0..6] == mac
}

/// Parse an STP/RSTP/MSTP (LLC) or PVST+ (SNAP) BPDU out of an Ethernet
/// frame. Handles a single optional 802.1Q VLAN tag. Returns `None` for any
/// frame that isn't a BPDU to a spanning-tree group address.
fn parse_bpdu(frame: &[u8]) -> Option<Bpdu> {
    let is_stp = dst_is(frame, MAC_STP);
    let is_pvst = dst_is(frame, MAC_PVST);
    if !is_stp && !is_pvst {
        return None;
    }
    // Skip a single 802.1Q tag if present; `off` lands on the length/type
    // field, so the LLC header begins two bytes later.
    let mut off = 12usize;
    if frame.len() >= 14 && frame[12] == 0x81 && frame[13] == 0x00 {
        off = 16;
    }
    let llc = off + 2;
    if frame.len() < llc + 3 {
        return None;
    }
    let bpdu_off = if frame[llc] == 0x42 && frame[llc + 1] == 0x42 {
        // 802.2 LLC: DSAP=SSAP=0x42, control(1) → BPDU follows.
        llc + 3
    } else if frame[llc] == 0xaa && frame[llc + 1] == 0xaa {
        // SNAP: control(1) + OUI(3) + PID(2) → BPDU follows (PVST+).
        llc + 8
    } else {
        return None;
    };
    parse_bpdu_body(frame.get(bpdu_off..)?, is_pvst)
}

fn parse_bpdu_body(b: &[u8], is_pvst: bool) -> Option<Bpdu> {
    // Protocol Identifier (2) must be 0x0000; then version(1), type(1).
    if b.len() < 4 || b[0] != 0 || b[1] != 0 {
        return None;
    }
    let version = b[2];
    let bpdu_type = b[3];

    // 0x80 = Topology Change Notification (no body).
    if bpdu_type == 0x80 {
        return Some(Bpdu {
            version,
            is_tcn: true,
            tc_flag: true,
            root_priority: 0,
            root_mac: [0; 6],
            root_path_cost: 0,
            is_pvst,
        });
    }
    // 0x00 = Configuration (STP), 0x02 = RST/MST BPDU. Anything else isn't one.
    if bpdu_type != 0x00 && bpdu_type != 0x02 {
        return None;
    }
    // flags(1) + root id (priority 2 + MAC 6) + root path cost(4) = need 17 bytes.
    if b.len() < 17 {
        return None;
    }
    let tc_flag = b[4] & 0x01 != 0;
    let root_priority = u16::from_be_bytes([b[5], b[6]]);
    let mut root_mac = [0u8; 6];
    root_mac.copy_from_slice(&b[7..13]);
    let root_path_cost = u32::from_be_bytes([b[13], b[14], b[15], b[16]]);
    Some(Bpdu {
        version,
        is_tcn: false,
        tc_flag,
        root_priority,
        root_mac,
        root_path_cost,
        is_pvst,
    })
}

fn version_label(version: u8, is_pvst: bool) -> &'static str {
    if is_pvst {
        return "pvst+";
    }
    match version {
        0 => "stp",
        2 => "rstp",
        3 => "mstp",
        _ => "unknown",
    }
}

fn mac_str(m: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

// ─── macOS BPF capture ───────────────────────────────────────────────────

/// Capture multicast/broadcast frames via `/dev/bpf` and hand each one to
/// `on_frame`. Requires root (open of `/dev/bpf*`), so an unprivileged call
/// returns an `EACCES`/`EPERM` error that `run_blocking` maps to a friendly
/// "needs admin" verdict.
#[cfg(target_os = "macos")]
fn capture_bpf<F: FnMut(&[u8])>(
    iface: &str,
    listen_secs: u32,
    mut on_frame: F,
) -> anyhow::Result<()> {
    use anyhow::Context;

    // BPF ioctls (<net/bpf.h>), group 'B' (0x42), BSD _IOR/_IOW encoding.
    const BIOCGBLEN: libc::c_ulong = 0x4004_4266; // _IOR('B',102,u_int)
    const BIOCSETIF: libc::c_ulong = 0x8020_426c; // _IOW('B',108,struct ifreq)
    const BIOCIMMEDIATE: libc::c_ulong = 0x8004_4270; // _IOW('B',112,u_int)
    const BIOCSETF: libc::c_ulong = 0x8010_4267; // _IOW('B',103,struct bpf_program)

    let fd = open_bpf().context("open /dev/bpf")?;
    let _guard = BpfFd(fd);

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

    let one: libc::c_uint = 1;
    if unsafe { libc::ioctl(fd, BIOCIMMEDIATE, &one) } < 0 {
        return Err(std::io::Error::last_os_error()).context("BIOCIMMEDIATE");
    }

    install_group_filter(fd, BIOCSETF)?;

    let mut blen: libc::c_uint = 0;
    if unsafe { libc::ioctl(fd, BIOCGBLEN, &mut blen) } < 0 {
        return Err(std::io::Error::last_os_error()).context("BIOCGBLEN");
    }
    let blen = if blen == 0 { 4096 } else { blen as usize };
    let mut buf = vec![0u8; blen];

    let deadline = Instant::now() + Duration::from_secs(listen_secs as u64);
    while Instant::now() < deadline {
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
            on_frame(&buf[start..end]);
            p += (hdrlen + caplen + 3) & !3;
        }
    }
    Ok(())
}

/// Open the first available BPF device. Root-gated on stock macOS.
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
        last = err;
    }
    Err(last)
}

/// Install a classic-BPF program accepting only frames whose destination MAC
/// has the group (multicast/broadcast) bit set — BPDUs + broadcast traffic,
/// skipping unicast. Snaplen capped at 256 bytes (enough for the BPDU header).
#[cfg(target_os = "macos")]
fn install_group_filter(fd: libc::c_int, biocsetf: libc::c_ulong) -> std::io::Result<()> {
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
    //   ldb [0]            ; first octet of destination MAC
    //   and #1            ; isolate the group (multicast/broadcast) bit
    //   jeq #0, +0, +1    ; unicast? reject : accept
    //   ret #0            ; REJECT
    //   ret #256          ; ACCEPT (snaplen 256)
    let prog = [
        BpfInsn {
            code: 0x30,
            jt: 0,
            jf: 0,
            k: 0,
        },
        BpfInsn {
            code: 0x54,
            jt: 0,
            jf: 0,
            k: 1,
        },
        BpfInsn {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: 0,
        },
        BpfInsn {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0,
        },
        BpfInsn {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 256,
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

    fn eth_llc_bpdu(dst: [u8; 6], body: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&dst); // dst MAC
        f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // src MAC
        f.extend_from_slice(&[0x00, 0x26]); // 802.3 length
        f.extend_from_slice(&[0x42, 0x42, 0x03]); // LLC DSAP/SSAP/control
        f.extend_from_slice(body);
        f
    }

    fn config_body(version: u8, bpdu_type: u8, flags: u8, prio: u16, mac: [u8; 6]) -> Vec<u8> {
        let mut b = vec![0x00, 0x00, version, bpdu_type, flags];
        b.extend_from_slice(&prio.to_be_bytes());
        b.extend_from_slice(&mac);
        b.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]); // root path cost
        b.extend_from_slice(&[0u8; 18]); // bridge id + port + timers (unused)
        b
    }

    #[test]
    fn parses_config_bpdu() {
        let mac = [0x00, 0x1d, 0xc1, 0x08, 0x00, 0x42];
        let frame = eth_llc_bpdu(MAC_STP, &config_body(0x00, 0x00, 0x00, 0x8000, mac));
        let bpdu = parse_bpdu(&frame).expect("config bpdu");
        assert!(!bpdu.is_tcn);
        assert_eq!(bpdu.version, 0);
        assert_eq!(bpdu.root_priority, 0x8000);
        assert_eq!(bpdu.root_mac, mac);
        assert_eq!(bpdu.root_path_cost, 4);
        assert!(!bpdu.is_pvst);
    }

    #[test]
    fn detects_topology_change_flag() {
        let frame = eth_llc_bpdu(MAC_STP, &config_body(0x02, 0x02, 0x01, 0x1000, [0xaa; 6]));
        let bpdu = parse_bpdu(&frame).expect("rstp bpdu");
        assert_eq!(bpdu.version, 2); // RSTP
        assert!(bpdu.tc_flag);
    }

    #[test]
    fn parses_tcn() {
        let frame = eth_llc_bpdu(MAC_STP, &[0x00, 0x00, 0x00, 0x80]);
        let bpdu = parse_bpdu(&frame).expect("tcn");
        assert!(bpdu.is_tcn);
        assert!(bpdu.tc_flag);
    }

    #[test]
    fn parses_pvst_snap_tagged() {
        // dst PVST, src, 802.1Q tag, length, SNAP, then BPDU body.
        let mut f = Vec::new();
        f.extend_from_slice(&MAC_PVST);
        f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        f.extend_from_slice(&[0x81, 0x00, 0x00, 0x0a]); // 802.1Q tag, VLAN 10
        f.extend_from_slice(&[0x00, 0x32]); // length
        f.extend_from_slice(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x01, 0x0b]); // SNAP
        f.extend_from_slice(&config_body(0x00, 0x00, 0x00, 0x7001, [0xbb; 6]));
        let bpdu = parse_bpdu(&f).expect("pvst bpdu");
        assert!(bpdu.is_pvst);
        assert_eq!(bpdu.root_priority, 0x7001);
    }

    #[test]
    fn rejects_non_bpdu_multicast() {
        // IPv4 multicast frame (dst 01:00:5e:..) is not a BPDU.
        let mut f = Vec::new();
        f.extend_from_slice(&[0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb]);
        f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        f.extend_from_slice(&[0x08, 0x00]); // IPv4 ethertype
        f.extend_from_slice(&[0u8; 40]);
        assert!(parse_bpdu(&f).is_none());
    }

    #[test]
    fn verdict_prioritises_loop_over_topology() {
        // High broadcast rate AND many topology changes → loop wins.
        let v = compute_verdict(10_000, 5, 20, 1500.0, 0.4, 1, false);
        assert_eq!(v, "loop_suspected");
    }

    #[test]
    fn verdict_legacy_stp() {
        let v = compute_verdict(50, 10, 0, 5.0, 0.0, 1, true);
        assert_eq!(v, "legacy_stp");
    }

    #[test]
    fn verdict_no_bpdus_is_inconclusive() {
        let v = compute_verdict(40, 0, 0, 5.0, 0.0, 0, false);
        assert_eq!(v, "no_bpdus_observed");
    }
}
