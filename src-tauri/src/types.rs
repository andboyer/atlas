use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceClass {
    PosTerminal,
    IpCamera,
    SmartHome,
    Printer,
    VoiceAssistant,
    Thermostat,
    Phone,
    Laptop,
    TvStreamer,
    GameConsole,
    Nas,
    RouterAp,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkStats {
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub band: Option<String>,
    pub channel: Option<u32>,
    pub channel_width_mhz: Option<u32>,
    pub rssi_dbm: Option<i32>,
    pub noise_dbm: Option<i32>,
    pub snr_db: Option<i32>,
    pub tx_rate_mbps: Option<f32>,
    pub rx_rate_mbps: Option<f32>,
    pub security: Option<String>,
    /// 802.11 PHY mode of the link (e.g. "802.11ax", "802.11ac", "802.11n").
    /// Used by the PHY-rate efficiency probe to compute the theoretical max.
    #[serde(default)]
    pub phy_mode: Option<String>,
    /// Wi-Fi generation label derived from phy_mode + band, e.g. "Wi-Fi 6E".
    #[serde(default)]
    pub wifi_generation: Option<String>,
    /// Vendor inferred from the BSSID's OUI prefix (e.g. "Apple", "Ubiquiti").
    #[serde(default)]
    pub vendor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachabilityStats {
    pub gateway_ip: Option<String>,
    pub gateway_latency_ms: Option<f32>,
    pub internet_latency_ms: Option<f32>,
    pub dns_latency_ms: Option<f32>,
    pub packet_loss_pct: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub mac: String,
    pub ip: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub class: DeviceClass,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub online: bool,
    pub latency_ms: Option<f32>,
    /// mDNS service types advertised by this device (e.g. "_ipp._tcp", "_airplay._tcp").
    #[serde(default)]
    pub services: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: f32,
    pub evidence: Vec<String>,
    pub affected_devices: Vec<String>,
    pub recommendation_id: Option<String>,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecommendationLink {
    pub label: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub id: String,
    pub title: String,
    pub summary: String,
    pub steps: Vec<String>,
    pub links: Vec<RecommendationLink>,
    pub auto_fix_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceProbe {
    pub target: String,
    pub reachable: bool,
    pub latency_ms: Option<f32>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub run_id: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub link: LinkStats,
    pub reachability: ReachabilityStats,
    pub devices: Vec<DeviceInfo>,
    pub findings: Vec<Finding>,
    pub recommendations: Vec<Recommendation>,
    #[serde(default)]
    pub service_reachability: Vec<ServiceProbe>,
    /// True when a captive portal was detected during this scan.
    #[serde(default)]
    pub captive_portal: bool,
    #[serde(default)]
    pub dns_leak: bool,
    #[serde(default)]
    pub mtu_bytes: Option<u32>,
    /// Nearby APs visible during this scan (used for interference analysis).
    #[serde(default)]
    pub nearby_aps: Vec<NearbyAp>,
    /// Measured download speed in Mbit/s (None if probe was skipped/failed).
    #[serde(default)]
    pub speed_mbps: Option<f32>,
    /// Bufferbloat / network quality (macOS `networkQuality` probe).
    #[serde(default)]
    pub quality: Option<QualityStats>,
    /// Per-channel interference scoring + recommended channels.
    #[serde(default)]
    pub interference: Option<InterferenceReport>,
    /// Theoretical max link rate vs actual negotiated rate.
    #[serde(default)]
    pub phy_efficiency: Option<PhyEfficiency>,
    /// Roaming summary from recent BSSID changes.
    #[serde(default)]
    pub roaming: Option<RoamingStats>,
    /// SSIDs flagged as potential evil-twin / rogue APs (same SSID, mixed security).
    #[serde(default)]
    pub rogue_aps: Vec<RogueApFinding>,
    /// WAN / ISP intelligence (public IP, ASN, geo, IPv6 status).
    #[serde(default)]
    pub wan: Option<WanInfo>,
    /// Trend deltas vs the previous hour.
    #[serde(default)]
    pub trends: Option<TrendReport>,
    /// Suggested alternate AP (stronger signal, same SSID).
    #[serde(default)]
    pub alternate_ap: Option<AlternateApSuggestion>,
}

/// A nearby WiFi access point visible during a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NearbyAp {
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub channel: Option<u32>,
    pub band: Option<String>,
    pub rssi_dbm: Option<i32>,
    /// Security mode advertised (e.g. "WPA2 Personal", "WPA3 Personal", "Open").
    #[serde(default)]
    pub security: Option<String>,
    /// 802.11 PHY mode (e.g. "802.11ax", "802.11ac", "802.11n").
    #[serde(default)]
    pub phy_mode: Option<String>,
    /// Channel width in MHz (20, 40, 80, 160).
    #[serde(default)]
    pub width_mhz: Option<u32>,
    /// Vendor inferred from the BSSID's OUI prefix (e.g. "Cisco Meraki").
    #[serde(default)]
    pub vendor: Option<String>,
    /// True when the OS hid the SSID for privacy (macOS Location Services gate,
    /// Windows location-toggle, etc.). When set, `ssid` carries a synthesized
    /// label like "Network 3" so the AP is still distinguishable in the UI.
    #[serde(default)]
    pub name_redacted: bool,
}

// ─── Quality / bufferbloat ───────────────────────────────────────────────────

/// Results from macOS `networkQuality`. RPM = Round-trips Per Minute, the
/// modern Apple/Cloudflare bufferbloat metric. Higher = better.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityStats {
    /// Downlink throughput in Mbit/s as measured by networkQuality.
    pub dl_throughput_mbps: Option<f32>,
    /// Uplink throughput in Mbit/s.
    pub ul_throughput_mbps: Option<f32>,
    /// Round-trips per minute under working conditions (higher = less bufferbloat).
    pub responsiveness_rpm: Option<u32>,
    /// Idle latency baseline in ms.
    pub idle_latency_ms: Option<f32>,
    /// Human label: "Low" / "Medium" / "High" responsiveness (mirrors Apple's UI).
    pub responsiveness_label: Option<String>,
}

// ─── Interference scoring ────────────────────────────────────────────────────

/// A per-channel interference score and the underlying contributors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelScore {
    pub channel: u32,
    pub band: String,
    /// Composite interference score 0-100; LOWER is better (less congestion).
    pub interference_score: f32,
    /// Number of co-channel APs (same channel).
    pub co_channel_count: u32,
    /// Number of adjacent-channel APs (overlapping but not same channel).
    pub adjacent_channel_count: u32,
    /// Strongest interferer's RSSI in dBm (most negative = quietest).
    pub strongest_interferer_dbm: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterferenceReport {
    /// All scored channels, sorted by ascending score (best first).
    pub channels: Vec<ChannelScore>,
    /// Recommended 2.4 GHz channel (best of 1, 6, 11).
    pub recommended_24: Option<u32>,
    /// Recommended 5 GHz channel (cleanest from observed APs).
    pub recommended_5: Option<u32>,
    /// Score of the current channel (None if no link channel known).
    pub current_channel_score: Option<f32>,
}

// ─── PHY-rate efficiency ─────────────────────────────────────────────────────

/// How close the negotiated TX rate is to the theoretical max for the
/// link's PHY mode + width + RSSI envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhyEfficiency {
    /// PHY mode used in the calculation (e.g. "802.11ax @ 80 MHz, 2 streams").
    pub phy_mode: String,
    /// Theoretical max Mbit/s for this PHY mode + width + assumed streams.
    pub theoretical_max_mbps: f32,
    /// Actual negotiated TX rate Mbit/s.
    pub actual_mbps: f32,
    /// Efficiency 0.0-1.0 (actual / theoretical).
    pub efficiency: f32,
    /// Human grade: "excellent" / "good" / "fair" / "poor".
    pub grade: String,
    /// Brief diagnostic — why is efficiency low if it is.
    pub diagnostic: String,
}

// ─── Roaming history ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoamingEvent {
    pub at: DateTime<Utc>,
    pub ssid: Option<String>,
    pub from_bssid: Option<String>,
    pub to_bssid: Option<String>,
    pub rssi_at_roam_dbm: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoamingStats {
    pub events_last_hour: u32,
    pub events_last_24h: u32,
    /// Average time between roams (seconds) over the last 24h, None if <2 events.
    pub avg_dwell_secs: Option<u32>,
    /// True if the link RSSI is weak (< -75 dBm) but no recent roam — sticky client.
    pub sticky_warning: bool,
    /// Recent events (most recent first), capped at 20.
    pub recent_events: Vec<RoamingEvent>,
}

// ─── Rogue / evil-twin AP detection ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RogueApFinding {
    pub ssid: String,
    /// BSSIDs seen advertising this SSID.
    pub bssids: Vec<String>,
    /// Security modes observed for this SSID (if >1 entry, that's the smoking gun).
    pub security_modes: Vec<String>,
    /// Reason this was flagged: "mixed_security" | "open_clone" | "many_bssids".
    pub reason: String,
    pub severity: Severity,
}

// ─── WAN / ISP intelligence ──────────────────────────────────────────────────

/// Public-facing WAN information about the local internet egress.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WanInfo {
    /// Public IPv4 address as seen from the internet (None if probe failed).
    pub public_ipv4: Option<String>,
    /// Public IPv6 address (None if no IPv6 connectivity).
    pub public_ipv6: Option<String>,
    /// Autonomous System Number, e.g. 7922 for Comcast.
    pub asn: Option<u32>,
    /// Human-readable ISP / network name.
    pub isp: Option<String>,
    /// ISO 3166-1 alpha-2 country code (e.g. "US").
    pub country: Option<String>,
    /// City + region (e.g. "Seattle, WA").
    pub region: Option<String>,
    /// True when both IPv4 and IPv6 connectivity were detected.
    pub dual_stack: bool,
}

// ─── Trend analysis ──────────────────────────────────────────────────────────

/// A single trended metric: current value vs the average over the previous
/// hour, plus a signed delta and a severity hint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendDelta {
    pub metric: String,
    pub label: String,
    pub current: f32,
    pub prev_hour_avg: f32,
    /// current - prev_hour_avg (signed in the metric's native units).
    pub delta: f32,
    /// "improved" | "stable" | "degraded".
    pub direction: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendReport {
    /// All trended metrics with non-trivial sample counts.
    pub deltas: Vec<TrendDelta>,
    /// Number of distinct sampling points used for the prev-hour averages.
    pub samples_considered: u32,
}

// ─── Alternate AP suggestion ─────────────────────────────────────────────────

/// When the connected AP has weak RSSI but a stronger AP on the same SSID
/// is visible nearby, we surface a suggestion to roam.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlternateApSuggestion {
    pub ssid: String,
    pub current_bssid: Option<String>,
    pub current_rssi_dbm: i32,
    pub alternate_bssid: String,
    pub alternate_rssi_dbm: i32,
    pub alternate_channel: Option<u32>,
    pub alternate_band: Option<String>,
    /// dB improvement (alternate - current). Positive means better.
    pub improvement_db: i32,
}

// ─── Live sampler ────────────────────────────────────────────────────────────

/// One tick of the high-frequency sampler that powers the rolling-60-min
/// charts. Emitted on the `metric:tick` Tauri event ~1 Hz, and stored in a
/// 3600-deep ring buffer accessible via `get_live_metrics`.
///
/// `rssi_dbm`/`snr_db`/`tx_rate_mbps` are sampled lazily by a separate slow
/// task (system_profiler on macOS takes ~13s) and carried forward on every
/// tick — they update visually every ~15s, while reachability values update
/// every second.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveSample {
    pub ts: DateTime<Utc>,
    pub rssi_dbm: Option<i32>,
    pub snr_db: Option<i32>,
    pub tx_rate_mbps: Option<f32>,
    pub gateway_ms: Option<f32>,
    pub internet_ms: Option<f32>,
    pub dns_ms: Option<f32>,
    pub link_up: bool,
}

// ─── Wi-Fi system events (macOS `log stream`) ───────────────────────────────

/// One classified Wi-Fi-subsystem event. Emitted on the `wifi:event` Tauri
/// event and persisted in a small (500-deep) ring buffer accessible via
/// `get_wifi_events`. On non-macOS platforms the producer is currently a
/// no-op so the ring stays empty.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiEvent {
    pub id: String,
    pub ts: DateTime<Utc>,
    /// Short classification: `roam`, `scan`, `assoc`, `disassoc`, `auth`,
    /// `deauth`, `power`, `kernel`, `other`.
    pub kind: String,
    pub subsystem: String,
    pub process: Option<String>,
    pub message: String,
    pub bssid: Option<String>,
    pub ssid: Option<String>,
    pub rssi_dbm: Option<i32>,
}

// ─── Active stress tests ──────────────────────────────────────────────────────

/// A single observation taken during a stress test (e.g. one ping reply).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StressSample {
    pub ts: DateTime<Utc>,
    /// Relative offset from test start in ms (handy for charting).
    pub offset_ms: u64,
    pub latency_ms: Option<f32>,
    pub success: bool,
    pub label: String,
}

/// Result of a single stress test invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StressTestResult {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub duration_ms: u64,
    pub success: bool,
    pub headline: String,
    pub details: Vec<String>,
    pub stats: StressStats,
    pub samples: Vec<StressSample>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StressStats {
    pub attempted: u32,
    pub succeeded: u32,
    pub failed: u32,
    pub min_ms: Option<f32>,
    pub avg_ms: Option<f32>,
    pub max_ms: Option<f32>,
    pub p95_ms: Option<f32>,
    pub jitter_ms: Option<f32>,
    pub loss_pct: Option<f32>,
}

// ─── Causal narratives (auto-explained anomalies) ───────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Narrative {
    pub id: String,
    pub at: DateTime<Utc>,
    /// `info`, `warn`, `critical`.
    pub severity: String,
    /// e.g. `latency_spike`, `link_drop`, `rssi_drop`, `dns_degraded`.
    pub trigger: String,
    pub headline: String,
    pub what_happened: String,
    pub likely_cause: String,
    pub what_to_try: Vec<String>,
    /// Always populated with deterministic heuristic text. Set to "llm" when
    /// an LLM also produced an enrichment (stored in `llm_summary`).
    pub source: String,
    pub llm_summary: Option<String>,
}

// ─── AV-over-IP diagnostics (Dante + multicast + PTP) ───────────────────────

/// One Dante endpoint discovered via mDNS, augmented with TCP reachability
/// to the well-known Dante control ports and (where possible) cross-referenced
/// against the last Wi-Fi scan so we can flag Dante endpoints riding Wi-Fi
/// (unsupported by Audinate).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DanteDevice {
    pub ip: String,
    pub hostname: Option<String>,
    /// Dante device model (from TXT `model=` or hostname suffix).
    pub model: Option<String>,
    /// Manufacturer string (from TXT `mf=`).
    pub manufacturer: Option<String>,
    /// All `_netaudio-*._udp` / `_ddm._tcp` / `_aes67._udp` service strings
    /// the device announced. Useful diagnostic of capability set.
    pub services: Vec<String>,
    /// Transmit channel capacity (from TXT `tx=`).
    pub tx_channels: Option<u32>,
    /// Receive channel capacity (from TXT `rx=`).
    pub rx_channels: Option<u32>,
    /// Operating sample rate (from TXT `sr=` or similar).
    pub sample_rate_hz: Option<u32>,
    /// Latency profile in milliseconds (0.25 / 0.5 / 1 / 2 / 5).
    pub latency_profile_ms: Option<f32>,
    /// `"none"` | `"primary_only"` | `"redundant"` — inferred from whether
    /// the same device announces on more than one IP / subnet.
    pub redundancy: String,
    /// Which local interface saw this device's mDNS announcement.
    pub on_interface: Option<String>,
    /// Subset of `[4440, 4444, 4455, 8800]` that accepted a TCP connect.
    pub control_ports_open: Vec<u16>,
    /// True if this device's IP falls inside the subnet of the currently
    /// associated Wi-Fi interface. Dante is officially unsupported on Wi-Fi.
    pub on_wifi: bool,
}

/// One multicast group joined on a specific local interface (parsed from
/// `netstat -gn`). `purpose` is a best-effort classification used to colour
/// the UI table and to feed the LLM prompt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MulticastGroup {
    pub iface: String,
    pub group: String,
    /// `"dante_audio"` | `"ptp"` | `"mdns"` | `"ssdp"` | `"control"` |
    /// `"link_local"` | `"other"`.
    pub purpose: String,
}

/// Per-interface multicast snapshot: every group joined plus quick counts
/// of the AV-relevant subsets (Dante audio in 239.69.x.x, PTP on the
/// well-known 224.0.1.129 / 224.0.0.107 addresses).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceMulticast {
    pub iface: String,
    pub group_count: u32,
    pub dante_audio_groups: u32,
    pub ptp_groups: u32,
    pub groups: Vec<MulticastGroup>,
}

/// Heuristic warning surfaced BEFORE the LLM runs — gives the user
/// something concrete even with no AI configured.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvWarning {
    pub severity: String, // "info" | "warn" | "critical"
    pub category: String, // "dante" | "ptp" | "multicast" | "wifi" | "qos"
    pub message: String,
}

/// Wrapper for results from any deep probe — privileged (IGMP querier
/// listen, DSCP audit, LLDP) or unprivileged (active PTP sampler, link
/// audit, SAP/SDP listener). All fields are optional because each probe
/// is independently opt-in. The privileged probes run via a re-exec of
/// the current binary under `osascript … administrator privileges`
/// (macOS) or `Start-Process -Verb RunAs` (Windows). The unprivileged
/// probes run in-process via `spawn_blocking`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeepProbeResult {
    pub ran_at: String,
    pub igmp: Option<IgmpProbeResult>,
    pub ptp: Option<PtpProbeResult>,
    pub dscp: Option<DscpProbeResult>,
    pub lldp: Option<LldpProbeResult>,
    pub link_audit: Option<LinkAuditResult>,
    pub sap: Option<SapProbeResult>,
}

/// Result of a passive listen on a raw IGMP socket. We listen rather than
/// query so that we cannot accidentally win the IGMP querier election.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IgmpProbeResult {
    pub iface: String,
    pub listen_secs: u32,
    pub queriers_seen: Vec<IgmpQuerier>,
    pub reports_seen: u32,
    pub leaves_seen: u32,
    /// `"querier_present"` | `"no_querier_observed"` | `"silent"` | `"error"`.
    pub verdict: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IgmpQuerier {
    pub from: String,
    pub version: u8,
    /// Max Response Time, deci-seconds (IGMPv2/v3 field).
    pub max_resp_ds: u32,
    pub group: String,
}

/// Result of the PTP active sampler. Joins the PTPv1 / PTPv2 multicast
/// groups on UDP 319 (event) and 320 (general) and parses Announce +
/// Sync messages to identify grandmasters, sync interval, and arrival
/// jitter. Unprivileged on every platform.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtpProbeResult {
    pub iface: String,
    pub listen_secs: u32,
    pub domains: Vec<PtpDomain>,
    pub grandmaster_count: u32,
    /// True if more than one grandmaster announced in the same domain
    /// during the listen window. Indicates an election storm — audio
    /// will glitch on every BMCA reshuffle.
    pub competing_gm_observed: bool,
    /// `"stable_gm"` | `"no_ptp"` | `"multiple_gms"` | `"jittery_sync"`
    /// | `"silent"` | `"error"`.
    pub verdict: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtpDomain {
    pub domain_number: u8,
    /// PTP version: 1 (IEEE 1588-2002) or 2 (IEEE 1588-2008).
    pub version: u8,
    /// `"default"` | `"media"` (SMPTE 2059-2 / AES67) | `"unknown"`.
    pub profile: String,
    pub grandmasters: Vec<PtpGrandmaster>,
    /// log2(announce interval seconds); typical values: 1 (2s, default)
    /// or -2 (250ms, media profile).
    pub announce_interval_log2: i8,
    /// log2(sync interval seconds); typical: 0 (1s) default, -3 (125ms) media.
    pub sync_interval_log2: i8,
    /// Total Sync messages observed during the listen window.
    pub sync_arrivals: u32,
    /// Stddev of inter-Sync arrival times in microseconds (only meaningful
    /// when sync_arrivals >= 3). Lower is better; >1000µs is a smoking
    /// gun for switch QoS issues.
    pub sync_jitter_us: Option<f32>,
    /// `"ipv4_multicast"` | `"ipv4_unicast"` | `"l2"`.
    pub transport: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtpGrandmaster {
    /// 8-byte EUI-64 clockIdentity, e.g. `"00:1d:c1:ff:fe:08:00:42"`.
    pub clock_identity: String,
    pub priority1: u8,
    pub priority2: u8,
    /// PTP clockClass: 6 = locked PRC, 7 = holdover, 187 = arb time scale,
    /// 248 = default, 255 = slave-only.
    pub clock_class: u8,
    pub clock_accuracy: u8,
    pub announces_seen: u32,
    pub source_ip: String,
}

/// Result of the DSCP / TTL audit probe. Opens a raw IPv4 socket
/// (privileged on all platforms) and reads the TOS + TTL byte from
/// every inbound PTP / Dante audio / AES67 audio packet, then reports
/// the median DSCP and TTL per stream class. The single most direct
/// way to verify "the switch is honouring QoS".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DscpProbeResult {
    pub iface: String,
    pub listen_secs: u32,
    pub observations: Vec<DscpObservation>,
    /// `"qos_preserved"` | `"qos_stripped"` | `"qos_mixed"` | `"silent"`
    /// | `"error"`.
    pub verdict: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DscpObservation {
    /// `"ptp_event"` | `"ptp_general"` | `"dante_audio"` | `"aes67_audio"`
    /// | `"rtp_other"`.
    pub stream_kind: String,
    pub dst_group: String,
    pub packets: u32,
    /// Observed median DSCP value (0..63). Should be 56 (CS7) for PTP,
    /// 46 (EF) for Dante audio, 34 (AF41) or 46 for AES67.
    pub dscp_median: u8,
    pub dscp_expected: u8,
    pub ttl_median: u8,
    pub ttl_min: u8,
}

/// Result of the LLDP / CDP listener (or ARP fallback). Identifies the
/// upstream switch model, port, VLAN, and capabilities. Critical for
/// pinpointing "which port am I plugged into".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LldpProbeResult {
    pub iface: String,
    pub listen_secs: u32,
    pub neighbors: Vec<LldpNeighbor>,
    /// `"l2_capture"` (BPF/AF_PACKET; full LLDP/CDP TLV parse) |
    /// `"arp_oui_fallback"` (Windows: ARP + OUI lookup; no LLDP TLVs) |
    /// `"none"`.
    pub mechanism: String,
    /// `"switch_identified"` | `"neighbors_only"` | `"silent"`
    /// | `"not_supported"` | `"error"`.
    pub verdict: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LldpNeighbor {
    pub source_mac: String,
    pub source_ip: Option<String>,
    /// `"lldp"` | `"cdp"` | `"arp"`.
    pub via: String,
    pub chassis_id: Option<String>,
    pub port_id: Option<String>,
    pub port_description: Option<String>,
    pub system_name: Option<String>,
    pub system_description: Option<String>,
    pub vlan_id: Option<u16>,
    pub oui_vendor: Option<String>,
    /// LLDP system capabilities subset: `"bridge"`, `"router"`,
    /// `"wlan"`, `"phone"`, `"docsis"`, `"station"`, `"stp"`, `"other"`.
    pub capabilities: Vec<String>,
}

/// Result of the per-NIC link audit (EEE / flow-control / duplex / speed
/// / MTU). Read via OS-specific APIs:
///   - macOS: `ifconfig <iface>` for media, `system_profiler SPNetworkDataType`
///     for full duplex / MTU. EEE state isn't always queryable.
///   - Linux: `ethtool <iface>` + `ethtool --show-eee <iface>`.
///   - Windows: `Get-NetAdapter` + `Get-NetAdapterAdvancedProperty`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkAuditResult {
    pub iface: String,
    pub link_speed_mbps: Option<u32>,
    /// `"full"` | `"half"` | `"unknown"`.
    pub duplex: Option<String>,
    /// `None` when this platform doesn't expose EEE state on the NIC.
    pub eee_enabled: Option<bool>,
    pub flow_control_rx: Option<bool>,
    pub flow_control_tx: Option<bool>,
    pub mtu: Option<u32>,
    /// `"ready_for_av"` | `"needs_attention"` | `"unknown"` | `"error"`.
    pub verdict: String,
    /// Human-readable list of specific issues found (e.g. "EEE enabled",
    /// "Half-duplex link", "Sub-gigabit link 100 Mb/s").
    pub issues: Vec<String>,
    pub error: Option<String>,
}

/// Result of the SAP/SDP listener. AES67 senders advertise themselves
/// via Session Announcement Protocol on 224.2.127.254:9875 with an SDP
/// payload describing each multicast stream's group, port, sample rate,
/// channel count, and ptime. Unprivileged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SapProbeResult {
    pub iface: String,
    pub listen_secs: u32,
    pub streams: Vec<SapStream>,
    /// `"streams_found"` | `"silent"` | `"error"`.
    pub verdict: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SapStream {
    /// SDP `o=` field (origin).
    pub origin: String,
    /// SDP `s=` field (session name).
    pub session_name: String,
    pub multicast_group: Option<String>,
    pub port: Option<u16>,
    pub sample_rate_hz: Option<u32>,
    pub channels: Option<u8>,
    pub payload_type: Option<u8>,
    pub ptime_ms: Option<f32>,
    pub source_ip: String,
}

/// Top-level AV diagnostics payload returned by `run_av_diagnostics`. The
/// LLM-driven `av_insights` command takes this as its sole context input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvDiagnosticsResult {
    pub generated_at: DateTime<Utc>,
    pub dante_devices: Vec<DanteDevice>,
    pub ddm_seen: bool,
    pub aes67_seen: bool,
    pub multicast: Vec<InterfaceMulticast>,
    pub warnings: Vec<AvWarning>,
    pub deep_probe: Option<DeepProbeResult>,
}
