export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface LinkStats {
  ssid: string | null;
  bssid: string | null;
  band: "2.4" | "5" | "6" | null;
  channel: number | null;
  channel_width_mhz: number | null;
  rssi_dbm: number | null;
  noise_dbm: number | null;
  snr_db: number | null;
  tx_rate_mbps: number | null;
  rx_rate_mbps: number | null;
  security: string | null;
  phy_mode?: string | null;
  wifi_generation?: string | null;
  vendor?: string | null;
}

export interface ReachabilityStats {
  gateway_ip: string | null;
  gateway_latency_ms: number | null;
  internet_latency_ms: number | null;
  dns_latency_ms: number | null;
  packet_loss_pct: number | null;
}

export interface DeviceInfo {
  mac: string;
  ip: string | null;
  hostname: string | null;
  vendor: string | null;
  class: DeviceClass;
  first_seen: string;
  last_seen: string;
  online: boolean;
  latency_ms: number | null;
  /** mDNS service types advertised by this device, e.g. ["_ipp._tcp", "_airplay._tcp"] */
  services: string[];
}

export type DeviceClass =
  | "pos_terminal"
  | "ip_camera"
  | "smart_home"
  | "printer"
  | "voice_assistant"
  | "thermostat"
  | "phone"
  | "laptop"
  | "tv_streamer"
  | "game_console"
  | "nas"
  | "router_ap"
  | "unknown";

export interface Finding {
  id: string;
  rule_id: string;
  title: string;
  severity: Severity;
  confidence: number;
  evidence: string[];
  affected_devices: string[];
  recommendation_id: string | null;
  observed_at: string;
}

export interface Recommendation {
  id: string;
  title: string;
  summary: string;
  steps: string[];
  links: { label: string; url: string }[];
  auto_fix_available: boolean;
}

export interface ServiceProbe {
  target: string;
  reachable: boolean;
  latency_ms: number | null;
  error: string | null;
}

export interface ScanResult {
  run_id: string;
  started_at: string;
  finished_at: string;
  link: LinkStats;
  reachability: ReachabilityStats;
  devices: DeviceInfo[];
  findings: Finding[];
  recommendations: Recommendation[];
  service_reachability: ServiceProbe[];
  /** True when a captive portal was detected during this scan. */
  captive_portal: boolean;
  dns_leak: boolean;
  mtu_bytes: number | null;
  nearby_aps: NearbyAp[];
  speed_mbps: number | null;
  quality?: QualityStats | null;
  interference?: InterferenceReport | null;
  phy_efficiency?: PhyEfficiency | null;
  roaming?: RoamingStats | null;
  rogue_aps?: RogueApFinding[];
  wan?: WanInfo | null;
  trends?: TrendReport | null;
  alternate_ap?: AlternateApSuggestion | null;
}

export interface NearbyAp {
  ssid: string | null;
  bssid: string | null;
  channel: number | null;
  band: string | null;
  rssi_dbm: number | null;
  security?: string | null;
  phy_mode?: string | null;
  width_mhz?: number | null;
  vendor?: string | null;
  /** True when the OS hid the SSID for privacy; `ssid` then carries a
   * synthesized "Network N" label so the entry stays distinguishable. */
  name_redacted?: boolean;
}

export interface QualityStats {
  dl_throughput_mbps: number | null;
  ul_throughput_mbps: number | null;
  responsiveness_rpm: number | null;
  idle_latency_ms: number | null;
  responsiveness_label: string | null;
}

export interface ChannelScore {
  channel: number;
  band: string;
  interference_score: number;
  co_channel_count: number;
  adjacent_channel_count: number;
  strongest_interferer_dbm: number | null;
}

export interface InterferenceReport {
  channels: ChannelScore[];
  recommended_24: number | null;
  recommended_5: number | null;
  current_channel_score: number | null;
}

export interface PhyEfficiency {
  phy_mode: string;
  theoretical_max_mbps: number;
  actual_mbps: number;
  efficiency: number;
  grade: string;
  diagnostic: string;
}

export interface RoamingEvent {
  at: string;
  ssid: string | null;
  from_bssid: string | null;
  to_bssid: string | null;
  rssi_at_roam_dbm: number | null;
}

export interface RoamingStats {
  events_last_hour: number;
  events_last_24h: number;
  avg_dwell_secs: number | null;
  sticky_warning: boolean;
  recent_events: RoamingEvent[];
}

export interface RogueApFinding {
  ssid: string;
  bssids: string[];
  security_modes: string[];
  reason: string;
  severity: Severity;
}

export interface WanInfo {
  public_ipv4: string | null;
  public_ipv6: string | null;
  asn: number | null;
  isp: string | null;
  country: string | null;
  region: string | null;
  dual_stack: boolean;
}

export interface TrendDelta {
  metric: string;
  label: string;
  current: number;
  prev_hour_avg: number;
  delta: number;
  /** "improved" | "stable" | "degraded" */
  direction: string;
}

export interface TrendReport {
  deltas: TrendDelta[];
  samples_considered: number;
}

export interface AlternateApSuggestion {
  ssid: string;
  current_bssid: string | null;
  current_rssi_dbm: number;
  alternate_bssid: string;
  alternate_rssi_dbm: number;
  alternate_channel: number | null;
  alternate_band: string | null;
  /** dB improvement (alternate − current). Positive means better. */
  improvement_db: number;
}

export interface ScanSummary {
  run_id: string;
  started_at: string;
  finished_at: string | null;
  findings_count: number;
  devices_online: number;
  devices_total: number;
  worst_severity: Severity | null;
}

export interface DeviceEvent {
  mac: string;
  occurred_at: string;
  event_type: "first_seen" | "online" | "offline" | string;
  details: string | null;
}

export interface MetricSample {
  metric: string;
  value: number;
  sampled_at: string;
  label: string | null;
}

export interface IncidentCorrelation {
  at: string;
  window_secs: number;
  metrics_before: MetricSample[];
  concurrent_events: DeviceEvent[];
}

/**
 * One tick of the live 1 Hz sampler. Mirrored 1:1 from
 * `crates/.../src/types.rs::LiveSample`. The backend emits these on the
 * `metric:tick` Tauri event and also exposes the most-recent 3600 (60 min)
 * via the `get_live_metrics` command for chart hydration on mount.
 */
export interface LiveSample {
  /** ISO 8601 timestamp (UTC) when the tick was sampled. */
  ts: string;
  rssi_dbm: number | null;
  snr_db: number | null;
  tx_rate_mbps: number | null;
  gateway_ms: number | null;
  internet_ms: number | null;
  dns_ms: number | null;
  link_up: boolean;
}

export interface Settings {
  scan_interval_secs: number;
  monitoring_enabled: boolean;
  notifications_enabled: boolean;
  notification_min_severity: Severity;
  llm_provider: string | null;
  llm_api_key: string | null;
  llm_model: string | null;
  llm_base_url: string | null;
  industry_profile: string;
  watchlist: string[];
  pos_targets: string[];
  onboarding_complete: boolean;
}

// ─── Wi-Fi system events (Play C) ────────────────────────────────────────

/** One classified Wi-Fi-subsystem event (macOS `log stream` source). */
export interface WifiEvent {
  id: string;
  ts: string;
  kind: string;
  subsystem: string;
  process: string | null;
  message: string;
  bssid: string | null;
  ssid: string | null;
  rssi_dbm: number | null;
}

// ─── Active stress tests (Play B) ────────────────────────────────────────

export interface StressSample {
  ts: string;
  offset_ms: number;
  latency_ms: number | null;
  success: boolean;
  label: string;
}

export interface StressStats {
  attempted: number;
  succeeded: number;
  failed: number;
  min_ms: number | null;
  avg_ms: number | null;
  max_ms: number | null;
  p95_ms: number | null;
  jitter_ms: number | null;
  loss_pct: number;
}

export interface StressTestResult {
  id: string;
  kind: string;
  label: string;
  started_at: string;
  finished_at: string;
  duration_ms: number;
  success: boolean;
  headline: string;
  details: string;
  stats: StressStats;
  samples: StressSample[];
}

export interface StressTestDescriptor {
  kind: string;
  label: string;
  description: string;
}

// ─── Causal narratives (Play D) ──────────────────────────────────────────

export interface Narrative {
  id: string;
  at: string;
  severity: string;
  trigger: string;
  headline: string;
  what_happened: string;
  likely_cause: string;
  what_to_try: string[];
  source: string;
  llm_summary: string | null;
}

// ─── LLM radio insights (Overview AI panel) ──────────────────────────────

export type RadioInsightSeverity = "info" | "warn" | "critical";

export interface RadioInsight {
  severity: RadioInsightSeverity;
  title: string;
  detail: string;
  /** Optional concrete suggestion. May be empty for pure-info items. */
  suggestion: string;
}

// =========================================================================
// AV-over-IP diagnostics (Dante / AES67 / multicast / PTP)
// =========================================================================

export interface DanteDevice {
  ip: string;
  hostname: string | null;
  model: string | null;
  manufacturer: string | null;
  services: string[];
  tx_channels: number | null;
  rx_channels: number | null;
  sample_rate_hz: number | null;
  latency_profile_ms: number | null;
  /** One of "none" | "primary_only" | "redundant". */
  redundancy: string;
  on_interface: string | null;
  control_ports_open: number[];
  on_wifi: boolean;
}

export interface MulticastGroup {
  iface: string;
  group: string;
  /** One of "dante_audio" | "ptp" | "mdns" | "ssdp" | "control" | "link_local" | "other". */
  purpose: string;
}

export interface InterfaceMulticast {
  iface: string;
  group_count: number;
  dante_audio_groups: number;
  ptp_groups: number;
  groups: MulticastGroup[];
}

export interface AvWarning {
  /** "info" | "warn" | "critical". */
  severity: string;
  /** "dante" | "multicast" | "ptp" | "wifi" | "qos" | "general". */
  category: string;
  message: string;
}

export interface IgmpQuerier {
  from: string;
  version: number;
  max_resp_ds: number;
  group: string;
}

export interface IgmpProbeResult {
  iface: string;
  listen_secs: number;
  queriers_seen: IgmpQuerier[];
  reports_seen: number;
  leaves_seen: number;
  /** "querier_present" | "no_querier_observed" | "silent" | "not_implemented" | "error". */
  verdict: string;
  error: string | null;
}

export interface DeepProbeResult {
  ran_at: string;
  igmp: IgmpProbeResult | null;
}

export interface AvDiagnosticsResult {
  generated_at: string;
  dante_devices: DanteDevice[];
  ddm_seen: boolean;
  aes67_seen: boolean;
  multicast: InterfaceMulticast[];
  warnings: AvWarning[];
  deep_probe: DeepProbeResult | null;
}

export interface AvInsight {
  severity: "info" | "warn" | "critical";
  category: "dante" | "multicast" | "ptp" | "wifi" | "qos" | "general";
  title: string;
  detail: string;
  suggestion: string;
}
