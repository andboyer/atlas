export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type UserMode = "simple" | "pro" | "admin";

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
}

export interface NearbyAp {
  ssid: string | null;
  bssid: string | null;
  channel: number | null;
  band: string | null;
  rssi_dbm: number | null;
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
}
