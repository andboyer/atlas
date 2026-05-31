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
}
