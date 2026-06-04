use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Application settings, stored as JSON in the app data directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// How often to run a background scan (seconds). 0 = monitoring disabled.
    pub scan_interval_secs: u64,
    /// Whether background monitoring is active.
    pub monitoring_enabled: bool,
    /// Whether to show OS notifications when findings are detected.
    pub notifications_enabled: bool,
    /// Minimum severity level to send a notification: "info", "low", "medium", "high", "critical".
    pub notification_min_severity: String,

    /// LLM provider: "openai", "anthropic", or "ollama".
    pub llm_provider: Option<String>,
    /// API key for the selected provider.
    pub llm_api_key: Option<String>,
    /// Model name, e.g. "gpt-4o-mini", "claude-3-haiku-20240307", "llama3".
    pub llm_model: Option<String>,
    /// Base URL override — required for Ollama (e.g. "http://localhost:11434").
    pub llm_base_url: Option<String>,

    /// Industry profile id: "retail_pos", "smart_home", "office", or "home".
    pub industry_profile: String,
    /// MAC addresses of devices the user has pinned for high-priority alerting.
    pub watchlist: Vec<String>,
    /// `host:port` strings to probe for SaaS / payment-processor reachability.
    pub pos_targets: Vec<String>,
    /// True after the user has completed the first-run onboarding wizard.
    #[serde(default)]
    pub onboarding_complete: bool,

    /// Kernel name of the NIC that diagnostic probes should pin to
    /// (`en0`, `en4`, …). Empty / unset means "let the kernel pick" — the
    /// previous behaviour. Used by AV-over-IP (mDNS browse, multicast
    /// snapshot, link audit), the privileged deep probes (IGMP, PTP,
    /// LLDP, SAP, DSCP), and `traceroute`. Wi-Fi-radio-bound probes
    /// (channel map, RSSI sampling) always use the Wi-Fi adapter
    /// regardless of this setting because that's the only NIC they can
    /// physically read.
    ///
    /// `alias` keeps the historical key (`preferred_av_interface`) so
    /// users who upgrade from <= v0.1.11 don't lose their pin.
    #[serde(default, alias = "preferred_av_interface")]
    pub preferred_interface: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            // Live-scanning default: a fresh scan every 15 s when monitoring is
            // running. Each probe self-bounds at 20 s and the join budget is 45 s,
            // so this gives the user near-real-time updates without overlapping
            // runs. Operators can tune this in Settings.
            scan_interval_secs: 15,
            // Monitoring auto-starts on first launch; the UI surfaces a Pause
            // button so the user can stop it at any time.
            monitoring_enabled: true,
            notifications_enabled: true,
            notification_min_severity: "medium".to_string(),
            llm_provider: None,
            llm_api_key: None,
            llm_model: None,
            llm_base_url: None,
            industry_profile: "home".to_string(),
            watchlist: vec![],
            pos_targets: vec![],
            onboarding_complete: false,
            preferred_interface: String::new(),
        }
    }
}

impl Settings {
    /// Load settings from disk; returns defaults if the file doesn't exist yet.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = std::fs::read_to_string(path)?;
        let s: Self = serde_json::from_str(&data)?;
        Ok(s)
    }

    /// Persist settings to disk (creates parent directories if needed).
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Return the settings file path given the app data directory.
    pub fn path_for(app_data_dir: &Path) -> PathBuf {
        app_data_dir.join("settings.json")
    }
}

/// Severity ordering for notification threshold comparison.
pub fn severity_order(s: &str) -> u8 {
    match s {
        "info" => 0,
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        "critical" => 4,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let s = Settings {
            monitoring_enabled: true,
            llm_provider: Some("openai".to_string()),
            ..Default::default()
        };
        s.save(&path).unwrap();

        let loaded = Settings::load(&path).unwrap();
        assert!(loaded.monitoring_enabled);
        assert_eq!(loaded.llm_provider.as_deref(), Some("openai"));
    }

    #[test]
    fn missing_file_gives_defaults() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonexistent.json");
        let s = Settings::load(&path).unwrap();
        assert_eq!(s.scan_interval_secs, 120);
        assert!(!s.monitoring_enabled);
    }

    #[test]
    fn severity_ordering() {
        assert!(severity_order("high") > severity_order("medium"));
        assert!(severity_order("critical") > severity_order("high"));
        assert!(severity_order("info") < severity_order("low"));
    }
}
