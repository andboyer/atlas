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
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            scan_interval_secs: 120,
            monitoring_enabled: false,
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
