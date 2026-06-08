//! Host inventory — TOML catalogue of switches and controllers the runbook
//! engine can reach.
//!
//! Layout on disk (`<app-data>/hosts.toml`):
//!
//! ```toml
//! [[host]]
//! id = "core-sw-1"
//! alias = "Core switch (closet A)"
//! hostname = "10.0.0.2"
//! port = 22
//! transport = "ssh"          # "ssh" or "https"
//! skill = "cisco-ios"        # must match a registered skill pack
//! username = "atlas"
//! auth = "key"               # "key" or "password"
//! key_path = "~/.ssh/atlas_ed25519"
//! roles = ["av-uplink"]      # used by `host.<role>` lookups in YAML
//! av_switch_uplink_port = "Gi1/0/24"  # optional per-role context
//! ```
//!
//! Passwords NEVER live in this file — they're stored in the OS keychain
//! keyed by `(service="com.andboyer.atlas", account=host.id)`.
//!
//! YAML runbooks reference the inventory via:
//!   * `host.<role>` — e.g. `host.av_switch` picks the first host whose
//!     `roles` contains the role mapping (`av_switch` → "av-uplink").
//!   * `host.<role>_uplink_port` — convenience accessor for the per-role
//!     context field on the resolved host.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Catalog file lives next to `settings.json`.
pub fn path_for(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join("hosts.toml")
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Inventory {
    /// Empty on first run. Populated by the Host Inventory UI in Settings.
    #[serde(rename = "host")]
    pub hosts: Vec<HostEntry>,
}

/// One configured remote target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostEntry {
    /// Stable slug — used as the keychain account id and the audit-log
    /// host reference. Operators see `alias`, runbook YAML references `id`.
    pub id: String,
    /// Operator-facing friendly name.
    pub alias: String,
    /// IPv4/IPv6/DNS name.
    pub hostname: String,
    /// 22 for ssh, 443 for https unless overridden.
    pub port: u16,
    /// `ssh` or `https`.
    pub transport: TransportKind,
    /// Skill pack id, e.g. `cisco-ios`, `tplink-omada`, `unifi`.
    pub skill: String,
    /// SSH username — ignored for HTTPS controllers that login via API.
    #[serde(default)]
    pub username: String,
    /// `key` or `password` (SSH). `api_key` or `password` (HTTPS).
    #[serde(default)]
    pub auth: AuthKind,
    /// Optional path to a private key for SSH. `~` expanded at use time.
    #[serde(default)]
    pub key_path: String,
    /// HTTPS controllers that need to know which site / org-id to scope
    /// their REST calls to (Omada / UniFi site uuid, GigaCore unit id).
    #[serde(default)]
    pub site: String,
    /// Free-form role tags for runbook lookup. Common: `av-uplink`,
    /// `av-edge`, `audio-controller`.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Optional uplink port label (Cisco notation `Gi1/0/24`). Surfaces in
    /// runbook YAML as `host.av_switch_uplink_port`.
    #[serde(default)]
    pub av_switch_uplink_port: String,
    /// Per-step timeout override in seconds; defaults to the engine's
    /// global 90s if unset / zero.
    #[serde(default)]
    pub timeout_seconds: u64,
    /// Reject TLS host-mismatch / self-signed cert for HTTPS controllers.
    /// Defaults to true (refuse). Operators with internal CAs flip this
    /// false per-host, NEVER globally.
    #[serde(default = "true_default")]
    pub tls_verify: bool,
}

fn true_default() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    Ssh,
    Https,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuthKind {
    #[default]
    Password,
    Key,
    ApiKey,
}

impl Inventory {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = std::fs::read_to_string(path)?;
        let inv: Self = toml::from_str(&data)?;
        Ok(inv)
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = toml::to_string_pretty(self)?;
        std::fs::write(path, text)?;
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&HostEntry> {
        self.hosts.iter().find(|h| h.id == id)
    }

    pub fn upsert(&mut self, entry: HostEntry) {
        if let Some(idx) = self.hosts.iter().position(|h| h.id == entry.id) {
            self.hosts[idx] = entry;
        } else {
            self.hosts.push(entry);
        }
    }

    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.hosts.len();
        self.hosts.retain(|h| h.id != id);
        before != self.hosts.len()
    }

    /// Resolve a role token like `"av-uplink"` to the first matching host.
    /// Used by `host.<role>` lookups inside runbook expressions.
    pub fn first_with_role(&self, role: &str) -> Option<&HostEntry> {
        self.hosts
            .iter()
            .find(|h| h.roles.iter().any(|r| r == role))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn round_trip_inventory() {
        let dir = tempdir().unwrap();
        let path = path_for(dir.path());
        let mut inv = Inventory::default();
        inv.upsert(HostEntry {
            id: "core-sw-1".into(),
            alias: "Core switch".into(),
            hostname: "10.0.0.2".into(),
            port: 22,
            transport: TransportKind::Ssh,
            skill: "cisco-ios".into(),
            username: "atlas".into(),
            auth: AuthKind::Key,
            key_path: "~/.ssh/atlas_ed25519".into(),
            site: String::new(),
            roles: vec!["av-uplink".into()],
            av_switch_uplink_port: "Gi1/0/24".into(),
            timeout_seconds: 0,
            tls_verify: true,
        });
        inv.save(&path).unwrap();

        let loaded = Inventory::load(&path).unwrap();
        let h = loaded.get("core-sw-1").expect("host roundtrips");
        assert_eq!(h.alias, "Core switch");
        assert_eq!(h.transport, TransportKind::Ssh);
        assert_eq!(h.roles, vec!["av-uplink"]);
    }

    #[test]
    fn missing_file_returns_empty() {
        let dir = tempdir().unwrap();
        let inv = Inventory::load(&path_for(dir.path())).unwrap();
        assert!(inv.hosts.is_empty());
    }

    #[test]
    fn role_lookup() {
        let mut inv = Inventory::default();
        inv.upsert(HostEntry {
            id: "h1".into(),
            alias: "h1".into(),
            hostname: "1.1.1.1".into(),
            port: 22,
            transport: TransportKind::Ssh,
            skill: "cisco-ios".into(),
            username: "x".into(),
            auth: AuthKind::Key,
            key_path: String::new(),
            site: String::new(),
            roles: vec!["av-edge".into()],
            av_switch_uplink_port: String::new(),
            timeout_seconds: 0,
            tls_verify: true,
        });
        assert_eq!(
            inv.first_with_role("av-edge").map(|h| h.id.as_str()),
            Some("h1")
        );
        assert!(inv.first_with_role("av-uplink").is_none());
    }
}
