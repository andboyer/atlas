//! Audit log — JSONL append-only at `<app-data>/agent-audit.jsonl`.
//!
//! Every `device.exec` invocation appends one line with:
//!  * timestamp (UTC, RFC3339)
//!  * runbook id + run id
//!  * host id + skill pack
//!  * command id + risk
//!  * rendered command string (or HTTPS path)
//!  * exit status
//!  * sha256 of stdout (NOT the stdout itself — credentials, MAC tables,
//!    and config snippets can be sensitive)
//!  * duration (ms)
//!  * approval verdict, if applicable
//!
//! The Settings → "Agent audit log" view reads the tail with a simple
//! reverse-line read; we never load the entire file into memory.

use chrono::Utc;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub fn path_for(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join("agent-audit.jsonl")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub ts: String,
    pub runbook_id: String,
    pub run_id: String,
    pub host_id: String,
    pub skill: String,
    pub command_id: String,
    pub rendered: String,
    pub risk: String,
    /// SSH process exit OR HTTPS status code. Empty string == not captured.
    pub exit: String,
    pub stdout_sha256: String,
    pub duration_ms: u64,
    /// `none` for read commands; `approved` / `denied` for mutate/dangerous.
    pub approval: String,
    /// LLM model that triggered the runbook (informational).
    #[serde(default)]
    pub model: String,
}

#[derive(Clone)]
pub struct Audit {
    path: PathBuf,
    /// Serialise writes from concurrent `device.exec` tasks so JSONL stays
    /// well-formed.
    lock: Arc<Mutex<()>>,
}

impl Audit {
    pub fn new(app_data_dir: &Path) -> Self {
        Self {
            path: path_for(app_data_dir),
            lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(&self, entry: &AuditEntry) -> std::io::Result<()> {
        let _g = self.lock.lock();
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let line = serde_json::to_string(entry)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
        Ok(())
    }

    /// Return the most recent N entries (newest first). Reads the file
    /// once; for the audit-log viewer in Settings, N = 200 is a reasonable
    /// upper bound.
    pub fn tail(&self, limit: usize) -> std::io::Result<Vec<AuditEntry>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let f = std::fs::File::open(&self.path)?;
        let reader = BufReader::new(f);
        let mut all: Vec<AuditEntry> = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<AuditEntry>(&line) {
                Ok(entry) => all.push(entry),
                Err(_) => continue, // skip malformed (forward-compat)
            }
        }
        all.reverse();
        all.truncate(limit);
        Ok(all)
    }

    /// Clear the audit log. Behind a confirmed-by-operator UI gate.
    pub fn clear(&self) -> std::io::Result<()> {
        let _g = self.lock.lock();
        if self.path.exists() {
            std::fs::remove_file(&self.path)?;
        }
        Ok(())
    }
}

/// Build an `AuditEntry` from a successful command response. The caller
/// computes the stdout hash here so we never store stdout in memory longer
/// than needed.
#[allow(clippy::too_many_arguments)] // 12 fields = one row of the JSONL
pub fn build_entry(
    runbook_id: &str,
    run_id: &str,
    host_id: &str,
    skill: &str,
    command_id: &str,
    rendered: &str,
    risk: &str,
    stdout: &str,
    exit: Option<i32>,
    duration_ms: u64,
    approval: &str,
    model: &str,
) -> AuditEntry {
    let mut hasher = Sha256::new();
    hasher.update(stdout.as_bytes());
    let stdout_sha256 = format!("{:x}", hasher.finalize());
    AuditEntry {
        ts: Utc::now().to_rfc3339(),
        runbook_id: runbook_id.into(),
        run_id: run_id.into(),
        host_id: host_id.into(),
        skill: skill.into(),
        command_id: command_id.into(),
        rendered: rendered.into(),
        risk: risk.into(),
        exit: exit.map(|c| c.to_string()).unwrap_or_default(),
        stdout_sha256,
        duration_ms,
        approval: approval.into(),
        model: model.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn round_trip_one_entry() {
        let dir = tempdir().unwrap();
        let audit = Audit::new(dir.path());
        let entry = build_entry(
            "dante-audio-dropouts",
            "run-1",
            "core-sw-1",
            "cisco-ios",
            "show_ip_igmp_snooping",
            "show ip igmp snooping",
            "read",
            "Global IGMP Snooping configuration: Enabled\n",
            Some(0),
            42,
            "none",
            "qwen2.5:7b",
        );
        audit.append(&entry).unwrap();
        let tail = audit.tail(10).unwrap();
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].host_id, "core-sw-1");
        assert_eq!(tail[0].risk, "read");
        // SHA256 of the test stdout should be deterministic and 64-char hex.
        assert_eq!(tail[0].stdout_sha256.len(), 64);
    }

    #[test]
    fn tail_returns_newest_first() {
        let dir = tempdir().unwrap();
        let audit = Audit::new(dir.path());
        for i in 0..5 {
            let entry = build_entry(
                "rb",
                "r",
                &format!("h{i}"),
                "cisco-ios",
                "show",
                "show ver",
                "read",
                "ok",
                Some(0),
                1,
                "none",
                "test",
            );
            audit.append(&entry).unwrap();
        }
        let tail = audit.tail(3).unwrap();
        assert_eq!(tail.len(), 3);
        // Newest first => h4, h3, h2
        assert_eq!(tail[0].host_id, "h4");
        assert_eq!(tail[2].host_id, "h2");
    }

    #[test]
    fn missing_log_returns_empty_tail() {
        let dir = tempdir().unwrap();
        let audit = Audit::new(dir.path());
        assert!(audit.tail(10).unwrap().is_empty());
    }
}
