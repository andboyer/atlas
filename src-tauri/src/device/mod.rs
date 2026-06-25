//! Device transport, host inventory, skill packs, and audit log.
//!
//! This module is the Phase 2-6 surface from `docs/PLAN.md`:
//!
//!  * **Host inventory** (`inventory.rs`) — TOML-on-disk catalogue of
//!    switches and controllers the operator wants the runbook engine to
//!    reach. Lives next to `settings.json` in the app data dir.
//!  * **Keychain** (`keychain.rs`) — operator-supplied passwords land in
//!    the OS keychain (macOS Keychain / Windows Credential Manager /
//!    Linux Secret Service). They are NEVER passed to the LLM.
//!  * **Skill packs** (`pack.rs`) — per-vendor TOML catalogues that declare
//!    each remote command as `{id, template, args, risk, parser}`. v1
//!    ships nine packs (`cisco-ios`, `cisco-nxos`, `extreme-exos`,
//!    `netgear-avline`, `tplink-omada`, `unifi`, `luminex-gigacore`,
//!    `q-sys-core`, `mikrotik-routeros`) with `read`-risk commands only.
//!  * **Transports** (`ssh.rs`, `https.rs`) — pluggable backends. v1 ships
//!    a system-`ssh` shell-out transport (no `russh` dep yet — keeps the
//!    binary small and reuses the operator's ssh-agent / `~/.ssh/config`)
//!    and a cookie-jar `reqwest` HTTPS transport for controller APIs.
//!  * **Audit** (`audit.rs`) — every remote command is appended to
//!    `agent-audit.jsonl` in the app data dir with host id, command id,
//!    rendered arguments, exit, output sha256, and runbook id. Viewable
//!    from Settings → "Agent audit log".
//!  * **Approval gates** (`approval.rs`) — runbook execution pauses on a
//!    `mutate` or `dangerous` command and emits a `RunbookEvent` to the
//!    frontend; only the operator can resolve the wait.
//!  * **`device.exec`** (`exec_tool.rs`) — the single allowlisted runbook
//!    tool that bridges the engine to the inventory + pack + transport
//!    pipeline. YAML runbooks invoke it as
//!    `tool: device.exec` `args: { host: "...", cmd: "...", ... }`.

pub mod approval;
pub mod audit;
pub mod exec_tool;
pub mod https;
pub mod inventory;
pub mod keychain;
pub mod pack;
pub mod parsers;
pub mod ssh;
pub mod validators;

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Risk tier for every command in every skill pack. v1 shipped packs are
/// mostly `Read`; the engine refuses to execute anything higher without an
/// explicit `Approve` event from the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    /// Pure read — `show ...`, `GET /api/...`. Safe to fire under runbook
    /// control with no approval.
    Read,
    /// State-changing but recoverable — `interface ... shut`, port-toggle,
    /// queue threshold tweak. v1 emits `RunbookEvent::ApprovalRequired`
    /// before running and aborts the step if the operator does not approve.
    Mutate,
    /// Destructive — anything touching `running-config`, ACL deletes, VLAN
    /// removal, `reload`. Requires both approval AND a typed-confirmation
    /// match on a per-command phrase. None ship enabled in v1.
    Dangerous,
}

impl Risk {
    pub fn requires_approval(self) -> bool {
        matches!(self, Risk::Mutate | Risk::Dangerous)
    }

    pub fn requires_typed_confirmation(self) -> bool {
        matches!(self, Risk::Dangerous)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Risk::Read => "read",
            Risk::Mutate => "mutate",
            Risk::Dangerous => "dangerous",
        }
    }
}

/// Transport-layer errors. These surface to the runbook executor as
/// `ToolError::Exec(...)` strings so runbook YAML can still branch on
/// `<bind>.error is not null`.
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("authentication failed for host `{0}`: {1}")]
    Auth(String, String),
    #[error("connection failed to `{0}`: {1}")]
    Connect(String, String),
    #[error("command timed out after {0} ms")]
    Timeout(u64),
    #[error("command exited with status {0}")]
    BadExit(i32),
    #[error("transport `{0}` is not supported on this build")]
    Unsupported(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("other: {0}")]
    Other(String),
}

/// Container for everything a transport needs to fire one command.
#[derive(Debug, Clone)]
pub struct CommandRequest {
    pub command_id: String,
    /// Fully-rendered command string. For SSH this is the literal line that
    /// gets piped to the remote shell; for HTTPS it's the path + query.
    pub rendered: String,
    /// Optional JSON body for HTTPS POST/PUT commands.
    pub body: Option<serde_json::Value>,
    /// HTTP method for HTTPS commands ("GET" / "POST" / ...). Ignored by SSH.
    pub method: String,
    pub risk: Risk,
    pub timeout: std::time::Duration,
}

/// Container for the captured remote-command output. SSH transports leave
/// `status_code` `None` (process exit handled separately); HTTPS transports
/// set it to the HTTP status code.
#[derive(Debug, Clone)]
pub struct CommandResponse {
    /// Stdout for SSH; response body for HTTPS.
    pub stdout: String,
    /// Stderr for SSH; empty for HTTPS.
    pub stderr: String,
    /// SSH: process exit code. HTTPS: HTTP status.
    pub status_code: Option<i32>,
    pub duration_ms: u64,
}

/// Common surface every transport implements. The `device.exec` tool walks
/// `host.transport` to pick the right backend.
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn exec(
        &self,
        host: &inventory::HostEntry,
        req: CommandRequest,
    ) -> Result<CommandResponse, TransportError>;

    /// Cheap reachability check used by the "Test connection" button in the
    /// Host Inventory UI. SSH transports run `echo ok`; HTTPS transports
    /// GET the controller's health/login endpoint.
    async fn test(&self, host: &inventory::HostEntry) -> Result<(), TransportError>;
}

/// Resolve the directory we keep device-related state in. Mirrors how
/// `Settings::path_for` derives `settings.json` — every file we own (host
/// inventory, audit log, keychain pointers) sits in the same dir.
pub fn device_data_dir(app_data_dir: &Path) -> PathBuf {
    app_data_dir.to_path_buf()
}
