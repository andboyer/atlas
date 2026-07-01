//! Tool registry — the runbook engine's allowlist of callable surfaces.
//!
//! A `Tool` is a typed wrapper around a probe (local) or a remote command
//! (later: SSH/HTTPS). All tools share a uniform async signature so the
//! engine can dispatch them uniformly:
//!
//! ```text
//!   async fn run(&self, args: Value, ctx: &ToolContext) -> Result<Value, ToolError>
//! ```
//!
//! **Security boundary:** the engine never executes a "tool" not in this
//! registry, even if a YAML runbook references one. The Rust-side
//! allowlist is the only way to expose new capabilities.

use anyhow::Result;
use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

use crate::probes::{self, iface};

#[derive(Debug, Error, Clone)]
pub enum ToolError {
    #[error("missing required argument `{0}`")]
    MissingArg(String),
    #[error("bad argument `{0}`: {1}")]
    BadArg(String, String),
    #[error("execution failed: {0}")]
    Exec(String),
    #[error("tool not implemented yet: {0}")]
    NotImplemented(&'static str),
    #[error("interface `{0}` not found on this host")]
    UnknownInterface(String),
}

/// Engine-supplied execution context. Tools should respect the pinned NIC
/// and the per-step timeout.
#[derive(Debug, Clone, Default)]
pub struct ToolContext {
    pub pinned_iface: Option<String>,
    pub timeout: Duration,
    /// Optional event sink: tools that need to surface UI events
    /// (e.g. `device.exec` raising an approval prompt) clone this and
    /// emit `RunbookEvent` variants directly. `None` when a run was
    /// invoked headlessly (e.g. by a unit test).
    pub event_tx: Option<tokio::sync::mpsc::UnboundedSender<crate::runbook::RunbookEvent>>,
}

#[async_trait]
pub trait Tool: Send + Sync {
    fn id(&self) -> &'static str;
    fn description(&self) -> &'static str;
    /// Run with already-substituted args.
    async fn run(&self, args: Value, ctx: &ToolContext) -> Result<Value, ToolError>;
}

/// Global registry shared by the engine.
#[derive(Clone, Default)]
pub struct Registry {
    tools: HashMap<&'static str, Arc<dyn Tool>>,
}

impl Registry {
    pub fn new() -> Self {
        let mut r = Self::default();
        r.register(Arc::new(LinkAuditTool));
        r.register(Arc::new(DanteBrowseTool));
        r.register(Arc::new(SapListenTool));
        r.register(Arc::new(MulticastGroupsTool));
        r.register(Arc::new(PtpProbeTool));
        r.register(Arc::new(DscpProbeTool));
        r.register(Arc::new(LldpProbeTool));
        r.register(Arc::new(ReachabilityTool));
        r.register(Arc::new(PingTool));
        r.register(Arc::new(GatewayTool));
        r.register(Arc::new(IgmpListenTool));
        r.register(Arc::new(StpProbeTool));
        r
    }

    pub fn register(&mut self, tool: Arc<dyn Tool>) {
        self.tools.insert(tool.id(), tool);
    }

    pub fn get(&self, id: &str) -> Option<Arc<dyn Tool>> {
        self.tools.get(id).cloned()
    }

    pub fn list(&self) -> Vec<(&'static str, &'static str)> {
        self.tools
            .values()
            .map(|t| (t.id(), t.description()))
            .collect()
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn arg_str(args: &Value, key: &str) -> Result<String, ToolError> {
    match args.get(key) {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(other) => Err(ToolError::BadArg(
            key.into(),
            format!("expected string, got {other}"),
        )),
        None => Err(ToolError::MissingArg(key.into())),
    }
}

fn arg_str_opt(args: &Value, key: &str) -> Option<String> {
    args.get(key).and_then(|v| v.as_str().map(String::from))
}

fn arg_u32(args: &Value, key: &str, default: u32) -> u32 {
    args.get(key)
        .and_then(|v| v.as_u64())
        .map(|n| n as u32)
        .unwrap_or(default)
}

fn resolve_iface(args: &Value, ctx: &ToolContext) -> Result<String, ToolError> {
    if let Some(s) = arg_str_opt(args, "iface") {
        if !s.is_empty() && s != "auto" {
            return Ok(s);
        }
    }
    ctx.pinned_iface
        .clone()
        .ok_or_else(|| ToolError::MissingArg("iface (no NIC pinned)".into()))
}

/// Run a sync probe on the blocking thread pool and convert the result to JSON.
async fn spawn_blocking_to_json<F, T>(f: F) -> Result<Value, ToolError>
where
    F: FnOnce() -> T + Send + 'static,
    T: serde::Serialize + Send + 'static,
{
    let res = tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| ToolError::Exec(format!("blocking task panicked: {e}")))?;
    serde_json::to_value(res).map_err(|e| ToolError::Exec(format!("serialize: {e}")))
}

// ── Tool implementations ─────────────────────────────────────────────────────

pub struct LinkAuditTool;
#[async_trait]
impl Tool for LinkAuditTool {
    fn id(&self) -> &'static str {
        "local.linkaudit"
    }
    fn description(&self) -> &'static str {
        "Per-NIC link speed, duplex, MTU, EEE and flow-control state."
    }
    async fn run(&self, args: Value, ctx: &ToolContext) -> Result<Value, ToolError> {
        let iface = resolve_iface(&args, ctx)?;
        spawn_blocking_to_json(move || probes::linkaudit::run_blocking(&iface)).await
    }
}

pub struct DanteBrowseTool;
#[async_trait]
impl Tool for DanteBrowseTool {
    fn id(&self) -> &'static str {
        "local.dante_browse"
    }
    fn description(&self) -> &'static str {
        "Browse Dante (`_netaudio._udp`) devices via mDNS."
    }
    async fn run(&self, args: Value, ctx: &ToolContext) -> Result<Value, ToolError> {
        let secs = arg_u32(&args, "duration_s", 5);
        let pinned = ctx.pinned_iface.clone();
        let devices = tokio::task::spawn_blocking(move || {
            probes::dante::browse_blocking(Duration::from_secs(secs as u64), pinned.as_deref())
        })
        .await
        .map_err(|e| ToolError::Exec(format!("blocking task panicked: {e}")))?;
        Ok(json!({ "devices": devices, "count": devices.len() }))
    }
}

pub struct SapListenTool;
#[async_trait]
impl Tool for SapListenTool {
    fn id(&self) -> &'static str {
        "local.sap_listen"
    }
    fn description(&self) -> &'static str {
        "Listen for AES67/Ravenna SAP/SDP announcements on 224.2.127.254:9875."
    }
    async fn run(&self, args: Value, ctx: &ToolContext) -> Result<Value, ToolError> {
        let iface = resolve_iface(&args, ctx)?;
        let secs = arg_u32(&args, "duration_s", 10);
        spawn_blocking_to_json(move || probes::sap::run_blocking(&iface, secs)).await
    }
}

pub struct MulticastGroupsTool;
#[async_trait]
impl Tool for MulticastGroupsTool {
    fn id(&self) -> &'static str {
        "local.multicast_groups"
    }
    fn description(&self) -> &'static str {
        "Enumerate multicast groups joined on each local interface."
    }
    async fn run(&self, args: Value, ctx: &ToolContext) -> Result<Value, ToolError> {
        // `iface` is optional — if set, filter to that interface; otherwise return all.
        let filter = arg_str_opt(&args, "iface").or_else(|| ctx.pinned_iface.clone());
        let all = tokio::task::spawn_blocking(probes::multicast::collect_blocking)
            .await
            .map_err(|e| ToolError::Exec(format!("blocking task panicked: {e}")))?;
        let scoped: Vec<_> = match &filter {
            Some(name) => all.into_iter().filter(|m| &m.iface == name).collect(),
            None => all,
        };
        let dante_audio_groups: u32 = scoped.iter().map(|m| m.dante_audio_groups).sum();
        let ptp_groups: u32 = scoped.iter().map(|m| m.ptp_groups).sum();
        // AES67 audio commonly re-uses the Dante 239.69.x.x range (AES67-2018
        // informative annex), and our classifier doesn't distinguish them
        // at the IP layer, so we report the same number for both buckets.
        // Runbooks can use either field interchangeably.
        let aes67_audio_groups: u32 = dante_audio_groups;
        let group_count: u32 = scoped.iter().map(|m| m.group_count).sum();
        Ok(json!({
            "interfaces": scoped,
            "iface": filter,
            "group_count": group_count,
            "dante_audio_groups": dante_audio_groups,
            "aes67_audio_groups": aes67_audio_groups,
            "ptp_groups": ptp_groups,
        }))
    }
}

pub struct PtpProbeTool;
#[async_trait]
impl Tool for PtpProbeTool {
    fn id(&self) -> &'static str {
        "local.ptp_probe"
    }
    fn description(&self) -> &'static str {
        "Listen on PTP UDP 319/320 and report grandmasters, jitter, and classification."
    }
    async fn run(&self, args: Value, ctx: &ToolContext) -> Result<Value, ToolError> {
        let iface = resolve_iface(&args, ctx)?;
        let secs = arg_u32(&args, "duration_s", 8);
        spawn_blocking_to_json(move || probes::ptp::run_blocking(&iface, secs)).await
    }
}

pub struct DscpProbeTool;
#[async_trait]
impl Tool for DscpProbeTool {
    fn id(&self) -> &'static str {
        "local.dscp_probe"
    }
    fn description(&self) -> &'static str {
        "Audit DSCP markings on inbound PTP / Dante audio / AES67 audio packets."
    }
    async fn run(&self, args: Value, ctx: &ToolContext) -> Result<Value, ToolError> {
        let iface = resolve_iface(&args, ctx)?;
        let secs = arg_u32(&args, "duration_s", 10);
        spawn_blocking_to_json(move || probes::dscp::run_blocking(&iface, secs)).await
    }
}

pub struct LldpProbeTool;
#[async_trait]
impl Tool for LldpProbeTool {
    fn id(&self) -> &'static str {
        "local.lldp_probe"
    }
    fn description(&self) -> &'static str {
        "Listen for LLDP/CDP frames to identify the upstream switch and port."
    }
    async fn run(&self, args: Value, ctx: &ToolContext) -> Result<Value, ToolError> {
        let iface = resolve_iface(&args, ctx)?;
        let secs = arg_u32(&args, "duration_s", 35);
        spawn_blocking_to_json(move || probes::lldp::run_blocking(&iface, secs)).await
    }
}

pub struct ReachabilityTool;
#[async_trait]
impl Tool for ReachabilityTool {
    fn id(&self) -> &'static str {
        "local.reachability"
    }
    fn description(&self) -> &'static str {
        "Pinned ping/DNS/packet-loss check against gateway + internet."
    }
    async fn run(&self, args: Value, ctx: &ToolContext) -> Result<Value, ToolError> {
        // iface is optional for reachability; falls back to ctx.pinned_iface.
        let iface = arg_str_opt(&args, "iface").or_else(|| ctx.pinned_iface.clone());
        let res = probes::reachability::collect(iface.as_deref())
            .await
            .map_err(|e| ToolError::Exec(e.to_string()))?;
        serde_json::to_value(res).map_err(|e| ToolError::Exec(format!("serialize: {e}")))
    }
}

pub struct PingTool;
#[async_trait]
impl Tool for PingTool {
    fn id(&self) -> &'static str {
        "local.ping"
    }
    fn description(&self) -> &'static str {
        "ICMP ping a host (1–10 packets), pinned to the selected NIC."
    }
    async fn run(&self, args: Value, ctx: &ToolContext) -> Result<Value, ToolError> {
        let host = arg_str(&args, "host")?;
        let count = arg_u32(&args, "count", 3).clamp(1, 10);
        let iface = arg_str_opt(&args, "iface").or_else(|| ctx.pinned_iface.clone());
        let avg_ms = probes::reachability::ping_via(&host, count, iface.as_deref()).await;
        Ok(json!({
            "host": host,
            "count": count,
            "iface": iface,
            "avg_ms": avg_ms,
            "reachable": avg_ms.is_some(),
        }))
    }
}

pub struct GatewayTool;
#[async_trait]
impl Tool for GatewayTool {
    fn id(&self) -> &'static str {
        "local.gateway"
    }
    fn description(&self) -> &'static str {
        "Resolve the default gateway for the selected NIC (or the kernel default)."
    }
    async fn run(&self, args: Value, ctx: &ToolContext) -> Result<Value, ToolError> {
        let iface = arg_str_opt(&args, "iface").or_else(|| ctx.pinned_iface.clone());
        let ip = probes::reachability::default_gateway_for_iface(iface.as_deref()).await;
        // Surface the iface's own IPv4 too — useful for "are we on the right VLAN" checks.
        let ipv4 = iface
            .as_deref()
            .and_then(iface::find_by_name)
            .and_then(|i| i.ipv4);
        Ok(json!({ "iface": iface, "ipv4": ipv4, "gateway_ip": ip }))
    }
}

/// Privileged IGMP listener. Re-execs the current binary under
/// platform-native elevation (macOS osascript / Windows UAC / Linux
/// pkexec) and parses the resulting `IgmpProbeResult`. If elevation
/// fails or is cancelled, falls back to a `verdict: "unavailable"`
/// JSON shape so YAML runbooks' `note_if: igmp.verdict ==
/// 'unavailable'` guards still fire and the engine treats the step as
/// `StepStatus::Unavailable` rather than a hard error.
pub struct IgmpListenTool;
#[async_trait]
impl Tool for IgmpListenTool {
    fn id(&self) -> &'static str {
        "local.igmp_listen"
    }
    fn description(&self) -> &'static str {
        "Listen on a raw IGMP socket for queriers / reports / leaves. \
         Requires administrator authorisation (UAC / pkexec / osascript)."
    }
    async fn run(&self, args: Value, ctx: &ToolContext) -> Result<Value, ToolError> {
        let iface = resolve_iface(&args, ctx)?;
        // 130 s catches an RFC-3376 default querier (General Query
        // every 125 s) with ~5 s of slack. Clamp at 180 s so an
        // operator-supplied value can't sit holding the elevation
        // dialog open for an unreasonable window.
        let secs = arg_u32(&args, "duration_s", 130).clamp(1, 180);
        let exe = match std::env::current_exe() {
            Ok(p) => p.to_string_lossy().into_owned(),
            Err(e) => {
                return Ok(json!({
                    "iface": iface,
                    "listen_secs": 0,
                    "queriers_seen": [],
                    "reports_seen": 0,
                    "leaves_seen": 0,
                    "verdict": "unavailable",
                    "error": format!("locate current exe: {e}"),
                    "note": "Could not resolve the Atlas binary path; the privileged IGMP listener was skipped."
                }));
            }
        };
        match crate::probes::agent::shared()
            .run_probe(&exe, "igmp-listen", &iface, secs)
            .await
        {
            Ok(raw) => match serde_json::from_str::<Value>(raw.trim()) {
                Ok(v) => Ok(v),
                Err(e) => Ok(json!({
                    "iface": iface,
                    "listen_secs": 0,
                    "queriers_seen": [],
                    "reports_seen": 0,
                    "leaves_seen": 0,
                    "verdict": "unavailable",
                    "error": format!("parse IgmpProbeResult: {e}"),
                    "note": "The privileged IGMP listener returned a non-JSON payload."
                })),
            },
            Err(e) => Ok(json!({
                "iface": iface,
                "listen_secs": 0,
                "queriers_seen": [],
                "reports_seen": 0,
                "leaves_seen": 0,
                "verdict": "unavailable",
                "error": e,
                "note": "Privileged IGMP listener was unavailable or declined; runbook continued without switch-side data."
            })),
        }
    }
}

/// Privileged STP / L2-loop listener. Re-execs the current binary under
/// platform-native elevation (macOS osascript / Windows UAC / Linux
/// pkexec) and parses the resulting `StpProbeResult`. Like the IGMP tool,
/// a failed/declined elevation falls back to a `verdict: "unavailable"`
/// JSON shape so runbook `note_if` guards still fire and the engine treats
/// the step as `Unavailable` rather than a hard error.
pub struct StpProbeTool;
#[async_trait]
impl Tool for StpProbeTool {
    fn id(&self) -> &'static str {
        "local.stp_listen"
    }
    fn description(&self) -> &'static str {
        "Passively capture spanning-tree BPDUs + broadcast/duplicate frames to detect \
         L2 loops and STP instability. Requires administrator authorisation."
    }
    async fn run(&self, args: Value, ctx: &ToolContext) -> Result<Value, ToolError> {
        let iface = resolve_iface(&args, ctx)?;
        let secs = arg_u32(&args, "duration_s", 30).clamp(5, 120);
        let exe = match std::env::current_exe() {
            Ok(p) => p.to_string_lossy().into_owned(),
            Err(e) => return Ok(stp_unavailable(&iface, format!("locate current exe: {e}"))),
        };
        match crate::probes::agent::shared()
            .run_probe(&exe, "stp-listen", &iface, secs)
            .await
        {
            Ok(raw) => match serde_json::from_str::<Value>(raw.trim()) {
                Ok(v) => Ok(v),
                Err(e) => Ok(stp_unavailable(
                    &iface,
                    format!("parse StpProbeResult: {e}"),
                )),
            },
            Err(e) => Ok(stp_unavailable(&iface, e)),
        }
    }
}

/// `StpProbeResult`-shaped fallback used when the privileged STP listener
/// can't run, so runbook guards referencing `stp.verdict` / `stp.detail`
/// still evaluate.
fn stp_unavailable(iface: &str, error: String) -> Value {
    json!({
        "iface": iface,
        "listen_secs": 0,
        "frames_seen": 0,
        "bpdus_seen": 0,
        "topology_changes": 0,
        "broadcast_pps_peak": 0.0,
        "multicast_pps_peak": 0.0,
        "duplicate_frame_ratio": 0.0,
        "stp_version": null,
        "root_bridges": [],
        "verdict": "unavailable",
        "detail": "The privileged STP / loop listener was unavailable or declined. Run the STP / L2 loop test from the AV tab and approve the admin prompt to capture BPDUs and broadcast traffic.",
        "error": error,
    })
}
