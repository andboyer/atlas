//! `device.exec` runbook tool — the single allowlisted bridge from the
//! runbook engine to the inventory + pack + transport + audit pipeline.
//!
//! YAML invocation shape:
//!
//! ```yaml
//! - id: snoop
//!   tool: device.exec
//!   args:
//!     host: "{host.av_switch}"     # or a literal host id like "core-sw-1"
//!     cmd: igmp_snooping_status    # must exist in the host's skill pack
//!     iface: "{host.av_switch_uplink_port}"  # extra args validated by pack
//!   bind: snoop
//! ```
//!
//! Execution flow:
//!  1. Resolve `host` -> `HostEntry` from the inventory.
//!  2. Resolve `host.skill` -> `SkillPack` and pull the command spec by id.
//!  3. Validate every declared arg via `device::validators` (strict types).
//!  4. Substitute validated args into the command template.
//!  5. Approval gate if the command's risk is Mutate / Dangerous.
//!  6. Dispatch through the right transport.
//!  7. Parse stdout via the command's named parser.
//!  8. Append an audit row with the stdout sha256.

use crate::device::approval::{self, ApprovalCenter, Verdict};
use crate::device::audit::{self, Audit};
use crate::device::inventory::{HostEntry, Inventory, TransportKind};
use crate::device::pack::{CommandSpec, PackRegistry, SkillPack};
use crate::device::parsers;
use crate::device::validators;
use crate::device::{https::HttpsTransport, ssh::SshTransport, CommandRequest, Transport};
use crate::runbook::tools::{Tool, ToolContext, ToolError};
use async_trait::async_trait;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub struct DeviceExecTool {
    inventory: Arc<Mutex<Inventory>>,
    packs: PackRegistry,
    ssh: Arc<SshTransport>,
    https: Arc<HttpsTransport>,
    audit: Audit,
    approval: ApprovalCenter,
    approval_wait: Duration,
    /// Stable per-execution metadata threaded into the audit log so a
    /// human reading the JSONL can correlate one row to one runbook run.
    /// `runbook_id` and `run_id` get filled in by the engine via the
    /// `RunbookId(...)` / `RunId(...)` arg-injection hack below; this is
    /// the only "magic args" surface the engine knows about.
    pub model: String,
}

/// Engine -> tool plumbing: when the runbook engine invokes a tool it
/// passes the normal `args` Value plus an injected pair under the
/// reserved `_runbook_id` / `_run_id` keys so the audit log can correlate.
/// These keys are stripped before template substitution.
pub const ARG_RUNBOOK_ID: &str = "_runbook_id";
pub const ARG_RUN_ID: &str = "_run_id";

impl DeviceExecTool {
    pub fn new(
        inventory: Arc<Mutex<Inventory>>,
        packs: PackRegistry,
        audit: Audit,
        approval: ApprovalCenter,
        model: String,
    ) -> Self {
        Self {
            inventory,
            packs: packs.clone(),
            ssh: Arc::new(SshTransport::new()),
            https: Arc::new(HttpsTransport::new(packs)),
            audit,
            approval,
            approval_wait: Duration::from_secs(120),
            model,
        }
    }

    fn host(&self, id: &str) -> Result<HostEntry, ToolError> {
        self.inventory
            .lock()
            .get(id)
            .cloned()
            .ok_or_else(|| ToolError::Exec(format!("unknown host `{id}`")))
    }

    fn pack(&self, skill: &str) -> Result<SkillPack, ToolError> {
        self.packs
            .get(skill)
            .cloned()
            .ok_or_else(|| ToolError::Exec(format!("unknown skill pack `{skill}`")))
    }

    fn command(&self, pack: &SkillPack, id: &str) -> Result<CommandSpec, ToolError> {
        pack.commands
            .iter()
            .find(|c| c.id == id)
            .cloned()
            .ok_or_else(|| {
                ToolError::Exec(format!("command `{id}` not in skill pack `{}`", pack.id))
            })
    }
}

#[async_trait]
impl Tool for DeviceExecTool {
    fn id(&self) -> &'static str {
        "device.exec"
    }
    fn description(&self) -> &'static str {
        "Run an allowlisted command from the host's skill pack and parse the result."
    }

    async fn run(&self, mut args: Value, ctx: &ToolContext) -> Result<Value, ToolError> {
        // Pull and remove the engine-injected metadata so it doesn't leak
        // into the template.
        let runbook_id = take_str(&mut args, ARG_RUNBOOK_ID).unwrap_or_default();
        let run_id = take_str(&mut args, ARG_RUN_ID).unwrap_or_default();

        // Required: host id + command id. Both are simple strings already
        // substituted by the engine's template renderer.
        let host_id =
            take_str(&mut args, "host").ok_or_else(|| ToolError::MissingArg("host".into()))?;
        let cmd_id =
            take_str(&mut args, "cmd").ok_or_else(|| ToolError::MissingArg("cmd".into()))?;

        if host_id.is_empty() {
            // `host.av_switch` resolved to null because no inventory entry
            // has that role. Surface as `skipped` so runbooks can
            // distinguish this from transport/tool availability issues.
            return Ok(json!({
                "verdict": "skipped",
                "reason": "missing_host_role",
                "host": null,
                "cmd": cmd_id,
                "note": "No inventory host matches the requested role; switch-side check skipped.",
            }));
        }

        let host = self.host(&host_id)?;
        let pack = self.pack(&host.skill)?;
        let cmd = self.command(&pack, &cmd_id)?;

        // Validate + render the remaining args through the spec's allowlist.
        let mut rendered_args: BTreeMap<String, String> = BTreeMap::new();
        for arg_spec in &cmd.args {
            let raw = take_str(&mut args, &arg_spec.name).unwrap_or_default();
            let value = if raw.is_empty() {
                if !arg_spec.default.is_empty() {
                    arg_spec.default.clone()
                } else if arg_spec.required {
                    return Err(ToolError::MissingArg(arg_spec.name.clone()));
                } else {
                    String::new()
                }
            } else {
                raw
            };
            if value.is_empty() {
                continue;
            }
            let kind = validators::Kind::parse(&arg_spec.kind).ok_or_else(|| {
                ToolError::BadArg(
                    arg_spec.name.clone(),
                    format!("unknown validator `{}`", arg_spec.kind),
                )
            })?;
            let canonical = validators::validate(&arg_spec.name, kind, &value)
                .map_err(|e| ToolError::BadArg(arg_spec.name.clone(), e.to_string()))?;
            rendered_args.insert(arg_spec.name.clone(), canonical);
        }

        // Render the template with the validated args. Any `{name}` whose
        // arg wasn't supplied is left literal so the operator sees the
        // exact unrendered command in the error message (and the audit
        // log) — better than silently dropping a placeholder.
        let rendered = render_template(&cmd.template, &rendered_args);
        let body = if cmd.body_template.is_empty() {
            None
        } else {
            let body_str = render_template(&cmd.body_template, &rendered_args);
            serde_json::from_str::<Value>(&body_str).ok()
        };

        // Approval gate.
        let approval_token: &'static str = "none";
        let mut approval_token_runtime = approval_token.to_string();
        if cmd.risk.requires_approval() {
            // Two-phase: register synchronously so we have a request_id
            // to put on the wire, emit the UI event, THEN await. The
            // operator's verdict arrives via `approve_runbook_step` /
            // `deny_runbook_step` Tauri commands.
            let (request_id, rx) = self.approval.register();
            if let Some(tx) = ctx.event_tx.as_ref() {
                let _ = tx.send(crate::runbook::RunbookEvent::ApprovalRequired {
                    run_id: run_id.clone(),
                    request_id: request_id.clone(),
                    host_id: host.id.clone(),
                    host_alias: host.alias.clone(),
                    command_id: cmd.id.clone(),
                    risk: approval::risk_label(cmd.risk).to_string(),
                    rendered: rendered.clone(),
                });
            }
            let verdict = self
                .approval
                .wait_for(&request_id, rx, self.approval_wait)
                .await;
            approval_token_runtime = approval::verdict_audit_token(verdict).to_string();
            if verdict != Verdict::Approve {
                return Ok(json!({
                    "verdict": "denied",
                    "reason": match verdict {
                        Verdict::Deny => "operator_denied",
                        Verdict::Timeout => "approval_timeout",
                        Verdict::Approve => "approved",
                    },
                    "host": host.id,
                    "cmd": cmd.id,
                    "approval": approval_token_runtime,
                    "note": format!(
                        "Operator did not approve {} command `{}` on host `{}`.",
                        approval::risk_label(cmd.risk),
                        cmd.id,
                        host.alias,
                    ),
                }));
            }
        }

        // Dispatch.
        let timeout = if host.timeout_seconds > 0 {
            Duration::from_secs(host.timeout_seconds)
        } else {
            ctx.timeout
        };
        let req = CommandRequest {
            command_id: cmd.id.clone(),
            rendered: rendered.clone(),
            body,
            method: cmd.method.clone(),
            risk: cmd.risk,
            timeout,
        };

        let transport: Arc<dyn Transport> = match host.transport {
            TransportKind::Ssh => self.ssh.clone(),
            TransportKind::Https => self.https.clone(),
        };

        let resp = match transport.exec(&host, req).await {
            Ok(r) => r,
            Err(e) => {
                // Audit failed dispatches too — the operator wants to see
                // them in the log when they're debugging why a runbook is
                // returning empty switch-side data.
                let entry = audit::build_entry(
                    &runbook_id,
                    &run_id,
                    &host.id,
                    &host.skill,
                    &cmd.id,
                    &rendered,
                    cmd.risk.as_str(),
                    "",
                    None,
                    0,
                    &approval_token_runtime,
                    &self.model,
                );
                let _ = self.audit.append(&entry);
                return Err(ToolError::Exec(format!("transport: {e}")));
            }
        };

        // Audit OK.
        let entry = audit::build_entry(
            &runbook_id,
            &run_id,
            &host.id,
            &host.skill,
            &cmd.id,
            &rendered,
            cmd.risk.as_str(),
            &resp.stdout,
            resp.status_code,
            resp.duration_ms,
            &approval_token_runtime,
            &self.model,
        );
        let _ = self.audit.append(&entry);

        // Parse.
        let parsed = parsers::parse_named(&cmd.parser, &resp.stdout);
        // Spread the parsed fields up to top-level for ergonomic YAML
        // access — guards write `snoop.snooping_enabled` rather than
        // `snoop.parsed.snooping_enabled`. Conflicts with the synthetic
        // top-level keys (`host`, `cmd`, `rendered`, `exit`, `duration_ms`,
        // `parsed`) are resolved in favour of the synthetic ones so an
        // accidentally-named pack field doesn't clobber engine metadata.
        let mut out = serde_json::Map::new();
        for (k, v) in flatten_parsed(parsed.clone()) {
            out.insert(k, v);
        }
        out.insert("host".into(), json!(host.id));
        out.insert("cmd".into(), json!(cmd.id));
        out.insert("rendered".into(), json!(rendered));
        out.insert("exit".into(), json!(resp.status_code));
        out.insert("duration_ms".into(), json!(resp.duration_ms));
        out.insert("parsed".into(), parsed);
        Ok(Value::Object(out))
    }
}

fn take_str(args: &mut Value, key: &str) -> Option<String> {
    let obj = args.as_object_mut()?;
    obj.remove(key).and_then(|v| match v {
        Value::String(s) => Some(s),
        Value::Null => None,
        other => Some(other.to_string()),
    })
}

fn render_template(tpl: &str, args: &BTreeMap<String, String>) -> String {
    // Same `{name}` shape as the runbook engine's expression-template
    // substitution — see `runbook::expr::render_template`. We intentionally
    // keep this a tiny independent copy rather than re-exporting because
    // the runbook side substitutes from Value bindings (any JSON type)
    // and this side from string-typed validated args.
    let mut out = String::with_capacity(tpl.len());
    let mut iter = tpl.chars().peekable();
    while let Some(c) = iter.next() {
        if c == '{' {
            let mut name = String::new();
            for nc in iter.by_ref() {
                if nc == '}' {
                    break;
                }
                name.push(nc);
            }
            match args.get(name.trim()) {
                Some(v) => out.push_str(v),
                None => {
                    out.push('{');
                    out.push_str(&name);
                    out.push('}');
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn flatten_parsed(parsed: Value) -> serde_json::Map<String, Value> {
    if let Value::Object(map) = parsed {
        map
    } else {
        let mut m = serde_json::Map::new();
        m.insert("value".into(), parsed);
        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn render_template_substitutes_known_keys() {
        let mut args = BTreeMap::new();
        args.insert("iface".into(), "Gi1/0/24".into());
        let out = render_template("show interfaces {iface}", &args);
        assert_eq!(out, "show interfaces Gi1/0/24");
    }

    #[test]
    fn render_template_keeps_unknown_placeholders_literal() {
        let args: BTreeMap<String, String> = BTreeMap::new();
        let out = render_template("show interfaces {iface}", &args);
        assert_eq!(out, "show interfaces {iface}");
    }

    #[test]
    fn flatten_parsed_object_inlines_fields() {
        let parsed = json!({"address": "10.0.0.1", "version": 2});
        let flat = flatten_parsed(parsed);
        assert_eq!(flat.get("address"), Some(&json!("10.0.0.1")));
    }
}
