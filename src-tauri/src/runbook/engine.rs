//! Runbook executor — drives a `Runbook` through its steps and emits
//! `RunbookEvent`s for the frontend.

use crate::device::approval::ApprovalCenter;
use crate::device::audit::Audit;
use crate::device::exec_tool::{DeviceExecTool, ARG_RUNBOOK_ID, ARG_RUN_ID};
use crate::device::inventory::Inventory;
use crate::device::pack::PackRegistry;
use crate::runbook::{
    expr, library, narrate, tools::Registry, tools::ToolContext, tools::ToolError, Branch,
    ExecutionOutcome, Runbook, RunbookEvent, RunbookExecution, StepRecord, StepStatus,
};
use chrono::Utc;
use parking_lot::Mutex;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::warn;
use uuid::Uuid;

/// LLM configuration passed in from the Tauri command. None disables narration.
#[derive(Debug, Clone)]
pub struct LlmConfig {
    pub provider: String,
    pub api_key: String,
    pub model: String,
    pub base_url: Option<String>,
}

/// Per-execution input bundle.
#[derive(Debug, Clone)]
pub struct ExecutionInputs {
    pub pinned_iface: Option<String>,
    /// Extra inputs to merge into bindings, e.g. `{"nic": "en0"}`.
    pub variables: BTreeMap<String, Value>,
}

pub struct Engine {
    registry: Registry,
    library: library::Library,
    llm: Option<LlmConfig>,
    per_step_timeout: Duration,
    max_nesting_depth: usize,
    /// Optional inventory snapshot — populated when the engine was built
    /// via `with_device(...)`. Used to populate `host.<role>` bindings.
    inventory: Option<Arc<Mutex<Inventory>>>,
}

impl Engine {
    pub fn new(llm: Option<LlmConfig>) -> Self {
        Self {
            registry: Registry::new(),
            library: library::load_bundled(),
            llm,
            per_step_timeout: Duration::from_secs(90),
            max_nesting_depth: 2,
            inventory: None,
        }
    }

    /// Attach the device-execution subsystem (inventory, skill packs,
    /// approval centre, audit log). Registers the `device.exec` tool and
    /// makes the inventory available for `host.<role>` binding resolution
    /// before each run.
    pub fn with_device(
        mut self,
        inventory: Arc<Mutex<Inventory>>,
        packs: PackRegistry,
        audit: Audit,
        approval: ApprovalCenter,
        model: String,
    ) -> Self {
        let tool = DeviceExecTool::new(inventory.clone(), packs, audit, approval, model);
        self.registry.register(Arc::new(tool));
        self.inventory = Some(inventory);
        self
    }

    /// Merge user-authored runbooks from `<app-data>/runbooks/*.yaml` on
    /// top of the bundled library. User entries override bundled entries
    /// with the same id (Phase 5).
    pub fn with_user_runbooks(mut self, dir: &std::path::Path) -> Self {
        self.library.merge_dir(dir);
        self
    }

    pub fn list_runbooks(&self) -> Vec<&Runbook> {
        self.library.all()
    }

    pub fn find(&self, id: &str) -> Option<&Runbook> {
        self.library.get(id)
    }

    /// Execute a runbook end-to-end, streaming events through `tx`. Returns
    /// the complete transcript when done.
    pub async fn run(
        &self,
        runbook_id: &str,
        inputs: ExecutionInputs,
        tx: Option<mpsc::UnboundedSender<RunbookEvent>>,
    ) -> Result<RunbookExecution, String> {
        let rb = self
            .find(runbook_id)
            .ok_or_else(|| format!("unknown runbook `{runbook_id}`"))?
            .clone();
        let run_id = Uuid::new_v4().to_string();

        let emit = |ev: RunbookEvent| {
            if let Some(t) = &tx {
                let _ = t.send(ev);
            }
        };

        emit(RunbookEvent::Started {
            run_id: run_id.clone(),
            runbook_id: rb.id.clone(),
            runbook_name: rb.name.clone(),
        });

        let started_at = Utc::now();
        let mut bindings: BTreeMap<String, Value> = inputs.variables.clone();
        // Make pinned_iface visible to template substitution as `{nic}`.
        if let Some(nic) = &inputs.pinned_iface {
            bindings
                .entry("nic".into())
                .or_insert(Value::String(nic.clone()));
        }
        // Populate `{host.<role>}` from inventory so YAML runbooks can
        // reference the operator's switch / controller / Q-SYS Core by
        // role rather than literal id. Also exposes `{host.<role>_uplink_port}`
        // for switch entries that declared one — needed by AV-line
        // runbooks that probe a specific switchport.
        if let Some(inv) = &self.inventory {
            let inv = inv.lock();
            let mut host_map = serde_json::Map::new();
            for entry in &inv.hosts {
                for role in &entry.roles {
                    host_map.insert(role.clone(), Value::String(entry.id.clone()));
                    if !entry.av_switch_uplink_port.is_empty() {
                        host_map.insert(
                            format!("{role}_uplink_port"),
                            Value::String(entry.av_switch_uplink_port.clone()),
                        );
                    }
                }
            }
            bindings.insert("host".into(), Value::Object(host_map));
        }
        let mut steps_out: Vec<StepRecord> = Vec::new();
        let mut outcome = ExecutionOutcome::Clean;

        let ctx = Arc::new(ToolContext {
            pinned_iface: inputs.pinned_iface.clone(),
            timeout: self.per_step_timeout,
            event_tx: tx.clone(),
        });

        let result = self
            .execute_steps(
                &rb,
                &mut bindings,
                &mut steps_out,
                &mut outcome,
                ctx.clone(),
                &run_id,
                &tx,
                0,
            )
            .await;

        if let Err(msg) = result {
            outcome = ExecutionOutcome::EngineError;
            emit(RunbookEvent::Error {
                run_id: run_id.clone(),
                message: msg,
            });
        }

        // Narration step (best-effort; never fatal).
        let narration = if let Some(cfg) = &self.llm {
            match narrate::narrate(cfg, &rb, &steps_out, &bindings).await {
                Ok(text) => {
                    emit(RunbookEvent::Narration {
                        run_id: run_id.clone(),
                        text: text.clone(),
                    });
                    Some(text)
                }
                Err(e) => {
                    warn!("runbook narration failed: {e}");
                    None
                }
            }
        } else {
            None
        };

        emit(RunbookEvent::Completed {
            run_id: run_id.clone(),
            outcome,
        });

        Ok(RunbookExecution {
            run_id,
            runbook_id: rb.id,
            runbook_name: rb.name,
            started_at,
            completed_at: Some(Utc::now()),
            inputs: inputs.variables,
            steps: steps_out,
            narration,
            outcome,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_steps(
        &self,
        rb: &Runbook,
        bindings: &mut BTreeMap<String, Value>,
        steps_out: &mut Vec<StepRecord>,
        outcome: &mut ExecutionOutcome,
        ctx: Arc<ToolContext>,
        run_id: &str,
        tx: &Option<mpsc::UnboundedSender<RunbookEvent>>,
        depth: usize,
    ) -> Result<(), String> {
        for step in &rb.steps {
            // when: precondition
            if let Some(expr_src) = &step.when_expr {
                match expr::eval_bool(expr_src, bindings) {
                    Ok(true) => {}
                    Ok(false) => {
                        let rec = StepRecord {
                            step_id: step.id.clone(),
                            tool: step.tool.clone(),
                            args_json: Value::Null,
                            started_at: Utc::now(),
                            duration_ms: 0,
                            status: StepStatus::Skipped,
                            result: None,
                            warnings: vec![],
                            notes: vec![format!("Skipped (when: `{expr_src}` was false)")],
                            error: None,
                            spawned_runbook: None,
                        };
                        emit_step_finished(tx, run_id, &rec);
                        steps_out.push(rec);
                        continue;
                    }
                    Err(e) => {
                        let rec = StepRecord {
                            step_id: step.id.clone(),
                            tool: step.tool.clone(),
                            args_json: Value::Null,
                            started_at: Utc::now(),
                            duration_ms: 0,
                            status: StepStatus::Error,
                            result: None,
                            warnings: vec![],
                            notes: vec![],
                            error: Some(format!("when expression error: {e}")),
                            spawned_runbook: None,
                        };
                        emit_step_finished(tx, run_id, &rec);
                        steps_out.push(rec);
                        continue;
                    }
                }
            }

            // Render args (string-template substitution).
            let args_value = substitute_args(&step.args, bindings);

            emit(
                tx,
                RunbookEvent::StepStarted {
                    run_id: run_id.into(),
                    step_id: step.id.clone(),
                    tool: step.tool.clone(),
                },
            );

            let start = Instant::now();
            let started_at = Utc::now();
            // device.exec gets the runbook_id + run_id injected so the
            // audit log can correlate one JSONL row to the step that
            // produced it. The keys live in `device::exec_tool` so the
            // executor stays the single source of truth for the contract.
            let mut tool_args = args_value.clone();
            if step.tool == "device.exec" {
                if let Some(obj) = tool_args.as_object_mut() {
                    obj.insert(ARG_RUNBOOK_ID.into(), Value::String(rb.id.clone()));
                    obj.insert(ARG_RUN_ID.into(), Value::String(run_id.into()));
                }
            }
            let exec_result = self.invoke_tool(&step.tool, tool_args, &ctx).await;
            let duration_ms = start.elapsed().as_millis() as u64;

            let mut rec = StepRecord {
                step_id: step.id.clone(),
                tool: step.tool.clone(),
                args_json: args_value.clone(),
                started_at,
                duration_ms,
                status: StepStatus::Ok,
                result: None,
                warnings: vec![],
                notes: vec![],
                error: None,
                spawned_runbook: None,
            };

            match exec_result {
                Ok(value) => {
                    let stub_not_impl = value
                        .get("verdict")
                        .and_then(|v| v.as_str())
                        .map(|s| s == "not_implemented")
                        .unwrap_or(false);
                    if stub_not_impl {
                        rec.status = StepStatus::NotImplemented;
                        if let Some(note) = value.get("note").and_then(|v| v.as_str()) {
                            rec.notes.push(note.to_string());
                        }
                    }
                    rec.result = Some(value.clone());
                    if let Some(name) = &step.bind {
                        bindings.insert(name.clone(), value.clone());
                    }
                    // Evaluate fail_if / warn_if / note_if against the bindings
                    // (the just-bound result is visible now).
                    if let Some(expr_src) = &step.fail_if {
                        if eval_guard_bool(expr_src, bindings, &mut rec) {
                            rec.status = StepStatus::Failed;
                            let msg = step
                                .on_fail
                                .as_deref()
                                .map(|t| expr::render_template(t, bindings))
                                .unwrap_or_else(|| {
                                    format!("Hard fail: `{expr_src}` evaluated true")
                                });
                            rec.notes.push(msg);
                            *outcome = ExecutionOutcome::HardFail;
                            emit_step_finished(tx, run_id, &rec);
                            steps_out.push(rec);
                            return Ok(());
                        }
                    }
                    if let Some(expr_src) = &step.warn_if {
                        if eval_guard_bool(expr_src, bindings, &mut rec) {
                            rec.status = StepStatus::Warn;
                            if *outcome == ExecutionOutcome::Clean {
                                *outcome = ExecutionOutcome::Issues;
                            }
                            let msg = step
                                .warn_msg
                                .as_deref()
                                .map(|t| expr::render_template(t, bindings))
                                .unwrap_or_else(|| format!("Warning: `{expr_src}`"));
                            rec.warnings.push(msg);
                        }
                    }
                    if let Some(expr_src) = &step.note_if {
                        if eval_guard_bool(expr_src, bindings, &mut rec) {
                            let msg = step
                                .note_msg
                                .as_deref()
                                .map(|t| expr::render_template(t, bindings))
                                .unwrap_or_else(|| format!("Note: `{expr_src}`"));
                            rec.notes.push(msg);
                        }
                    }
                }
                Err(ToolError::NotImplemented(_)) => {
                    rec.status = StepStatus::NotImplemented;
                    rec.notes.push("Tool not implemented in this build.".into());
                }
                Err(e) => {
                    rec.status = StepStatus::Error;
                    rec.error = Some(e.to_string());
                }
            }

            // Branch dispatch (only when status is OK or Warn or NotImplemented).
            let consider_branches = matches!(
                rec.status,
                StepStatus::Ok | StepStatus::Warn | StepStatus::NotImplemented
            );
            if consider_branches {
                for br in &step.branch {
                    if matches!(expr::eval_bool(&br.when, bindings), Ok(true)) {
                        apply_branch(br, bindings, &mut rec);
                        if let Some(child_id) = &br.runbook {
                            if depth < self.max_nesting_depth {
                                emit(
                                    tx,
                                    RunbookEvent::NestedRunbookStarted {
                                        run_id: run_id.into(),
                                        parent_step_id: step.id.clone(),
                                        child_runbook_id: child_id.clone(),
                                    },
                                );
                                rec.spawned_runbook = Some(child_id.clone());
                            } else {
                                rec.notes.push(format!(
                                    "Skipped nested runbook `{child_id}` (max depth reached)"
                                ));
                            }
                        }
                        break;
                    }
                }
            }

            let nested_to_run = rec.spawned_runbook.clone();
            emit_step_finished(tx, run_id, &rec);
            steps_out.push(rec);

            // Execute nested runbook AFTER the parent step has been
            // emitted so the UI can render them in order.
            if let Some(child_id) = nested_to_run {
                if let Some(child_rb) = self.find(&child_id).cloned() {
                    // Box the recursive call to keep the future size finite.
                    Box::pin(self.execute_steps(
                        &child_rb,
                        bindings,
                        steps_out,
                        outcome,
                        ctx.clone(),
                        run_id,
                        tx,
                        depth + 1,
                    ))
                    .await?;
                } else {
                    warn!("nested runbook `{child_id}` not in library");
                }
            }
        }
        Ok(())
    }

    async fn invoke_tool(
        &self,
        tool_id: &str,
        args: Value,
        ctx: &ToolContext,
    ) -> Result<Value, ToolError> {
        let tool = self
            .registry
            .get(tool_id)
            .ok_or_else(|| ToolError::Exec(format!("unregistered tool `{tool_id}`")))?;
        match tokio::time::timeout(ctx.timeout, tool.run(args, ctx)).await {
            Ok(r) => r,
            Err(_) => Err(ToolError::Exec(format!(
                "tool `{tool_id}` exceeded timeout {:?}",
                ctx.timeout
            ))),
        }
    }
}

fn emit(tx: &Option<mpsc::UnboundedSender<RunbookEvent>>, ev: RunbookEvent) {
    if let Some(t) = tx {
        let _ = t.send(ev);
    }
}

fn emit_step_finished(
    tx: &Option<mpsc::UnboundedSender<RunbookEvent>>,
    run_id: &str,
    rec: &StepRecord,
) {
    emit(
        tx,
        RunbookEvent::StepFinished {
            run_id: run_id.into(),
            record: rec.clone(),
        },
    );
}

fn eval_guard_bool(
    expr_src: &str,
    bindings: &BTreeMap<String, Value>,
    rec: &mut StepRecord,
) -> bool {
    match expr::eval_bool(expr_src, bindings) {
        Ok(b) => b,
        Err(e) => {
            rec.notes
                .push(format!("Guard expression error: `{expr_src}` — {e}"));
            false
        }
    }
}

fn apply_branch(br: &Branch, bindings: &BTreeMap<String, Value>, rec: &mut StepRecord) {
    if let Some(text) = &br.note {
        rec.notes.push(expr::render_template(text, bindings));
    }
}

/// Walk the runbook YAML args and substitute `"{path.to.value}"` strings
/// from the bindings. Only string values are templated; non-strings pass
/// through. This lets YAML authors write `args: { iface: "{nic}" }` and
/// get the runtime NIC value substituted.
fn substitute_args(args: &BTreeMap<String, Value>, bindings: &BTreeMap<String, Value>) -> Value {
    let mut out = serde_json::Map::new();
    for (k, v) in args {
        out.insert(k.clone(), substitute_value(v, bindings));
    }
    Value::Object(out)
}

fn substitute_value(v: &Value, bindings: &BTreeMap<String, Value>) -> Value {
    match v {
        Value::String(s) => {
            // If the string is exactly `"{path}"` (no extra text), prefer the
            // typed value of `path` so numeric args stay numeric.
            let trimmed = s.trim();
            if trimmed.starts_with('{')
                && trimmed.ends_with('}')
                && trimmed.matches('{').count() == 1
            {
                let path = &trimmed[1..trimmed.len() - 1];
                if let Some(resolved) = expr::resolve_path_pub(path.trim(), bindings) {
                    return resolved;
                }
            }
            Value::String(expr::render_template(s, bindings))
        }
        Value::Array(arr) => {
            Value::Array(arr.iter().map(|x| substitute_value(x, bindings)).collect())
        }
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), substitute_value(v, bindings)))
                .collect(),
        ),
        other => other.clone(),
    }
}
