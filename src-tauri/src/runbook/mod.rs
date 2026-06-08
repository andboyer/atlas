//! Runbook engine: deterministic, composable AV/IP troubleshooting flows.
//!
//! The engine loads YAML runbook definitions, executes ordered steps that
//! invoke local probes (or, in later phases, SSH/HTTPS commands against
//! switches), evaluates guard expressions against captured results, and
//! finally hands the entire transcript to the LLM for a plain-language
//! narration. The LLM is a *narrator*, never a planner — it cannot invent
//! steps or pick tools that aren't already in the runbook YAML.
//!
//! Design pillars:
//!  * **Deterministic.** Two runs against the same network produce the same
//!    step transcript. Branching is rule-based, not LLM-judged.
//!  * **Safe by construction.** Every tool the engine can call is on a
//!    Rust-side allowlist; YAML can only reference registered tool IDs.
//!  * **Composable.** Runbooks can `runbook:` into other runbooks
//!    (one level of nesting) so common subtrees (e.g. `igmp-no-querier`)
//!    can be invoked from multiple parents.
//!  * **Read-only in v1.** No tool ships that mutates remote state. Write
//!    surfaces will land in a later phase with explicit approval gating.

pub mod engine;
pub mod expr;
pub mod library;
pub mod narrate;
pub mod tools;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Top-level runbook definition (parsed from YAML).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Runbook {
    /// Stable identifier, e.g. `dante-audio-dropouts`. URL-safe slug.
    pub id: String,
    /// Operator-facing display name.
    pub name: String,
    /// Free-form category for grouping in the UI (e.g. `av`, `multicast`, `ptp`).
    pub category: String,
    /// Which AoIP protocols this book applies to (for UI filtering).
    #[serde(default)]
    pub applies_to: Vec<String>,
    /// Operator-facing one-line description.
    #[serde(default)]
    pub description: String,
    /// Symptom phrases used by the LLM picker to match user prompts.
    #[serde(default)]
    pub symptoms: Vec<String>,
    /// Steps executed in order. Branching can short-circuit the rest.
    pub steps: Vec<Step>,
}

/// One step in a runbook execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    /// Step identifier, unique within a runbook. Used in `bind` references.
    pub id: String,
    /// Tool to invoke, e.g. `local.linkaudit`, `local.dante_browse`.
    pub tool: String,
    /// Tool-specific arguments. Template strings like `"{nic}"` are
    /// substituted from the execution context's variables.
    #[serde(default)]
    pub args: BTreeMap<String, serde_json::Value>,
    /// Optional bind name — if set, the tool result is stored under this
    /// key in the runbook's bindings dict and is visible to later steps'
    /// guard expressions.
    #[serde(default)]
    pub bind: Option<String>,
    /// Optional precondition. If the expression evaluates to false, the
    /// step is skipped entirely.
    #[serde(default, rename = "when")]
    pub when_expr: Option<String>,
    /// Hard fail — if this expression evaluates true after the tool runs,
    /// the runbook stops and reports `on_fail` as the cause.
    #[serde(default)]
    pub fail_if: Option<String>,
    /// Operator-friendly explanation of `fail_if`. Required when `fail_if`
    /// is set.
    #[serde(default)]
    pub on_fail: Option<String>,
    /// Soft warning — if true after the tool runs, the warning is added to
    /// the transcript and shown in the UI, but execution continues.
    #[serde(default)]
    pub warn_if: Option<String>,
    /// Template for `warn_if` message; can reference bindings, e.g.
    /// `"DSCP is {dscp.value}, expected 46"`.
    #[serde(default)]
    pub warn_msg: Option<String>,
    /// Informational note (like `warn_if` but flagged as info, not warning).
    #[serde(default)]
    pub note_if: Option<String>,
    /// Template for `note_if` message.
    #[serde(default)]
    pub note_msg: Option<String>,
    /// Branches taken AFTER the tool runs and warn/fail checks pass. The
    /// first matching `when` triggers either an inline note or a nested
    /// runbook invocation.
    #[serde(default)]
    pub branch: Vec<Branch>,
}

/// A single branch arm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Branch {
    /// Guard expression — first matching wins.
    pub when: String,
    /// Inline message added to the transcript.
    #[serde(default)]
    pub note: Option<String>,
    /// Nested runbook id to execute. The nested book runs with the same
    /// bindings (and may add its own).
    #[serde(default)]
    pub runbook: Option<String>,
}

/// One transcript entry per step execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepRecord {
    pub step_id: String,
    pub tool: String,
    pub args_json: serde_json::Value,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub duration_ms: u64,
    pub status: StepStatus,
    /// Tool output as JSON (whatever the tool returned).
    #[serde(default)]
    pub result: Option<serde_json::Value>,
    /// Soft warnings emitted by guards.
    #[serde(default)]
    pub warnings: Vec<String>,
    /// Informational notes emitted by guards or branch arms.
    #[serde(default)]
    pub notes: Vec<String>,
    /// Error text if the tool itself failed.
    #[serde(default)]
    pub error: Option<String>,
    /// If a nested runbook was triggered, its id is recorded here so the UI
    /// can render the nested transcript inline.
    #[serde(default)]
    pub spawned_runbook: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    /// Tool ran and all guards passed.
    Ok,
    /// Tool ran but a soft warning fired.
    Warn,
    /// Tool ran but `fail_if` triggered — execution stopped at this step.
    Failed,
    /// `when` precondition was false; tool did not run.
    Skipped,
    /// Tool itself errored.
    Error,
    /// Tool ran but reported it could not execute in this build /
    /// environment (e.g. operator declined the elevation prompt, or a
    /// platform-specific capability is unavailable). Runbooks branch on
    /// this verdict via `note_if` so flow continues with reduced data.
    NotImplemented,
}

/// Full transcript of a runbook execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunbookExecution {
    /// UUID for this execution.
    pub run_id: String,
    pub runbook_id: String,
    pub runbook_name: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Operator-supplied context (NIC, host overrides, etc.).
    pub inputs: BTreeMap<String, serde_json::Value>,
    pub steps: Vec<StepRecord>,
    /// LLM narration of the transcript. Populated after the engine finishes.
    #[serde(default)]
    pub narration: Option<String>,
    /// Final classification chosen by the engine.
    pub outcome: ExecutionOutcome,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionOutcome {
    /// No warnings, no failures — everything looked healthy.
    Clean,
    /// One or more soft warnings; user should review.
    Issues,
    /// A `fail_if` guard triggered; execution stopped early with a clear cause.
    HardFail,
    /// An exception inside the engine prevented completion.
    EngineError,
}

/// Streaming event emitted to the frontend as a runbook executes. The
/// React UI subscribes via `runbook-event` and renders the transcript
/// incrementally.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RunbookEvent {
    Started {
        run_id: String,
        runbook_id: String,
        runbook_name: String,
    },
    StepStarted {
        run_id: String,
        step_id: String,
        tool: String,
    },
    StepFinished {
        run_id: String,
        record: StepRecord,
    },
    NestedRunbookStarted {
        run_id: String,
        parent_step_id: String,
        child_runbook_id: String,
    },
    Narration {
        run_id: String,
        text: String,
    },
    Completed {
        run_id: String,
        outcome: ExecutionOutcome,
    },
    Error {
        run_id: String,
        message: String,
    },
    /// Emitted by `device.exec` when a `Mutate` / `Dangerous` command is
    /// about to fire. The UI presents an approval modal; the operator's
    /// response is fed back into `ApprovalCenter::resolve(request_id, ...)`
    /// via the `approve_runbook_step` / `deny_runbook_step` Tauri commands.
    ApprovalRequired {
        run_id: String,
        request_id: String,
        host_id: String,
        host_alias: String,
        command_id: String,
        risk: String,
        rendered: String,
    },
}
