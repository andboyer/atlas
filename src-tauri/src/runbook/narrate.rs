//! LLM narration of a completed runbook execution.
//!
//! The narrator gets the entire deterministic transcript as JSON and is
//! asked for an operator-facing summary: what we checked, what was OK,
//! what was wrong, and what to do next. It cannot pick which steps ran;
//! it only translates evidence into prose.

use crate::llm::{dispatch_public, ChatMessage};
use crate::runbook::{engine::LlmConfig, ExecutionOutcome, Runbook, StepRecord, StepStatus};
use anyhow::Result;
use serde_json::Value;
use std::collections::BTreeMap;

/// Build the system + user messages and dispatch to the configured LLM.
pub async fn narrate(
    cfg: &LlmConfig,
    rb: &Runbook,
    steps: &[StepRecord],
    bindings: &BTreeMap<String, Value>,
) -> Result<String> {
    let system = system_msg();
    let user = user_msg(rb, steps, bindings);
    let messages = vec![
        ChatMessage {
            role: "system".into(),
            content: system,
        },
        ChatMessage {
            role: "user".into(),
            content: user,
        },
    ];
    dispatch_public(
        &cfg.provider,
        &cfg.api_key,
        &cfg.model,
        cfg.base_url.as_deref(),
        &messages,
    )
    .await
}

fn system_msg() -> String {
    "You are an audio-over-IP network engineer summarising the results of a \
     deterministic troubleshooting runbook for the operator. Be specific, factual, \
     and concise. Cite step ids inline when referencing evidence. Do not invent \
     evidence that is not in the transcript. Structure your response as: \
     (1) a one-sentence verdict, (2) a bulleted list of concrete findings with \
     the worst issue first, (3) the next 1–3 actions to take. \
     Audience: AV technician, comfortable with VLANs / IGMP / PTP / DSCP. \
     Skip generic explanations of those protocols — explain only what is wrong \
     with THIS network."
        .to_string()
}

fn user_msg(rb: &Runbook, steps: &[StepRecord], bindings: &BTreeMap<String, Value>) -> String {
    let mut out = String::new();
    out.push_str(&format!("# Runbook: {} ({})\n", rb.name, rb.id));
    if !rb.description.is_empty() {
        out.push_str(&format!("Description: {}\n", rb.description));
    }
    out.push_str(&format!("Applies to: {}\n\n", rb.applies_to.join(", ")));

    out.push_str("## Inputs\n");
    for (k, v) in bindings.iter() {
        // Only echo small primitive inputs; the per-step results section
        // already covers bound probe results.
        if matches!(v, Value::String(_) | Value::Number(_) | Value::Bool(_)) {
            out.push_str(&format!("- {k}: {v}\n"));
        }
    }

    out.push_str("\n## Steps executed\n");
    for s in steps {
        let icon = match s.status {
            StepStatus::Ok => "✓",
            StepStatus::Warn => "!",
            StepStatus::Failed => "✗",
            StepStatus::Skipped => "·",
            StepStatus::Error => "?",
            StepStatus::NotImplemented => "…",
        };
        out.push_str(&format!(
            "\n### {icon} `{}` (tool: {}, {:?}, {} ms)\n",
            s.step_id, s.tool, s.status, s.duration_ms
        ));
        if let Some(err) = &s.error {
            out.push_str(&format!("Error: {err}\n"));
        }
        for w in &s.warnings {
            out.push_str(&format!("WARN: {w}\n"));
        }
        for n in &s.notes {
            out.push_str(&format!("NOTE: {n}\n"));
        }
        if let Some(result) = &s.result {
            // Trim very large probe payloads to keep prompts under control.
            let mut compact = serde_json::to_string(result).unwrap_or_default();
            if compact.len() > 3000 {
                compact.truncate(2997);
                compact.push_str("...");
            }
            out.push_str(&format!("RESULT: {compact}\n"));
        }
        if let Some(child) = &s.spawned_runbook {
            out.push_str(&format!("Triggered nested runbook: `{child}`\n"));
        }
    }

    let final_outcome = derive_outcome(steps);
    out.push_str(&format!("\n## Final outcome: {final_outcome:?}\n"));

    out
}

fn derive_outcome(steps: &[StepRecord]) -> ExecutionOutcome {
    let mut out = ExecutionOutcome::Clean;
    for s in steps {
        match s.status {
            StepStatus::Failed => return ExecutionOutcome::HardFail,
            StepStatus::Warn | StepStatus::Error if out == ExecutionOutcome::Clean => {
                out = ExecutionOutcome::Issues;
            }
            _ => {}
        }
    }
    out
}
