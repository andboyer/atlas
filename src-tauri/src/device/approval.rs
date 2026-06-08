//! Approval gating for `Mutate` / `Dangerous` commands.
//!
//! When a runbook step calls `device.exec` against a non-`Read` command,
//! the engine emits a `RunbookEvent::ApprovalRequired` and parks the step
//! on a oneshot until the operator resolves it through the frontend.
//!
//! Implementation: a process-global `ApprovalCenter` keyed by `(run_id,
//! request_id)`. The Tauri command `approve_runbook_step` looks the pair
//! up and fulfils the oneshot. v1 ships zero non-Read commands enabled,
//! so this whole surface is exercised by unit tests but never blocks a
//! shipped runbook.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use uuid::Uuid;

use crate::device::Risk;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Approve,
    Deny,
    /// Operator never answered before the timeout fired.
    Timeout,
}

/// Per-process pending-approvals registry. Cloned into every runbook
/// Engine that wires `device.exec`.
#[derive(Default, Clone)]
pub struct ApprovalCenter {
    inner: Arc<Mutex<HashMap<String, oneshot::Sender<Verdict>>>>,
}

impl ApprovalCenter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a new approval request. Returns a `request_id` (UUID) that
    /// the frontend will echo back to resolve the wait, plus a future
    /// the caller can await. The future resolves to `Verdict::Timeout`
    /// after `wait`.
    pub async fn request(&self, wait: Duration) -> (String, Verdict) {
        let (id, rx) = self.register();
        let verdict = self.wait_for(&id, rx, wait).await;
        (id, verdict)
    }

    /// Synchronously reserve a request id + receiver. The caller is
    /// expected to emit a `RunbookEvent::ApprovalRequired` carrying the
    /// id, then `wait_for` it. Splitting registration from awaiting lets
    /// the event reach the UI before the operator can resolve it.
    pub fn register(&self) -> (String, oneshot::Receiver<Verdict>) {
        let id = Uuid::new_v4().to_string();
        let (tx, rx) = oneshot::channel::<Verdict>();
        self.inner.lock().insert(id.clone(), tx);
        (id, rx)
    }

    /// Await an operator verdict on a previously-registered request.
    pub async fn wait_for(
        &self,
        id: &str,
        rx: oneshot::Receiver<Verdict>,
        wait: Duration,
    ) -> Verdict {
        match tokio::time::timeout(wait, rx).await {
            Ok(Ok(v)) => v,
            _ => {
                // Drop the entry so the operator's late-arriving response
                // doesn't dangle. send() will then fail with a closed
                // channel; resolve() just no-ops.
                self.inner.lock().remove(id);
                Verdict::Timeout
            }
        }
    }

    /// Operator-side: deliver a verdict to a pending request. Returns
    /// false if the id is unknown (e.g. already timed out).
    pub fn resolve(&self, request_id: &str, verdict: Verdict) -> bool {
        let tx = self.inner.lock().remove(request_id);
        match tx {
            Some(tx) => tx.send(verdict).is_ok(),
            None => false,
        }
    }

    /// Returns the list of currently-pending request ids — used by the UI
    /// to render outstanding "needs approval" cards on tab switch.
    pub fn pending(&self) -> Vec<String> {
        self.inner.lock().keys().cloned().collect()
    }
}

/// Convenience for the engine path: hold the verdict + the request id so
/// both can be threaded into the audit log.
#[derive(Debug, Clone)]
pub struct ApprovalOutcome {
    pub request_id: String,
    pub verdict: Verdict,
}

/// Returns the audit-log `approval` token for a verdict.
pub fn verdict_audit_token(v: Verdict) -> &'static str {
    match v {
        Verdict::Approve => "approved",
        Verdict::Deny => "denied",
        Verdict::Timeout => "timeout",
    }
}

/// Pretty-print risk for the approval banner.
pub fn risk_label(r: Risk) -> &'static str {
    match r {
        Risk::Read => "read",
        Risk::Mutate => "MUTATE",
        Risk::Dangerous => "DANGEROUS",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn approve_resolves_to_approve() {
        let center = ApprovalCenter::new();
        let center2 = center.clone();
        let task = tokio::spawn(async move { center2.request(Duration::from_secs(5)).await });
        // Give the request task a beat to install the oneshot.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let pending = center.pending();
        assert_eq!(pending.len(), 1);
        assert!(center.resolve(&pending[0], Verdict::Approve));
        let (_id, v) = task.await.unwrap();
        assert_eq!(v, Verdict::Approve);
    }

    #[tokio::test]
    async fn no_response_times_out() {
        let center = ApprovalCenter::new();
        let (_id, v) = center.request(Duration::from_millis(20)).await;
        assert_eq!(v, Verdict::Timeout);
        // Center should be empty after timeout (no stale entries).
        assert!(center.pending().is_empty());
    }

    #[tokio::test]
    async fn unknown_resolve_returns_false() {
        let center = ApprovalCenter::new();
        assert!(!center.resolve("not-a-real-id", Verdict::Approve));
    }
}
