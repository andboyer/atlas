import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import {
  ShieldAlert,
  Check,
  X as XIcon,
  Terminal,
  Server,
} from "lucide-react";

interface ApprovalRequest {
  run_id: string;
  request_id: string;
  host_id: string;
  host_alias: string;
  command_id: string;
  risk: "read" | "mutate" | "dangerous";
  rendered: string;
  // Time the request was first observed (client wall clock).
  observed_at: number;
}

interface ApprovalRequiredEvent {
  kind: "approval_required";
  run_id: string;
  request_id: string;
  host_id: string;
  host_alias: string;
  command_id: string;
  risk: "read" | "mutate" | "dangerous";
  rendered: string;
}

const RISK_TONE: Record<ApprovalRequest["risk"], string> = {
  read: "border-emerald-500/40 bg-emerald-500/10 text-emerald-200",
  mutate: "border-amber-500/40 bg-amber-500/10 text-amber-200",
  dangerous: "border-rose-500/40 bg-rose-500/10 text-rose-200",
};

/**
 * Always-on listener for `runbook-event` of kind `approval_required`.
 * Surfaces a modal stack of pending requests; operator approves or denies
 * each. Mounted once at the App root.
 */
export function ApprovalModal() {
  const [queue, setQueue] = useState<ApprovalRequest[]>([]);
  const [resolving, setResolving] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let unlisten: UnlistenFn | null = null;
    (async () => {
      unlisten = await listen<ApprovalRequiredEvent>(
        "runbook-event",
        (ev) => {
          if (ev.payload.kind !== "approval_required") return;
          const next: ApprovalRequest = {
            run_id: ev.payload.run_id,
            request_id: ev.payload.request_id,
            host_id: ev.payload.host_id,
            host_alias: ev.payload.host_alias,
            command_id: ev.payload.command_id,
            risk: ev.payload.risk,
            rendered: ev.payload.rendered,
            observed_at: Date.now(),
          };
          setQueue((q) =>
            q.find((r) => r.request_id === next.request_id) ? q : [...q, next],
          );
        },
      );
    })();
    return () => {
      if (unlisten) unlisten();
    };
  }, []);

  const respond = async (req: ApprovalRequest, approve: boolean) => {
    setResolving(req.request_id);
    setError(null);
    try {
      await invoke<boolean>(
        approve ? "approve_runbook_step" : "deny_runbook_step",
        { requestId: req.request_id },
      );
      setQueue((q) => q.filter((r) => r.request_id !== req.request_id));
    } catch (e) {
      setError(String(e));
    } finally {
      setResolving(null);
    }
  };

  if (queue.length === 0) return null;
  const current = queue[0];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
      <div className="w-full max-w-xl rounded-xl border border-[var(--color-border)] bg-[var(--color-panel)] shadow-2xl">
        <header className="flex items-center justify-between border-b border-[var(--color-border)] px-4 py-3">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-5 w-5 text-amber-300" />
            <h2 className="text-sm font-semibold uppercase tracking-wide">
              Runbook step requires approval
            </h2>
          </div>
          {queue.length > 1 && (
            <span className="rounded border border-[var(--color-border)] px-2 py-0.5 text-[10px] text-[var(--color-muted)]">
              {queue.length} pending
            </span>
          )}
        </header>

        <div className="space-y-3 px-4 py-4">
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div>
              <div className="text-[10px] uppercase tracking-wide text-[var(--color-muted)]">
                Host
              </div>
              <div className="mt-0.5 inline-flex items-center gap-1">
                <Server className="h-3 w-3 text-[var(--color-muted)]" />
                <span className="font-semibold">{current.host_alias}</span>
                <code className="ml-1 rounded bg-black/30 px-1 py-0.5 text-[10px] text-[var(--color-muted)]">
                  {current.host_id}
                </code>
              </div>
            </div>
            <div>
              <div className="text-[10px] uppercase tracking-wide text-[var(--color-muted)]">
                Command
              </div>
              <div className="mt-0.5 inline-flex items-center gap-1">
                <Terminal className="h-3 w-3 text-[var(--color-muted)]" />
                <code className="font-semibold">{current.command_id}</code>
                <span
                  className={`ml-2 rounded border px-1.5 py-0.5 text-[10px] uppercase ${RISK_TONE[current.risk]}`}
                >
                  {current.risk}
                </span>
              </div>
            </div>
          </div>

          <div>
            <div className="mb-1 text-[10px] uppercase tracking-wide text-[var(--color-muted)]">
              Rendered command
            </div>
            <pre className="max-h-48 overflow-auto rounded border border-[var(--color-border)] bg-black/40 p-3 font-mono text-[11px] leading-relaxed text-slate-200">
              {current.rendered}
            </pre>
          </div>

          {error && (
            <div className="rounded border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-200">
              {error}
            </div>
          )}
        </div>

        <footer className="flex items-center justify-end gap-2 border-t border-[var(--color-border)] px-4 py-3">
          <button
            type="button"
            disabled={resolving === current.request_id}
            onClick={() => respond(current, false)}
            className="inline-flex items-center gap-1 rounded border border-rose-500/50 bg-rose-500/15 px-3 py-1.5 text-xs text-rose-200 hover:bg-rose-500/25 disabled:opacity-50"
          >
            <XIcon className="h-3.5 w-3.5" />
            Deny
          </button>
          <button
            type="button"
            disabled={resolving === current.request_id}
            onClick={() => respond(current, true)}
            className="inline-flex items-center gap-1 rounded border border-emerald-500/50 bg-emerald-500/15 px-3 py-1.5 text-xs text-emerald-200 hover:bg-emerald-500/25 disabled:opacity-50"
          >
            <Check className="h-3.5 w-3.5" />
            {resolving === current.request_id ? "Approving…" : "Approve"}
          </button>
        </footer>
      </div>
    </div>
  );
}

export default ApprovalModal;
