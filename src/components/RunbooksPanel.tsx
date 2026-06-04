import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import {
  Stethoscope,
  Play,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Clock,
  ChevronDown,
  ChevronRight,
  Search,
} from "lucide-react";
import { useApp } from "../store";

// ─────────────────────────────────────────────────────────────────────────────
// Types — mirror the Rust runbook engine surface.
// ─────────────────────────────────────────────────────────────────────────────

interface RunbookSummary {
  id: string;
  name: string;
  category: string;
  description: string;
  applies_to: string[];
  symptoms: string[];
  step_count: number;
}

type StepStatus =
  | "ok"
  | "warn"
  | "failed"
  | "skipped"
  | "error"
  | "not_implemented";

interface StepRecord {
  step_id: string;
  tool: string;
  args_json: unknown;
  started_at: string;
  duration_ms: number;
  status: StepStatus;
  result: unknown;
  warnings: string[];
  notes: string[];
  error: string | null;
  spawned_runbook: string | null;
}

type ExecutionOutcome = "clean" | "issues" | "hard_fail" | "engine_error";

interface RunbookExecution {
  run_id: string;
  runbook_id: string;
  runbook_name: string;
  started_at: string;
  completed_at: string | null;
  inputs: unknown;
  steps: StepRecord[];
  narration: string | null;
  outcome: ExecutionOutcome;
}

type RunbookEvent =
  | { kind: "started"; run_id: string; runbook_id: string; runbook_name: string }
  | { kind: "step_started"; run_id: string; step_id: string; tool: string }
  | { kind: "step_finished"; run_id: string; step: StepRecord }
  | {
      kind: "nested_runbook_started";
      run_id: string;
      parent_run_id: string;
      runbook_id: string;
    }
  | { kind: "narration"; run_id: string; text: string }
  | { kind: "completed"; run_id: string; outcome: ExecutionOutcome }
  | { kind: "error"; run_id: string; message: string };

// ─────────────────────────────────────────────────────────────────────────────
// UI helpers
// ─────────────────────────────────────────────────────────────────────────────

const STATUS_META: Record<
  StepStatus,
  { label: string; tone: string; icon: ReactNode }
> = {
  ok: {
    label: "OK",
    tone: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
    icon: <CheckCircle2 className="h-3.5 w-3.5" />,
  },
  warn: {
    label: "Warning",
    tone: "bg-amber-500/15 text-amber-300 border-amber-500/30",
    icon: <AlertTriangle className="h-3.5 w-3.5" />,
  },
  failed: {
    label: "Failed",
    tone: "bg-rose-500/15 text-rose-300 border-rose-500/30",
    icon: <XCircle className="h-3.5 w-3.5" />,
  },
  skipped: {
    label: "Skipped",
    tone: "bg-slate-500/15 text-slate-300 border-slate-500/30",
    icon: <ChevronRight className="h-3.5 w-3.5" />,
  },
  error: {
    label: "Engine error",
    tone: "bg-rose-500/15 text-rose-300 border-rose-500/30",
    icon: <XCircle className="h-3.5 w-3.5" />,
  },
  not_implemented: {
    label: "Not implemented",
    tone: "bg-slate-500/15 text-slate-300 border-slate-500/30",
    icon: <Clock className="h-3.5 w-3.5" />,
  },
};

const OUTCOME_META: Record<
  ExecutionOutcome,
  { label: string; tone: string }
> = {
  clean: { label: "Clean", tone: "bg-emerald-500/15 text-emerald-300" },
  issues: { label: "Issues found", tone: "bg-amber-500/15 text-amber-300" },
  hard_fail: { label: "Hard fail", tone: "bg-rose-500/15 text-rose-300" },
  engine_error: {
    label: "Engine error",
    tone: "bg-rose-500/15 text-rose-300",
  },
};

function StatusPill({ status }: { status: StepStatus }) {
  const meta = STATUS_META[status];
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${meta.tone}`}
    >
      {meta.icon}
      {meta.label}
    </span>
  );
}

function StepCard({ step }: { step: StepRecord }) {
  const [open, setOpen] = useState(
    step.status === "warn" || step.status === "failed" || step.status === "error",
  );
  const pretty = useMemo(() => {
    try {
      return JSON.stringify(step.result, null, 2);
    } catch {
      return String(step.result);
    }
  }, [step.result]);

  return (
    <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)]">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left"
      >
        <div className="flex flex-1 items-center gap-3 min-w-0">
          {open ? (
            <ChevronDown className="h-4 w-4 shrink-0 text-[var(--color-muted)]" />
          ) : (
            <ChevronRight className="h-4 w-4 shrink-0 text-[var(--color-muted)]" />
          )}
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-semibold">{step.step_id}</span>
              <code className="rounded bg-black/30 px-1.5 py-0.5 text-[10px] text-[var(--color-muted)]">
                {step.tool}
              </code>
            </div>
            <div className="mt-0.5 text-[11px] text-[var(--color-muted)]">
              {step.duration_ms} ms
            </div>
          </div>
        </div>
        <StatusPill status={step.status} />
      </button>

      {open && (
        <div className="border-t border-[var(--color-border)] px-4 py-3 text-sm">
          {step.warnings.length > 0 && (
            <div className="mb-3 space-y-1">
              {step.warnings.map((w, i) => (
                <div
                  key={i}
                  className="rounded border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-amber-200"
                >
                  <span className="font-semibold uppercase tracking-wide text-[10px] mr-2">
                    Warning
                  </span>
                  {w}
                </div>
              ))}
            </div>
          )}
          {step.notes.length > 0 && (
            <div className="mb-3 space-y-1">
              {step.notes.map((n, i) => (
                <div
                  key={i}
                  className="rounded border border-sky-500/30 bg-sky-500/10 px-3 py-2 text-sky-200"
                >
                  <span className="font-semibold uppercase tracking-wide text-[10px] mr-2">
                    Note
                  </span>
                  {n}
                </div>
              ))}
            </div>
          )}
          {step.error && (
            <div className="mb-3 rounded border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-rose-200">
              <span className="font-semibold uppercase tracking-wide text-[10px] mr-2">
                Error
              </span>
              {step.error}
            </div>
          )}
          {step.spawned_runbook && (
            <div className="mb-3 rounded border border-violet-500/30 bg-violet-500/10 px-3 py-2 text-violet-200">
              Spawned nested runbook:{" "}
              <code className="text-violet-100">{step.spawned_runbook}</code>
            </div>
          )}
          <details className="text-xs">
            <summary className="cursor-pointer text-[var(--color-muted)]">
              Captured data
            </summary>
            <pre className="mt-2 max-h-72 overflow-auto rounded bg-black/40 p-3 font-mono text-[11px] leading-relaxed text-slate-300">
              {pretty}
            </pre>
          </details>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main panel
// ─────────────────────────────────────────────────────────────────────────────

export function RunbooksPanel() {
  const preferredInterface = useApp(
    (s) => s.settings?.preferred_interface ?? "",
  );
  const nic = preferredInterface.trim() || null;
  const [runbooks, setRunbooks] = useState<RunbookSummary[]>([]);
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [execution, setExecution] = useState<RunbookExecution | null>(null);
  const [liveSteps, setLiveSteps] = useState<StepRecord[]>([]);
  const [liveNarration, setLiveNarration] = useState<string | null>(null);
  const [liveRunbookName, setLiveRunbookName] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const activeRunId = useRef<string | null>(null);

  // Load catalog once.
  useEffect(() => {
    void (async () => {
      try {
        const list = await invoke<RunbookSummary[]>("list_runbooks");
        setRunbooks(list);
        if (list.length > 0 && !selected) setSelected(list[0].id);
      } catch (e) {
        setError(String(e));
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Subscribe to runbook events for live transcript.
  useEffect(() => {
    let unlisten: UnlistenFn | null = null;
    void (async () => {
      unlisten = await listen<RunbookEvent>("runbook-event", (ev) => {
        const payload = ev.payload;
        if (!activeRunId.current || payload.run_id !== activeRunId.current) {
          // Only display events for the currently-active run.
          if (payload.kind !== "started") return;
        }
        switch (payload.kind) {
          case "started":
            activeRunId.current = payload.run_id;
            setLiveSteps([]);
            setLiveNarration(null);
            setLiveRunbookName(payload.runbook_name);
            break;
          case "step_finished":
            setLiveSteps((prev) => [...prev, payload.step]);
            break;
          case "narration":
            setLiveNarration(payload.text);
            break;
          case "error":
            setError(payload.message);
            break;
          case "completed":
            // Final RunbookExecution will arrive via the run_runbook
            // Promise; nothing else to do here.
            break;
          default:
            break;
        }
      });
    })();
    return () => {
      if (unlisten) unlisten();
    };
  }, []);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return runbooks;
    return runbooks.filter(
      (rb) =>
        rb.name.toLowerCase().includes(q) ||
        rb.id.toLowerCase().includes(q) ||
        rb.category.toLowerCase().includes(q) ||
        rb.description.toLowerCase().includes(q) ||
        rb.symptoms.some((s) => s.toLowerCase().includes(q)),
    );
  }, [runbooks, query]);

  const byCategory = useMemo(() => {
    const buckets = new Map<string, RunbookSummary[]>();
    for (const rb of filtered) {
      const arr = buckets.get(rb.category) ?? [];
      arr.push(rb);
      buckets.set(rb.category, arr);
    }
    return Array.from(buckets.entries()).sort((a, b) => a[0].localeCompare(b[0]));
  }, [filtered]);

  const selectedSummary = runbooks.find((rb) => rb.id === selected);

  const runSelected = async () => {
    if (!selected) return;
    setRunning(true);
    setError(null);
    setExecution(null);
    setLiveSteps([]);
    setLiveNarration(null);
    setLiveRunbookName(selectedSummary?.name ?? null);
    try {
      const result = await invoke<RunbookExecution>("run_runbook", {
        runbookId: selected,
        iface: nic ?? null,
      });
      setExecution(result);
      // Final narration on the result trumps any partial event.
      if (result.narration) setLiveNarration(result.narration);
    } catch (e) {
      setError(String(e));
    } finally {
      setRunning(false);
    }
  };

  const transcript = execution?.steps.length ? execution.steps : liveSteps;
  const narration = execution?.narration ?? liveNarration;

  return (
    <div className="space-y-6">
      <div className="atlas-card flex flex-col gap-4 p-5">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-[var(--color-accent)]">
              <Stethoscope className="h-3.5 w-3.5" /> Troubleshooting Runbooks
            </div>
            <h2 className="mt-1 text-xl font-semibold tracking-tight">
              Guided AV / IP investigations
            </h2>
            <p className="mt-1 text-sm leading-relaxed text-[var(--color-muted)]">
              Each runbook chains local probes (PTP, DSCP, multicast, Dante
              browse, SAP, LLDP, reachability) and uses your configured LLM to
              narrate the findings.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              type="button"
              disabled={!selected || running}
              onClick={runSelected}
              className="inline-flex items-center gap-2 rounded-lg bg-gradient-to-b from-[var(--color-accent)] to-[#b8893f] px-3.5 py-2 text-sm font-semibold text-[var(--atlas-navy,#0B1F3A)] shadow-[inset_0_1px_0_rgba(255,255,255,0.25),0_6px_14px_-8px_rgba(212,162,76,0.6)] transition-opacity hover:opacity-95 disabled:opacity-50"
            >
              <Play className={`h-4 w-4 ${running ? "animate-pulse" : ""}`} />
              {running ? "Running…" : "Run runbook"}
            </button>
          </div>
        </div>

        {error && (
          <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-sm text-rose-300">
            {error}
          </div>
        )}

        <label className="relative block">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--color-muted)]" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter by symptom, name, or category…"
            className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] pl-9 pr-3 py-2 text-sm outline-none focus:border-[var(--color-accent)]"
          />
        </label>
      </div>

      <div className="grid gap-6 lg:grid-cols-[minmax(0,320px)_1fr]">
        <section className="space-y-4">
          {byCategory.map(([cat, items]) => (
            <div
              key={cat}
              className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-3"
            >
              <div className="px-2 pb-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-[var(--color-muted)]">
                {cat}
              </div>
              <ul className="space-y-1">
                {items.map((rb) => {
                  const active = rb.id === selected;
                  return (
                    <li key={rb.id}>
                      <button
                        type="button"
                        onClick={() => setSelected(rb.id)}
                        className={`block w-full rounded-lg border px-3 py-2 text-left transition-colors ${
                          active
                            ? "border-[var(--color-accent)] bg-[var(--color-accent)]/10"
                            : "border-transparent hover:border-[var(--color-border)] hover:bg-white/5"
                        }`}
                      >
                        <div className="text-sm font-semibold">{rb.name}</div>
                        <div className="mt-0.5 text-[11px] text-[var(--color-muted)] line-clamp-2">
                          {rb.symptoms[0] ?? rb.description}
                        </div>
                      </button>
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
          {byCategory.length === 0 && (
            <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-6 text-sm text-[var(--color-muted)]">
              {runbooks.length === 0
                ? "Loading runbooks…"
                : "No runbooks match this filter."}
            </div>
          )}
        </section>

        <section className="space-y-4">
          {selectedSummary && (
            <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <h3 className="text-lg font-semibold">
                    {selectedSummary.name}
                  </h3>
                  <p className="mt-1 text-sm text-[var(--color-muted)]">
                    {selectedSummary.description}
                  </p>
                </div>
                <span className="rounded-full border border-[var(--color-border)] px-2 py-0.5 text-[10px] uppercase tracking-wide text-[var(--color-muted)]">
                  {selectedSummary.step_count} step
                  {selectedSummary.step_count === 1 ? "" : "s"}
                </span>
              </div>
              {selectedSummary.symptoms.length > 0 && (
                <ul className="mt-3 grid gap-1 text-xs text-[var(--color-muted)] sm:grid-cols-2">
                  {selectedSummary.symptoms.map((s, i) => (
                    <li key={i} className="flex items-start gap-2">
                      <span className="mt-1 h-1 w-1 shrink-0 rounded-full bg-[var(--color-accent)]" />
                      <span>{s}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}

          {(transcript.length > 0 || running || execution) && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold uppercase tracking-wide text-[var(--color-muted)]">
                  Transcript
                  {liveRunbookName && (
                    <span className="ml-2 text-[var(--color-fg)] normal-case">
                      {liveRunbookName}
                    </span>
                  )}
                </h3>
                {execution && (
                  <span
                    className={`rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${
                      OUTCOME_META[execution.outcome].tone
                    }`}
                  >
                    {OUTCOME_META[execution.outcome].label}
                  </span>
                )}
              </div>
              <div className="space-y-2">
                {transcript.map((step, i) => (
                  <StepCard key={`${step.step_id}-${i}`} step={step} />
                ))}
              </div>
              {running && transcript.length === 0 && (
                <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)] p-4 text-sm text-[var(--color-muted)]">
                  Starting probes…
                </div>
              )}
            </div>
          )}

          {narration && (
            <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5">
              <h3 className="text-sm font-semibold uppercase tracking-wide text-[var(--color-muted)]">
                Narrative
              </h3>
              <div className="mt-2 whitespace-pre-wrap text-sm leading-relaxed text-[var(--color-fg)]">
                {narration}
              </div>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}

export default RunbooksPanel;
