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
  ChevronLeft,
  Search,
  Sparkles,
  Plus,
  Trash2,
  ListChecks,
  User,
} from "lucide-react";
import { useApp } from "../store";
import { RunbookBuilderModal } from "./RunbookBuilder";

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

interface UserRunbook {
  id: string;
}

type StepStatus =
  | "ok"
  | "warn"
  | "failed"
  | "skipped"
  | "denied"
  | "unavailable"
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
  | { kind: "step_finished"; run_id: string; record: StepRecord }
  | {
      kind: "nested_runbook_started";
      run_id: string;
      parent_step_id: string;
      child_runbook_id: string;
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
  denied: {
    label: "Denied",
    tone: "bg-orange-500/15 text-orange-300 border-orange-500/30",
    icon: <XCircle className="h-3.5 w-3.5" />,
  },
  unavailable: {
    label: "Unavailable",
    tone: "bg-slate-500/15 text-slate-300 border-slate-500/30",
    icon: <Clock className="h-3.5 w-3.5" />,
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
    step.status === "warn" ||
      step.status === "failed" ||
      step.status === "denied" ||
      step.status === "error",
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

/** A runbook tile in the library grid. */
function RunbookCard({
  rb,
  custom,
  busy,
  onRun,
  onDelete,
}: {
  rb: RunbookSummary;
  custom: boolean;
  busy: boolean;
  onRun: () => void;
  onDelete?: () => void;
}) {
  return (
    <div className="group flex flex-col rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-4 transition-colors hover:border-[var(--color-accent)]/50">
      <div className="mb-2 flex items-center gap-2">
        <span className="rounded-full border border-[var(--color-border)] px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-[var(--color-muted)]">
          {rb.category}
        </span>
        {custom && (
          <span className="inline-flex items-center gap-1 rounded-full border border-[var(--color-accent)]/40 bg-[var(--color-accent)]/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-[var(--color-accent)]">
            <User className="h-3 w-3" /> Custom
          </span>
        )}
      </div>
      <h3 className="text-sm font-semibold leading-snug">{rb.name}</h3>
      <p className="mt-1 line-clamp-2 text-xs text-[var(--color-muted)]">
        {rb.symptoms[0] ?? rb.description}
      </p>
      <div className="mt-3 flex items-center justify-between gap-2 border-t border-[var(--color-border)] pt-3">
        <span className="inline-flex items-center gap-1 text-[11px] text-[var(--color-muted)]">
          <ListChecks className="h-3.5 w-3.5" />
          {rb.step_count} step{rb.step_count === 1 ? "" : "s"}
        </span>
        <div className="flex items-center gap-1.5">
          {custom && onDelete && (
            <button
              type="button"
              onClick={onDelete}
              title="Delete this runbook"
              className="rounded-md p-1.5 text-rose-300 opacity-0 transition-opacity hover:bg-rose-500/10 group-hover:opacity-100"
            >
              <Trash2 className="h-3.5 w-3.5" />
            </button>
          )}
          <button
            type="button"
            disabled={busy}
            onClick={onRun}
            className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--color-accent)] px-3 py-1.5 text-xs font-semibold text-white transition-opacity hover:opacity-90 disabled:opacity-50"
          >
            <Play className="h-3.5 w-3.5" /> Run
          </button>
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main panel — a library of runbooks + a focused run view.
// ─────────────────────────────────────────────────────────────────────────────

export function RunbooksPanel() {
  const preferredInterface = useApp(
    (s) => s.settings?.preferred_interface ?? "",
  );
  const nic = preferredInterface.trim() || null;
  const pendingRunbookId = useApp((s) => s.pendingRunbookId);
  const clearPendingRunbook = useApp((s) => s.clearPendingRunbook);

  const [runbooks, setRunbooks] = useState<RunbookSummary[]>([]);
  const [userIds, setUserIds] = useState<Set<string>>(new Set());
  const [query, setQuery] = useState("");
  const [activeCategory, setActiveCategory] = useState<string>("all");
  const [showBuilder, setShowBuilder] = useState(false);

  // Run state — when a runbook is running/has run we switch to the run view.
  const [view, setView] = useState<"library" | "run">("library");
  const [activeRunbook, setActiveRunbook] = useState<RunbookSummary | null>(null);
  const [running, setRunning] = useState(false);
  const [execution, setExecution] = useState<RunbookExecution | null>(null);
  const [liveSteps, setLiveSteps] = useState<StepRecord[]>([]);
  const [liveNarration, setLiveNarration] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const activeRunId = useRef<string | null>(null);

  // Natural-language diagnosis state.
  const [diagnosing, setDiagnosing] = useState(false);
  const [noMatch, setNoMatch] = useState<string | null>(null);

  const loadCatalog = async () => {
    try {
      const [list, users] = await Promise.all([
        invoke<RunbookSummary[]>("list_runbooks"),
        invoke<UserRunbook[]>("list_user_runbooks"),
      ]);
      setRunbooks(list);
      setUserIds(new Set(users.map((u) => u.id)));
    } catch (e) {
      setError(String(e));
    }
  };

  // Load catalog once.
  useEffect(() => {
    void loadCatalog();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Subscribe to runbook events for the live transcript.
  useEffect(() => {
    let unlisten: UnlistenFn | null = null;
    void (async () => {
      unlisten = await listen<RunbookEvent>("runbook-event", (ev) => {
        const payload = ev.payload;
        if (!activeRunId.current || payload.run_id !== activeRunId.current) {
          if (payload.kind !== "started") return;
        }
        switch (payload.kind) {
          case "started":
            activeRunId.current = payload.run_id;
            setLiveSteps([]);
            setLiveNarration(null);
            break;
          case "step_finished":
            setLiveSteps((prev) => [...prev, payload.record]);
            break;
          case "narration":
            setLiveNarration(payload.text);
            break;
          case "error":
            setError(payload.message);
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

  // Categories present in the catalog, for the filter chips.
  const categories = useMemo(() => {
    const set = new Set(runbooks.map((rb) => rb.category));
    return ["all", ...Array.from(set).sort((a, b) => a.localeCompare(b))];
  }, [runbooks]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return runbooks.filter((rb) => {
      if (activeCategory !== "all" && rb.category !== activeCategory) return false;
      if (!q) return true;
      return (
        rb.name.toLowerCase().includes(q) ||
        rb.id.toLowerCase().includes(q) ||
        rb.category.toLowerCase().includes(q) ||
        rb.description.toLowerCase().includes(q) ||
        rb.symptoms.some((s) => s.toLowerCase().includes(q))
      );
    });
  }, [runbooks, query, activeCategory]);

  const runRunbook = async (rb: RunbookSummary) => {
    setActiveRunbook(rb);
    setView("run");
    setRunning(true);
    setError(null);
    setExecution(null);
    setLiveSteps([]);
    setLiveNarration(null);
    try {
      const result = await invoke<RunbookExecution>("run_runbook", {
        runbookId: rb.id,
        iface: nic ?? null,
      });
      setExecution(result);
      if (result.narration) setLiveNarration(result.narration);
    } catch (e) {
      setError(String(e));
    } finally {
      setRunning(false);
    }
  };

  // Deep-link: AV "Diagnose with…" sets a pending id — run it automatically.
  useEffect(() => {
    if (!pendingRunbookId || runbooks.length === 0) return;
    const rb = runbooks.find((r) => r.id === pendingRunbookId);
    clearPendingRunbook();
    if (rb) void runRunbook(rb);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pendingRunbookId, runbooks]);

  // Natural-language diagnosis — the search text doubles as a symptom: resolve
  // it to the best-matching runbook (deterministic, with an LLM fallback) and
  // run it automatically.
  const runDiagnosis = async () => {
    const symptom = query.trim();
    if (!symptom || diagnosing || running) return;
    setDiagnosing(true);
    setError(null);
    setNoMatch(null);
    try {
      const match = await invoke<RunbookSummary | null>("pick_runbook", {
        symptom,
      });
      if (!match) {
        setNoMatch(symptom);
        return;
      }
      await runRunbook(match);
    } catch (e) {
      setError(String(e));
    } finally {
      setDiagnosing(false);
    }
  };

  const deleteRunbook = async (id: string) => {
    if (!confirm(`Delete the runbook “${id}”?`)) return;
    try {
      await invoke("delete_user_runbook", { id });
      await loadCatalog();
    } catch (e) {
      setError(String(e));
    }
  };

  const transcript = execution?.steps.length ? execution.steps : liveSteps;
  const narration = execution?.narration ?? liveNarration;
  const busy = running || diagnosing;

  // ── Run view ────────────────────────────────────────────────────────────
  if (view === "run" && activeRunbook) {
    return (
      <div className="space-y-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <button
            type="button"
            onClick={() => setView("library")}
            className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-sm text-[var(--color-muted)] hover:bg-[var(--color-panel-2)] hover:text-[var(--color-text)]"
          >
            <ChevronLeft className="h-4 w-4" /> All runbooks
          </button>
          <button
            type="button"
            disabled={running}
            onClick={() => void runRunbook(activeRunbook)}
            className="inline-flex items-center gap-2 rounded-lg bg-[var(--color-accent)] px-3.5 py-2 text-sm font-semibold text-white transition-opacity hover:opacity-90 disabled:opacity-50"
          >
            <Play className={`h-4 w-4 ${running ? "animate-pulse" : ""}`} />
            {running ? "Running…" : "Run again"}
          </button>
        </div>

        <div className="atlas-card p-5">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-[var(--color-accent)]">
                <Stethoscope className="h-3.5 w-3.5" /> {activeRunbook.category}
              </div>
              <h2 className="mt-1 text-xl font-semibold tracking-tight">
                {activeRunbook.name}
              </h2>
              <p className="mt-1 text-sm text-[var(--color-muted)]">
                {activeRunbook.description}
              </p>
            </div>
            {execution && (
              <span
                className={`shrink-0 rounded-full px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wide ${
                  OUTCOME_META[execution.outcome].tone
                }`}
              >
                {OUTCOME_META[execution.outcome].label}
              </span>
            )}
          </div>
        </div>

        {error && (
          <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-sm text-rose-300">
            {error}
          </div>
        )}

        {narration && (
          <div className="atlas-card p-5">
            <h3 className="text-sm font-semibold uppercase tracking-wide text-[var(--color-muted)]">
              Narrative
            </h3>
            <div className="mt-2 whitespace-pre-wrap text-sm leading-relaxed text-[var(--color-fg)]">
              {narration}
            </div>
          </div>
        )}

        <div className="space-y-2">
          <h3 className="text-sm font-semibold uppercase tracking-wide text-[var(--color-muted)]">
            Steps
          </h3>
          {transcript.map((step, i) => (
            <StepCard key={`${step.step_id}-${i}`} step={step} />
          ))}
          {running && transcript.length === 0 && (
            <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)] p-4 text-sm text-[var(--color-muted)]">
              Starting probes…
            </div>
          )}
        </div>
      </div>
    );
  }

  // ── Library view ──────────────────────────────────────────────────────────
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-[var(--color-accent)]">
            <Stethoscope className="h-3.5 w-3.5" /> Troubleshooting Runbooks
          </div>
          <h2 className="mt-1 text-xl font-semibold tracking-tight">
            Guided AV / IP investigations
          </h2>
          <p className="mt-1 text-sm text-[var(--color-muted)]">
            Pick a runbook to run a chain of local probes — or describe what
            you're seeing and let Atlas choose one.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setShowBuilder(true)}
          className="inline-flex items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)] px-3.5 py-2 text-sm font-medium hover:bg-[var(--color-panel-2)]"
        >
          <Plus className="h-4 w-4" /> New runbook
        </button>
      </div>

      {/* Single smart bar — filters the grid as you type, and doubles as a
          plain-English symptom for "Diagnose & run". */}
      <div className="flex flex-col gap-2 sm:flex-row">
        <label className="relative flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--color-muted)]" />
          <input
            type="text"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setNoMatch(null);
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter") void runDiagnosis();
            }}
            placeholder="Describe a problem, or filter by name / symptom…"
            className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg)] py-2.5 pl-9 pr-3 text-sm outline-none focus:border-[var(--color-accent)]"
          />
        </label>
        <button
          type="button"
          disabled={!query.trim() || busy}
          onClick={() => void runDiagnosis()}
          className="inline-flex items-center justify-center gap-2 rounded-lg bg-gradient-to-b from-[var(--color-accent)] to-[#b8893f] px-4 py-2.5 text-sm font-semibold text-[var(--atlas-navy,#0B1F3A)] shadow-[inset_0_1px_0_rgba(255,255,255,0.25),0_6px_14px_-8px_rgba(212,162,76,0.6)] transition-opacity hover:opacity-95 disabled:opacity-50"
        >
          <Sparkles className={`h-4 w-4 ${diagnosing ? "animate-pulse" : ""}`} />
          {diagnosing ? "Diagnosing…" : "Diagnose & run"}
        </button>
      </div>

      {noMatch && (
        <div className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-300">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>
            No runbook confidently matched “{noMatch}”. Try rephrasing, or pick
            one below.
          </span>
        </div>
      )}

      {error && (
        <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-sm text-rose-300">
          {error}
        </div>
      )}

      {/* Category filter chips. */}
      {categories.length > 2 && (
        <div className="flex flex-wrap gap-2">
          {categories.map((cat) => {
            const active = cat === activeCategory;
            return (
              <button
                key={cat}
                type="button"
                onClick={() => setActiveCategory(cat)}
                className={`rounded-full border px-3 py-1 text-xs font-medium capitalize transition-colors ${
                  active
                    ? "border-[var(--color-accent)] bg-[var(--color-accent)]/10 text-[var(--color-accent)]"
                    : "border-[var(--color-border)] text-[var(--color-muted)] hover:bg-[var(--color-panel-2)]"
                }`}
              >
                {cat === "all" ? "All" : cat}
              </button>
            );
          })}
        </div>
      )}

      {/* The library grid. */}
      {filtered.length > 0 ? (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {filtered.map((rb) => (
            <RunbookCard
              key={rb.id}
              rb={rb}
              custom={userIds.has(rb.id)}
              busy={busy}
              onRun={() => void runRunbook(rb)}
              onDelete={
                userIds.has(rb.id) ? () => void deleteRunbook(rb.id) : undefined
              }
            />
          ))}
        </div>
      ) : (
        <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-8 text-center text-sm text-[var(--color-muted)]">
          {runbooks.length === 0
            ? "Loading runbooks…"
            : "No runbooks match your search."}
        </div>
      )}

      {showBuilder && (
        <RunbookBuilderModal
          onClose={() => setShowBuilder(false)}
          onSaved={() => {
            setShowBuilder(false);
            void loadCatalog();
          }}
        />
      )}
    </div>
  );
}

export default RunbooksPanel;
