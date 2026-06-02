import { Sparkles, AlertOctagon, AlertTriangle, Info } from "lucide-react";
import { useApp } from "../store";
import type { Narrative } from "../types";

const SEV_STYLES: Record<
  string,
  { ring: string; chip: string; Icon: React.ComponentType<{ className?: string }> }
> = {
  critical: {
    ring: "border-rose-500/40 bg-rose-500/5",
    chip: "bg-rose-500/15 text-rose-300",
    Icon: AlertOctagon,
  },
  warn: {
    ring: "border-amber-500/40 bg-amber-500/5",
    chip: "bg-amber-500/15 text-amber-300",
    Icon: AlertTriangle,
  },
  warning: {
    ring: "border-amber-500/40 bg-amber-500/5",
    chip: "bg-amber-500/15 text-amber-300",
    Icon: AlertTriangle,
  },
  info: {
    ring: "border-sky-500/40 bg-sky-500/5",
    chip: "bg-sky-500/15 text-sky-300",
    Icon: Info,
  },
};

function clock(iso: string): string {
  return new Date(iso).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function relative(iso: string): string {
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60) return `${Math.max(0, Math.round(diff))}s ago`;
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
  return `${(diff / 3600).toFixed(1)}h ago`;
}

function NarrativeCard({ n }: { n: Narrative }) {
  const styles = SEV_STYLES[n.severity] ?? SEV_STYLES.info;
  const { Icon } = styles;
  return (
    <article
      className={`rounded-2xl border ${styles.ring} p-4 shadow-sm transition-colors`}
    >
      <header className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-3">
          <span
            className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${styles.chip}`}
          >
            <Icon className="h-4 w-4" />
          </span>
          <div>
            <h3 className="text-sm font-semibold text-[var(--color-text)]">
              {n.headline}
            </h3>
            <p className="mt-0.5 text-[11px] uppercase tracking-wider text-slate-500">
              {n.trigger.replace(/_/g, " ")}
            </p>
          </div>
        </div>
        <div className="text-right text-xs text-slate-500">
          <div className="tabular-nums">{clock(n.at)}</div>
          <div className="text-[10px]">{relative(n.at)}</div>
        </div>
      </header>

      <div className="mt-3 space-y-2 text-sm">
        <p className="text-slate-300">
          <span className="text-slate-500">What happened: </span>
          {n.what_happened}
        </p>
        <p className="text-slate-300">
          <span className="text-slate-500">Likely cause: </span>
          {n.likely_cause}
        </p>
      </div>

      {n.what_to_try.length > 0 && (
        <div className="mt-3">
          <p className="text-xs font-medium uppercase tracking-wider text-slate-500">
            What to try
          </p>
          <ol className="mt-1.5 list-decimal space-y-1 pl-5 text-sm text-slate-300 marker:text-slate-500">
            {n.what_to_try.map((step, i) => (
              <li key={i}>{step}</li>
            ))}
          </ol>
        </div>
      )}

      {n.llm_summary && n.llm_summary.trim() && (
        <div className="mt-3 flex items-start gap-2 rounded-lg border border-indigo-500/30 bg-indigo-500/5 p-3 text-sm text-indigo-100">
          <Sparkles className="mt-0.5 h-4 w-4 shrink-0 text-indigo-300" />
          <p className="leading-relaxed">{n.llm_summary}</p>
        </div>
      )}
    </article>
  );
}

/**
 * Causal narratives panel (Play D). Renders the most recent narrative cards
 * newest-first and re-renders live as `narrative:new` / `narrative:update`
 * events arrive (handled by the store subscriber).
 */
export function NarrativePanel() {
  const narratives = useApp((s) => s.narratives);
  const ordered = [...narratives].reverse();

  return (
    <section>
      <div className="mb-3 flex items-end justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold uppercase tracking-wider text-[var(--color-muted)]">
            Causal narratives
          </h2>
          <p className="mt-0.5 text-xs text-slate-500">
            Detected anomalies, explained — last {Math.min(20, ordered.length)} of{" "}
            {ordered.length}
          </p>
        </div>
      </div>

      {ordered.length === 0 ? (
        <div className="rounded-2xl border border-dashed border-[var(--color-border)] bg-[var(--color-panel)]/60 px-6 py-8 text-center">
          <p className="text-sm text-[var(--color-muted)]">
            No anomalies detected yet.
          </p>
          <p className="mt-1 text-xs text-slate-500">
            The narrator watches the live telemetry stream and writes a short
            "what happened / why / what to try" card whenever something
            interesting fires.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {ordered.slice(0, 20).map((n) => (
            <NarrativeCard key={n.id} n={n} />
          ))}
        </div>
      )}
    </section>
  );
}
