import { useApp } from "../store";
import type { AvInsight } from "../types";

/**
 * LLM-powered AV-over-IP suggestions panel. Lives at the bottom of the
 * AV / Multicast tab. Calls the `av_insights` backend command which sends
 * a focused Dante / multicast / PTP prompt to the configured LLM and asks
 * for a structured JSON list of `{ severity, category, title, detail,
 * suggestion }` items so we can render proper cards (not a wall of prose).
 *
 * Three render states:
 *   • no AV diagnostics yet  → muted prompt to run the diagnostic sweep
 *   • diag, no LLM key       → muted prompt to configure a key in Settings
 *   • diag + LLM configured  → Generate-suggestions button + cards
 */
export function AvInsights() {
  const hasAv = useApp((s) => !!s.avDiagnostics);
  const hasLlmKey = useApp(
    (s) => !!s.settings.llm_api_key || s.settings.llm_provider === "ollama",
  );
  const items = useApp((s) => s.avInsights);
  const loading = useApp((s) => s.avInsightsLoading);
  const error = useApp((s) => s.avInsightsError);
  const load = useApp((s) => s.loadAvInsights);

  if (!hasAv) {
    return (
      <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5 text-sm text-[var(--color-muted)]">
        <p className="font-medium text-[var(--color-text)]">AV insights (AI)</p>
        <p className="mt-1">
          Run the AV-over-IP diagnostics above to enable AI-generated
          suggestions about Dante, multicast, and PTP health.
        </p>
      </div>
    );
  }

  if (!hasLlmKey) {
    return (
      <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5 text-sm text-[var(--color-muted)]">
        <p className="font-medium text-[var(--color-text)]">AV insights (AI)</p>
        <p className="mt-1">
          Configure an LLM API key in <span className="font-medium">⚙ Settings</span> to
          generate AV-over-IP suggestions.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5">
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="text-sm font-medium">AV insights (AI)</p>
          <p className="text-xs text-[var(--color-muted)]">
            Ask the LLM to enumerate Dante, multicast, and PTP issues — plus
            concrete switch / AP / DSP configuration changes.
          </p>
        </div>
        <button
          onClick={load}
          disabled={loading}
          className="rounded-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-medium text-white hover:opacity-90 disabled:opacity-50"
        >
          {loading
            ? "Thinking…"
            : items && items.length > 0
              ? "Regenerate"
              : "Generate suggestions"}
        </button>
      </div>

      {error && (
        <div className="mt-4 rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-300">
          {error}
        </div>
      )}

      {items && items.length > 0 && (
        <div className="mt-4 space-y-3">
          {items.map((it, i) => (
            <AvInsightCard key={i} insight={it} />
          ))}
        </div>
      )}
    </div>
  );
}

function AvInsightCard({ insight }: { insight: AvInsight }) {
  const tone =
    insight.severity === "critical"
      ? {
          ring: "border-rose-500/40",
          chip: "bg-rose-500/15 text-rose-300",
          label: "Critical",
        }
      : insight.severity === "warn"
        ? {
            ring: "border-amber-500/40",
            chip: "bg-amber-500/15 text-amber-300",
            label: "Warn",
          }
        : {
            ring: "border-sky-500/30",
            chip: "bg-sky-500/15 text-sky-300",
            label: "Info",
          };

  const catTone: Record<AvInsight["category"], string> = {
    dante: "bg-violet-500/15 text-violet-300 border-violet-500/30",
    multicast: "bg-cyan-500/15 text-cyan-300 border-cyan-500/30",
    ptp: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
    wifi: "bg-blue-500/15 text-blue-300 border-blue-500/30",
    qos: "bg-fuchsia-500/15 text-fuchsia-300 border-fuchsia-500/30",
    general: "bg-slate-500/15 text-slate-300 border-slate-500/30",
  };

  return (
    <div
      className={`rounded-lg border bg-[var(--color-panel-2)] p-4 ${tone.ring}`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2">
          <h3 className="text-sm font-semibold">{insight.title}</h3>
          <span
            className={`shrink-0 rounded-full border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide ${
              catTone[insight.category] ?? catTone.general
            }`}
          >
            {insight.category}
          </span>
        </div>
        <span
          className={`shrink-0 rounded-full px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide ${tone.chip}`}
        >
          {tone.label}
        </span>
      </div>
      {insight.detail && (
        <p className="mt-2 text-sm leading-relaxed text-[var(--color-muted)]">
          {insight.detail}
        </p>
      )}
      {insight.suggestion && (
        <div className="mt-3 rounded-md border border-[var(--color-border)] bg-[var(--color-panel)] p-3 text-xs leading-relaxed">
          <span className="font-medium text-[var(--color-text)]">
            Suggestion:
          </span>{" "}
          <span className="text-[var(--color-muted)]">{insight.suggestion}</span>
        </div>
      )}
    </div>
  );
}

export default AvInsights;
