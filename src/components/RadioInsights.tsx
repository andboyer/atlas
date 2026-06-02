import { useApp } from "../store";
import type { RadioInsight } from "../types";

/**
 * LLM-powered RF/airspace suggestions panel. Lives on the Overview tab next
 * to the rules-engine findings. Calls the `radio_insights` backend command
 * which sends a focused, radio-only prompt to the configured LLM and asks
 * for a structured JSON list of `{ severity, title, detail, suggestion }`
 * items so we can render proper cards (not a wall of prose).
 *
 * Three render states:
 *   • no scan yet           → muted prompt to run a scan
 *   • scan, no LLM key      → muted prompt to configure a key in Settings
 *   • scan + LLM configured → Generate-suggestions button + cards
 */
export function RadioInsights() {
  const hasLastScan = useApp((s) => !!s.lastScan);
  const hasLlmKey = useApp(
    (s) => !!s.settings.llm_api_key || s.settings.llm_provider === "ollama",
  );
  const items = useApp((s) => s.radioInsights);
  const loading = useApp((s) => s.radioInsightsLoading);
  const error = useApp((s) => s.radioInsightsError);
  const load = useApp((s) => s.loadRadioInsights);

  if (!hasLastScan) {
    return (
      <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5 text-sm text-[var(--color-muted)]">
        <p className="font-medium text-[var(--color-text)]">Radio insights (AI)</p>
        <p className="mt-1">
          Run a scan to get AI-generated suggestions about your radio
          environment.
        </p>
      </div>
    );
  }

  if (!hasLlmKey) {
    return (
      <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5 text-sm text-[var(--color-muted)]">
        <p className="font-medium text-[var(--color-text)]">Radio insights (AI)</p>
        <p className="mt-1">
          Configure an LLM API key in <span className="font-medium">⚙ Settings</span> to
          generate radio suggestions.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5">
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="text-sm font-medium">Radio insights (AI)</p>
          <p className="text-xs text-[var(--color-muted)]">
            Ask the LLM to surface issues and concrete suggestions about your
            band, channel, neighbors, and PHY rates.
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
            <InsightCard key={i} insight={it} />
          ))}
        </div>
      )}
    </div>
  );
}

function InsightCard({ insight }: { insight: RadioInsight }) {
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

  return (
    <div
      className={`rounded-lg border bg-[var(--color-panel-2)] p-4 ${tone.ring}`}
    >
      <div className="flex items-start justify-between gap-3">
        <h3 className="text-sm font-semibold">{insight.title}</h3>
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

export default RadioInsights;
