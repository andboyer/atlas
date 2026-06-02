import { useState } from "react";
import { useApp } from "../store";

/**
 * Plain-language LLM summary of the most recent scan's findings.
 *
 * Self-contained — pulls scan + LLM config from the store. Renders three
 * states:
 *   • no scan yet           → muted prompt to run a scan
 *   • scan, no LLM key      → muted prompt to configure a key in Settings
 *   • scan + LLM configured → Explain-findings button + collapsible result
 */
export function AiExplanation() {
  const findings = useApp((s) => s.lastScan?.findings) ?? [];
  const explanation = useApp((s) => s.explanation);
  const explaining = useApp((s) => s.explaining);
  const explainFindings = useApp((s) => s.explainFindings);
  const hasLlmKey = useApp(
    (s) => !!s.settings.llm_api_key || s.settings.llm_provider === "ollama",
  );
  const hasLastScan = useApp((s) => !!s.lastScan);
  const [showExplanation, setShowExplanation] = useState(false);

  const handleExplain = async () => {
    setShowExplanation(true);
    if (!explanation) await explainFindings();
  };

  if (!hasLastScan) {
    return (
      <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5 text-sm text-[var(--color-muted)]">
        <p className="font-medium text-[var(--color-text)]">AI explanation</p>
        <p className="mt-1">Run a scan to get a plain-language summary of your network.</p>
      </div>
    );
  }

  if (!hasLlmKey) {
    return (
      <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5 text-sm text-[var(--color-muted)]">
        <p className="font-medium text-[var(--color-text)]">AI explanation</p>
        <p className="mt-1">
          Configure an LLM API key in <span className="font-medium">⚙ Settings</span> to get
          AI-powered explanations of your findings.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5">
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="text-sm font-medium">AI explanation</p>
          <p className="text-xs text-[var(--color-muted)]">
            {findings.length === 0
              ? "Get a plain-language summary of your current network state."
              : `Get a plain-language summary of the ${findings.length} finding${findings.length === 1 ? "" : "s"} from your last scan.`}
          </p>
        </div>
        <button
          onClick={handleExplain}
          disabled={explaining}
          className="rounded-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-medium text-white hover:opacity-90 disabled:opacity-50"
        >
          {explaining ? "Thinking…" : explanation && showExplanation ? "Refresh" : "Explain"}
        </button>
      </div>
      {showExplanation && explanation && (
        <div className="mt-4 whitespace-pre-wrap rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)] p-4 text-sm leading-relaxed">
          {explanation}
        </div>
      )}
    </div>
  );
}

export default AiExplanation;
