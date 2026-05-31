import { useState } from "react";
import { useApp } from "../store";
import { SeverityBadge } from "./SeverityBadge";

export function FindingsList() {
  const findings = useApp((s) => s.lastScan?.findings ?? []);
  const recommendations = useApp((s) => s.lastScan?.recommendations ?? []);
  const explanation = useApp((s) => s.explanation);
  const explaining = useApp((s) => s.explaining);
  const explainFindings = useApp((s) => s.explainFindings);
  const hasLlmKey = useApp((s) => !!s.settings.llm_api_key || s.settings.llm_provider === "ollama");
  const hasLastScan = useApp((s) => !!s.lastScan);
  const [showExplanation, setShowExplanation] = useState(false);

  const recById = new Map(recommendations.map((r) => [r.id, r]));

  if (findings.length === 0) {
    return (
      <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-6 text-sm text-[var(--color-muted)]">
        No findings yet — run a scan to detect issues.
      </div>
    );
  }

  const handleExplain = async () => {
    setShowExplanation(true);
    if (!explanation) await explainFindings();
  };

  return (
    <div className="space-y-3">
      {findings.map((f) => {
        const rec = f.recommendation_id ? recById.get(f.recommendation_id) : null;
        return (
          <div
            key={f.id}
            className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5"
          >
            <div className="flex items-center justify-between gap-3">
              <h3 className="text-base font-semibold">{f.title}</h3>
              <SeverityBadge severity={f.severity} />
            </div>
            {f.evidence.length > 0 && (
              <ul className="mt-3 list-disc space-y-1 pl-5 text-sm text-[var(--color-muted)]">
                {f.evidence.map((e, i) => (
                  <li key={i}>{e}</li>
                ))}
              </ul>
            )}
            {rec && (
              <div className="mt-4 rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)] p-4">
                <p className="text-sm font-medium">{rec.title}</p>
                <p className="mt-1 text-sm text-[var(--color-muted)]">
                  {rec.summary}
                </p>
                {rec.steps.length > 0 && (
                  <ol className="mt-2 list-decimal space-y-1 pl-5 text-sm">
                    {rec.steps.map((s, i) => (
                      <li key={i}>{s}</li>
                    ))}
                  </ol>
                )}
              </div>
            )}
          </div>
        );
      })}

      {/* AI explanation panel */}
      {hasLastScan && hasLlmKey && (
        <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium">AI explanation</p>
              <p className="text-xs text-[var(--color-muted)]">
                Get a plain-language summary from your configured LLM.
              </p>
            </div>
            <button
              onClick={handleExplain}
              disabled={explaining}
              className="rounded-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-medium text-white hover:opacity-90 disabled:opacity-50"
            >
              {explaining ? "Thinking…" : "Explain findings"}
            </button>
          </div>
          {showExplanation && explanation && (
            <div className="mt-4 whitespace-pre-wrap rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)] p-4 text-sm leading-relaxed">
              {explanation}
            </div>
          )}
        </div>
      )}

      {hasLastScan && !hasLlmKey && (
        <p className="text-center text-xs text-[var(--color-muted)]">
          Configure an LLM API key in ⚙ Settings to get AI-powered explanations.
        </p>
      )}
    </div>
  );
}

