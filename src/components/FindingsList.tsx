import { useApp } from "../store";
import { SeverityBadge } from "./SeverityBadge";

export function FindingsList() {
  const findings = useApp((s) => s.lastScan?.findings) ?? [];
  const recommendations = useApp((s) => s.lastScan?.recommendations) ?? [];

  const recById = new Map(recommendations.map((r) => [r.id, r]));

  if (findings.length === 0) {
    return (
      <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-6 text-sm text-[var(--color-muted)]">
        No findings yet — run a scan to detect issues.
      </div>
    );
  }

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
    </div>
  );
}

