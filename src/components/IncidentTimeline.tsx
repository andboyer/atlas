import { useApp } from "../store";
import type { Severity, ScanSummary } from "../types";

function severityColor(s: Severity | null): string {
  switch (s) {
    case "critical": return "bg-red-600";
    case "high":     return "bg-orange-500";
    case "medium":   return "bg-yellow-500";
    case "low":      return "bg-sky-500";
    case "info":     return "bg-slate-500";
    default:         return "bg-emerald-500";
  }
}

function severityLabel(s: Severity | null): string {
  return s ?? "clean";
}

function ScanDot({ scan }: { scan: ScanSummary }) {
  const time = new Date(scan.started_at).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  });
  const date = new Date(scan.started_at).toLocaleDateString([], {
    month: "short",
    day: "numeric",
  });
  const label =
    scan.findings_count === 0
      ? "No findings"
      : `${scan.findings_count} finding${scan.findings_count !== 1 ? "s" : ""}`;

  return (
    <div className="group relative flex flex-col items-center gap-1">
      <div
        className={`h-3 w-3 rounded-full ring-2 ring-[var(--color-bg)] transition-transform group-hover:scale-125 ${severityColor(scan.worst_severity)}`}
      />
      {/* tooltip */}
      <div className="pointer-events-none absolute bottom-full mb-2 hidden min-w-[8rem] rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)] px-3 py-2 text-xs shadow-xl group-hover:block z-10">
        <div className="font-semibold text-[var(--color-fg)]">
          {date} · {time}
        </div>
        <div className="mt-0.5 capitalize text-[var(--color-muted)]">
          {severityLabel(scan.worst_severity)}
        </div>
        <div className="mt-0.5 text-[var(--color-muted)]">{label}</div>
      </div>
      <span className="text-[9px] text-[var(--color-muted)]">{time}</span>
    </div>
  );
}

export function IncidentTimeline() {
  const recentScans = useApp((s) => s.recentScans);

  if (recentScans.length === 0) {
    return (
      <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] px-5 py-8 text-center text-sm text-[var(--color-muted)]">
        No scan history yet — run a few scans to populate the timeline.
      </div>
    );
  }

  // Show oldest → newest left-to-right
  const sorted = [...recentScans].reverse();

  // Severity legend
  const legend: Array<{ severity: Severity | null; label: string }> = [
    { severity: null, label: "clean" },
    { severity: "info", label: "info" },
    { severity: "low", label: "low" },
    { severity: "medium", label: "medium" },
    { severity: "high", label: "high" },
    { severity: "critical", label: "critical" },
  ];

  return (
    <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5">
      {/* legend */}
      <div className="mb-4 flex flex-wrap items-center gap-3">
        {legend.map((l) => (
          <span key={l.label} className="flex items-center gap-1.5 text-xs text-[var(--color-muted)]">
            <span className={`inline-block h-2.5 w-2.5 rounded-full ${severityColor(l.severity)}`} />
            {l.label}
          </span>
        ))}
      </div>

      {/* timeline dots connected by a line */}
      <div className="relative">
        {/* horizontal connector */}
        <div className="absolute top-[5px] left-0 right-0 h-px bg-[var(--color-border)]" />
        <div className="relative flex flex-wrap gap-x-4 gap-y-6">
          {sorted.map((scan) => (
            <ScanDot key={scan.run_id} scan={scan} />
          ))}
        </div>
      </div>

      <p className="mt-4 text-xs text-[var(--color-muted)]">
        Hover a dot to see details · {recentScans.length} scan
        {recentScans.length !== 1 ? "s" : ""} shown
      </p>
    </div>
  );
}
