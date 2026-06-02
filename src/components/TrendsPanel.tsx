import { TrendingDown, TrendingUp, Minus, Activity } from "lucide-react";
import { useApp } from "../store";
import type { TrendDelta } from "../types";

export function TrendsPanel() {
  const trends = useApp((s) => s.lastScan?.trends ?? null);

  if (!trends || trends.deltas.length === 0) return null;

  return (
    <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5">
      <div className="mb-3 flex items-center gap-2">
        <Activity className="h-4 w-4 text-[var(--color-accent)]" />
        <h2 className="text-sm font-semibold uppercase tracking-wide text-[var(--color-muted)]">
          Trend vs previous hour
        </h2>
        <span className="ml-auto text-xs text-[var(--color-muted)]">
          {trends.samples_considered} samples
        </span>
      </div>
      <ul className="space-y-1.5 text-sm">
        {trends.deltas.map((d) => (
          <TrendRow key={d.metric} delta={d} />
        ))}
      </ul>
    </div>
  );
}

function TrendRow({ delta }: { delta: TrendDelta }) {
  const tone =
    delta.direction === "improved"
      ? "text-emerald-300"
      : delta.direction === "degraded"
        ? "text-rose-300"
        : "text-[var(--color-muted)]";
  const Icon =
    delta.direction === "improved"
      ? TrendingUp
      : delta.direction === "degraded"
        ? TrendingDown
        : Minus;
  const sign = delta.delta > 0 ? "+" : "";
  return (
    <li className="flex items-center justify-between gap-3 border-t border-[var(--color-border)]/50 pt-1.5 first:border-t-0 first:pt-0">
      <span className="flex items-center gap-2">
        <Icon className={`h-3.5 w-3.5 ${tone}`} />
        <span>{delta.label}</span>
      </span>
      <span className="text-right text-xs text-[var(--color-muted)]">
        <span className="text-[var(--color-text)]">{fmt(delta.current)}</span>
        <span className="mx-1.5">vs</span>
        <span>{fmt(delta.prev_hour_avg)}</span>
        <span className={`ml-2 font-mono ${tone}`}>
          {sign}
          {fmt(delta.delta)}
        </span>
      </span>
    </li>
  );
}

function fmt(n: number): string {
  if (Math.abs(n) >= 100) return n.toFixed(0);
  if (Math.abs(n) >= 10) return n.toFixed(1);
  return n.toFixed(2);
}
