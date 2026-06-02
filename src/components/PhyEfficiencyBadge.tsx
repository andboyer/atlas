/**
 * PhyEfficiencyBadge — compact PHY-rate efficiency gauge.
 *
 * Visible in Pro/Admin modes. Shows how close the negotiated TX rate is to
 * the theoretical max for the link's PHY + width, plus a brief diagnostic.
 */
import { Activity } from "lucide-react";
import type { PhyEfficiency } from "../types";

interface Props {
  phy: PhyEfficiency | null | undefined;
}

function gradeColor(grade: string): string {
  switch (grade) {
    case "excellent":
      return "text-emerald-400";
    case "good":
      return "text-emerald-300";
    case "fair":
      return "text-amber-400";
    case "poor":
      return "text-rose-400";
    default:
      return "text-[var(--color-muted)]";
  }
}

function barColor(eff: number): string {
  if (eff >= 0.75) return "bg-emerald-500";
  if (eff >= 0.5) return "bg-emerald-400";
  if (eff >= 0.25) return "bg-amber-400";
  return "bg-rose-500";
}

export default function PhyEfficiencyBadge({ phy }: Props) {
  if (!phy) {
    return (
      <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5">
        <div className="flex items-center gap-2 text-sm font-semibold text-[var(--color-muted)]">
          <Activity className="h-4 w-4" />
          PHY-rate efficiency
        </div>
        <p className="mt-2 text-xs text-[var(--color-muted)]">
          Need a connected link with a known PHY mode to evaluate.
        </p>
      </div>
    );
  }

  const pct = Math.round(phy.efficiency * 100);

  return (
    <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5">
      <div className="mb-3 flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm font-semibold">
          <Activity className="h-4 w-4 text-[var(--color-accent)]" />
          PHY-rate efficiency
        </div>
        <span className={`text-xs font-semibold uppercase ${gradeColor(phy.grade)}`}>
          {phy.grade}
        </span>
      </div>

      <div className="mb-2 flex items-baseline gap-2">
        <span className="text-2xl font-semibold">{pct}%</span>
        <span className="text-xs text-[var(--color-muted)]">
          {phy.actual_mbps.toFixed(0)} / {phy.theoretical_max_mbps.toFixed(0)} Mbps theoretical
        </span>
      </div>

      <div className="mb-3 h-2 w-full overflow-hidden rounded-full bg-[var(--color-panel-2)]">
        <div
          className={`h-full ${barColor(phy.efficiency)} transition-all`}
          style={{ width: `${Math.max(2, pct)}%` }}
        />
      </div>

      <p className="text-xs text-[var(--color-muted)]">{phy.diagnostic}</p>
      <p className="mt-1 text-[10px] uppercase tracking-wide text-[var(--color-muted)]">
        {phy.phy_mode}
      </p>
    </div>
  );
}
