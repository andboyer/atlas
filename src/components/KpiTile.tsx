import type { ReactNode } from "react";

type Tone = "good" | "warn" | "bad" | "neutral";

interface Props {
  icon: ReactNode;
  label: string;
  value: ReactNode;
  sublabel?: ReactNode;
  tone?: Tone;
}

/**
 * KPI tile. Gradient icon chip on the left, oversized tabular value on the
 * right. Tone tints both the chip + the value so a glance gives you the
 * verdict.
 */
const VALUE_TONE: Record<Tone, string> = {
  good: "text-[var(--color-good)]",
  warn: "text-[var(--color-warn)]",
  bad: "text-[var(--color-bad)]",
  neutral: "text-[var(--color-text)]",
};

const CHIP_TONE: Record<Tone, string> = {
  good: "from-emerald-500/30 to-emerald-500/10 text-emerald-300 ring-emerald-500/30",
  warn: "from-amber-500/30 to-amber-500/10 text-amber-300 ring-amber-500/30",
  bad: "from-rose-500/30 to-rose-500/10 text-rose-300 ring-rose-500/30",
  neutral: "from-[var(--color-accent)]/25 to-[var(--color-accent-2)]/10 text-[var(--color-accent)] ring-[var(--color-accent)]/25",
};

export function KpiTile({ icon, label, value, sublabel, tone = "neutral" }: Props) {
  return (
    <div className="atlas-card atlas-card-hover p-4">
      <div className="flex items-start gap-3">
        <div
          className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br ring-1 ${CHIP_TONE[tone]}`}
        >
          {icon}
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-[10px] font-medium uppercase tracking-[0.14em] text-[var(--color-muted)]">
            {label}
          </div>
          <div
            className={`mt-1 truncate text-2xl font-semibold tracking-tight tabular-nums ${VALUE_TONE[tone]}`}
            title={typeof value === "string" ? value : undefined}
          >
            {value}
          </div>
          {sublabel && (
            <div className="mt-0.5 truncate text-xs text-[var(--color-muted)]">
              {sublabel}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
