import type { ReactNode } from "react";

type Tone = "good" | "warn" | "bad" | "neutral";

interface Props {
  icon: ReactNode;
  label: string;
  value: ReactNode;
  sublabel?: ReactNode;
  tone?: Tone;
}

const TONE: Record<Tone, string> = {
  good: "text-[var(--color-good)]",
  warn: "text-[var(--color-warn)]",
  bad: "text-[var(--color-bad)]",
  neutral: "text-[var(--color-text)]",
};

export function KpiTile({ icon, label, value, sublabel, tone = "neutral" }: Props) {
  return (
    <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-4">
      <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-[var(--color-muted)]">
        {icon}
        <span>{label}</span>
      </div>
      <div className={`mt-2 text-2xl font-semibold ${TONE[tone]}`}>{value}</div>
      {sublabel && (
        <div className="mt-1 text-xs text-[var(--color-muted)]">{sublabel}</div>
      )}
    </div>
  );
}
