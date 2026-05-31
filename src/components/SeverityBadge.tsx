import clsx from "clsx";
import type { Severity } from "../types";

const styles: Record<Severity, string> = {
  info: "bg-sky-500/15 text-sky-300 border-sky-500/30",
  low: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  medium: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  high: "bg-orange-500/15 text-orange-300 border-orange-500/30",
  critical: "bg-rose-500/15 text-rose-300 border-rose-500/30",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={clsx(
        "inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium uppercase tracking-wide",
        styles[severity],
      )}
    >
      {severity}
    </span>
  );
}
