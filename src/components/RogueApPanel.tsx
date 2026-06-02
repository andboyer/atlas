/**
 * RogueApPanel — flagged evil-twin / mixed-security / suspicious AP findings.
 *
 * Visible in Admin mode. Each finding is rendered as a severity-colored card
 * with the SSID, the reason it was flagged, and the BSSIDs involved.
 */
import { ShieldAlert } from "lucide-react";
import type { RogueApFinding, Severity } from "../types";

interface Props {
  findings: RogueApFinding[] | null | undefined;
}

function sevClasses(sev: Severity): string {
  switch (sev) {
    case "critical":
    case "high":
      return "border-rose-500/40 bg-rose-500/10 text-rose-200";
    case "medium":
      return "border-amber-500/40 bg-amber-500/10 text-amber-200";
    case "low":
      return "border-sky-500/40 bg-sky-500/10 text-sky-200";
    default:
      return "border-[var(--color-border)] bg-[var(--color-panel-2)] text-[var(--color-muted)]";
  }
}

export default function RogueApPanel({ findings }: Props) {
  const items = findings ?? [];
  return (
    <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5">
      <div className="mb-3 flex items-center gap-2 text-sm font-semibold">
        <ShieldAlert className="h-4 w-4 text-[var(--color-accent)]" />
        Suspicious access points
      </div>

      {items.length === 0 ? (
        <p className="text-xs text-[var(--color-muted)]">
          No rogue / evil-twin signatures detected in the latest scan.
        </p>
      ) : (
        <div className="space-y-2">
          {items.map((f, i) => (
            <div
              key={`${f.ssid}-${i}`}
              className={`rounded-lg border p-3 text-xs ${sevClasses(f.severity)}`}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="font-semibold">
                  {f.ssid || "(hidden SSID)"}
                </span>
                <span className="rounded-full bg-black/30 px-2 py-0.5 text-[10px] uppercase tracking-wide">
                  {f.severity}
                </span>
              </div>
              <p className="mt-1 opacity-90">{f.reason}</p>
              {f.security_modes.length > 1 && (
                <p className="mt-1 text-[11px] opacity-80">
                  Security modes seen: {f.security_modes.join(", ")}
                </p>
              )}
              {f.bssids.length > 0 && (
                <p className="mt-1 font-mono text-[10px] opacity-70">
                  {f.bssids.slice(0, 4).join("  ")}
                  {f.bssids.length > 4 && ` (+${f.bssids.length - 4} more)`}
                </p>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
