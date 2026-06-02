/**
 * ScanMetaFooter — run_id + timing breadcrumb at the bottom of every tab.
 */
import { Clock } from "lucide-react";
import { useApp } from "../store";

function fmtDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function durationMs(startIso: string, endIso: string): number | null {
  try {
    return new Date(endIso).getTime() - new Date(startIso).getTime();
  } catch {
    return null;
  }
}

export function ScanMetaFooter() {
  const scan = useApp((s) => s.lastScan);
  if (!scan) return null;

  const dur = durationMs(scan.started_at, scan.finished_at);

  return (
    <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-dashed border-[var(--color-border)] px-4 py-2 text-[10px] uppercase tracking-wider text-[var(--color-muted)]">
      <span className="flex items-center gap-1.5">
        <Clock className="h-3 w-3" />
        Scan completed {fmtDate(scan.finished_at)}
        {dur != null && (
          <span className="ml-2 normal-case tracking-normal text-[var(--color-text)]">
            took {(dur / 1000).toFixed(1)}s
          </span>
        )}
      </span>
      <span className="font-mono text-[9px] normal-case tracking-normal">
        run {scan.run_id.slice(0, 8)}
      </span>
    </div>
  );
}
