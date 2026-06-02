/**
 * LivePauseControl — Pause / Resume button for the live scanner.
 *
 * Shows the current state of background monitoring (running / paused) and
 * lets the user toggle it. When running, displays a small countdown to the
 * next scan tick. When paused, shows "Resume live scan".
 *
 * Replaces the old "Run quick scan" button — the tool now scans continuously
 * by default. A separate "Scan now" affordance triggers an immediate one-off
 * scan without disturbing the monitor.
 */
import { useEffect, useState } from "react";
import { Pause, Play, RefreshCw, Loader2 } from "lucide-react";
import { useApp } from "../store";

export function LivePauseControl() {
  const monitoring = useApp((s) => s.monitoring);
  const intervalSecs = useApp((s) => s.intervalSecs);
  const lastScan = useApp((s) => s.lastScan);
  const scanning = useApp((s) => s.scanning);
  const startMonitoring = useApp((s) => s.startMonitoring);
  const stopMonitoring = useApp((s) => s.stopMonitoring);
  const runQuickScan = useApp((s) => s.runQuickScan);

  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    if (!monitoring) return;
    const id = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, [monitoring]);

  const lastFinishedMs = lastScan
    ? new Date(lastScan.finished_at).getTime()
    : null;
  const nextInSecs =
    monitoring && lastFinishedMs != null
      ? Math.max(
          0,
          Math.ceil((lastFinishedMs + intervalSecs * 1000 - now) / 1000)
        )
      : null;

  const handleToggle = async () => {
    if (monitoring) {
      await stopMonitoring();
    } else {
      await startMonitoring();
    }
  };

  return (
    <div className="flex items-center gap-2">
      {scanning ? (
        <span className="inline-flex items-center gap-1.5 rounded-full bg-[var(--color-accent)]/15 px-2.5 py-1 text-xs text-[var(--color-accent)]">
          <Loader2 className="h-3 w-3 animate-spin" />
          Scanning…
        </span>
      ) : monitoring ? (
        <span
          className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/15 px-2.5 py-1 text-xs text-emerald-300"
          title={`Next scan in ${nextInSecs ?? "?"}s`}
        >
          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
          {nextInSecs == null
            ? "Live"
            : nextInSecs === 0
              ? "Live · scanning soon"
              : `Live · next in ${nextInSecs}s`}
        </span>
      ) : (
        <span className="inline-flex items-center gap-1.5 rounded-full bg-amber-500/15 px-2.5 py-1 text-xs text-amber-300">
          <span className="h-1.5 w-1.5 rounded-full bg-amber-400" />
          Paused
        </span>
      )}

      <button
        type="button"
        onClick={() => runQuickScan()}
        disabled={scanning}
        className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)] px-3 py-1.5 text-xs text-[var(--color-muted)] transition-colors hover:text-[var(--color-text)] disabled:opacity-50"
        title="Trigger an immediate scan without disturbing the live monitor"
      >
        <RefreshCw className={`h-3.5 w-3.5 ${scanning ? "animate-spin" : ""}`} />
        Scan now
      </button>

      <button
        type="button"
        onClick={handleToggle}
        className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold transition-opacity hover:opacity-90 ${
          monitoring
            ? "bg-[var(--color-panel-2)] text-[var(--color-text)]"
            : "bg-[var(--color-accent)] text-slate-900"
        }`}
        title={monitoring ? "Pause live scanning" : "Resume live scanning"}
      >
        {monitoring ? (
          <>
            <Pause className="h-3.5 w-3.5" />
            Pause
          </>
        ) : (
          <>
            <Play className="h-3.5 w-3.5" />
            Resume
          </>
        )}
      </button>
    </div>
  );
}
