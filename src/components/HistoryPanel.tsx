import { useEffect } from "react";
import { useApp } from "../store";

function eventColor(t: string): string {
  if (t === "offline") return "text-red-400";
  if (t === "online") return "text-emerald-400";
  return "text-sky-400";
}

function formatTime(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleString();
  } catch {
    return iso;
  }
}

export function HistoryPanel() {
  const recentScans = useApp((s) => s.recentScans);
  const recentEvents = useApp((s) => s.recentEvents);
  const refreshHistory = useApp((s) => s.refreshHistory);

  useEffect(() => {
    void refreshHistory();
  }, [refreshHistory]);

  return (
    <div className="grid gap-6 md:grid-cols-2">
      <section className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5">
        <header className="mb-3 flex items-center justify-between">
          <h3 className="text-sm font-semibold">Recent scans</h3>
          <button
            type="button"
            onClick={() => void refreshHistory()}
            className="text-xs text-[var(--color-muted)] hover:text-white"
          >
            Refresh
          </button>
        </header>
        {recentScans.length === 0 ? (
          <p className="text-sm text-[var(--color-muted)]">
            No scans recorded yet. Run a scan to start building history.
          </p>
        ) : (
          <ul className="space-y-2 text-sm">
            {recentScans.map((s) => (
              <li
                key={s.run_id}
                className="flex items-center justify-between rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)] px-3 py-2"
              >
                <div>
                  <div className="font-medium">{formatTime(s.started_at)}</div>
                  <div className="text-xs text-[var(--color-muted)]">
                    {s.devices_online} / {s.devices_total} devices online ·{" "}
                    {s.findings_count} finding{s.findings_count === 1 ? "" : "s"}
                  </div>
                </div>
                {s.worst_severity && (
                  <span className="rounded-full bg-white/5 px-2 py-0.5 text-xs uppercase tracking-wide">
                    {s.worst_severity}
                  </span>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5">
        <header className="mb-3 flex items-center justify-between">
          <h3 className="text-sm font-semibold">Recent device events</h3>
          <span className="text-xs text-[var(--color-muted)]">
            Online ↔ offline transitions
          </span>
        </header>
        {recentEvents.length === 0 ? (
          <p className="text-sm text-[var(--color-muted)]">
            No transitions yet. Once devices go offline/online between scans
            they'll appear here.
          </p>
        ) : (
          <ul className="space-y-1.5 text-sm">
            {recentEvents.map((e, i) => (
              <li
                key={`${e.mac}-${e.occurred_at}-${i}`}
                className="flex items-center justify-between gap-3"
              >
                <span className={`font-mono text-xs ${eventColor(e.event_type)}`}>
                  {e.event_type.padEnd(11, " ")}
                </span>
                <span className="flex-1 truncate text-[var(--color-muted)]">
                  {e.mac}
                  {e.details ? ` · ${e.details}` : ""}
                </span>
                <span className="text-xs text-[var(--color-muted)]">
                  {formatTime(e.occurred_at)}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
