import { useApp } from "../store";

const KIND_COLORS: Record<string, string> = {
  roam: "bg-sky-500/15 text-sky-300 border-sky-500/30",
  scan: "bg-slate-500/15 text-slate-300 border-slate-500/30",
  assoc: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  disassoc: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  auth: "bg-indigo-500/15 text-indigo-300 border-indigo-500/30",
  deauth: "bg-rose-500/15 text-rose-300 border-rose-500/30",
  power: "bg-violet-500/15 text-violet-300 border-violet-500/30",
  kernel: "bg-stone-500/15 text-stone-300 border-stone-500/30",
  other: "bg-zinc-500/15 text-zinc-300 border-zinc-500/30",
};

function chip(kind: string): string {
  return KIND_COLORS[kind] ?? KIND_COLORS.other;
}

function clock(iso: string): string {
  return new Date(iso).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

/**
 * Wi-Fi system events timeline (Play C). Subscribes to the rolling ring of
 * `wifi:event` Tauri events and renders the most recent ones with kind
 * chips + a small table of the latest 25.
 */
export function WifiEventsTimeline() {
  const events = useApp((s) => s.wifiEvents);
  const recent = [...events].reverse().slice(0, 25);

  return (
    <section>
      <div className="mb-3 flex items-end justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold uppercase tracking-wider text-[var(--color-muted)]">
            Wi-Fi system events
          </h2>
          <p className="mt-0.5 text-xs text-slate-500">
            Live from macOS <code className="text-slate-400">log stream</code> —
            roam, scan, assoc, deauth, kernel
          </p>
        </div>
        <span className="text-xs text-slate-500 tabular-nums">
          {events.length} captured
        </span>
      </div>

      {events.length === 0 ? (
        <div className="rounded-2xl border border-dashed border-[var(--color-border)] bg-[var(--color-panel)]/60 px-6 py-8 text-center">
          <p className="text-sm text-[var(--color-muted)]">No events yet.</p>
          <p className="mt-1 text-xs text-slate-500">
            Wi-Fi subsystem events (roams, deauths, scans) will appear here as
            they happen on macOS. On other platforms this list stays empty.
          </p>
        </div>
      ) : (
        <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)]/60">
          {/* Compact chip strip showing the last ~12 event kinds */}
          <div className="flex flex-wrap gap-1.5 border-b border-[var(--color-border)]/60 p-3">
            {recent.slice(0, 12).map((e) => (
              <span
                key={e.id}
                title={`${clock(e.ts)} · ${e.kind} · ${e.message}`}
                className={`rounded-full border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider ${chip(
                  e.kind,
                )}`}
              >
                {e.kind}
              </span>
            ))}
          </div>

          {/* Table of recent events */}
          <div className="max-h-72 overflow-auto">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-[var(--color-panel)] text-[10px] uppercase tracking-wider text-slate-500">
                <tr>
                  <th className="px-3 py-2 text-left">Time</th>
                  <th className="px-3 py-2 text-left">Kind</th>
                  <th className="px-3 py-2 text-left">Process</th>
                  <th className="px-3 py-2 text-left">Detail</th>
                </tr>
              </thead>
              <tbody>
                {recent.map((e) => (
                  <tr
                    key={e.id}
                    className="border-t border-[var(--color-border)]/40"
                  >
                    <td className="px-3 py-1.5 font-mono tabular-nums text-slate-400">
                      {clock(e.ts)}
                    </td>
                    <td className="px-3 py-1.5">
                      <span
                        className={`rounded-full border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider ${chip(
                          e.kind,
                        )}`}
                      >
                        {e.kind}
                      </span>
                    </td>
                    <td className="px-3 py-1.5 font-mono text-slate-400">
                      {e.process ?? "—"}
                    </td>
                    <td className="px-3 py-1.5 text-slate-300">{e.message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </section>
  );
}
