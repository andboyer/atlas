import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useApp } from "../store";
import type { DeviceEvent, IncidentCorrelation } from "../types";

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

function formatMetric(metric: string, value: number): string {
  if (metric.endsWith("_ms")) return `${value.toFixed(1)} ms`;
  if (metric === "link.rssi_dbm" || metric === "link.snr_db")
    return `${value.toFixed(0)} dB${metric.endsWith("_dbm") ? "m" : ""}`;
  if (metric === "link.tx_rate_mbps") return `${value.toFixed(0)} Mbps`;
  if (metric === "reach.loss_pct") return `${value.toFixed(1)}%`;
  if (metric.startsWith("devices.")) return `${value.toFixed(0)}`;
  return value.toString();
}

function metricLabel(metric: string): string {
  const map: Record<string, string> = {
    "link.rssi_dbm": "RSSI",
    "link.snr_db": "SNR",
    "link.tx_rate_mbps": "TX rate",
    "reach.gateway_ms": "Gateway latency",
    "reach.internet_ms": "Internet latency",
    "reach.dns_ms": "DNS latency",
    "reach.loss_pct": "Packet loss",
    "devices.online": "Devices online",
    "devices.total": "Devices known",
  };
  return map[metric] ?? metric;
}

function EventRow({ event }: { event: DeviceEvent }) {
  const [expanded, setExpanded] = useState(false);
  const [snap, setSnap] = useState<IncidentCorrelation | null>(null);
  const [loading, setLoading] = useState(false);

  const canCorrelate = event.event_type === "offline" || event.event_type === "online";

  async function toggle() {
    const next = !expanded;
    setExpanded(next);
    if (next && !snap && canCorrelate) {
      setLoading(true);
      try {
        const r = await invoke<IncidentCorrelation>("get_incident_correlation", {
          at: event.occurred_at,
          windowSecs: 180,
          excludeMac: event.mac,
        });
        setSnap(r);
      } catch (e) {
        console.warn("correlation failed:", e);
      } finally {
        setLoading(false);
      }
    }
  }

  return (
    <li>
      <button
        type="button"
        onClick={() => void toggle()}
        className="flex w-full items-center justify-between gap-3 rounded-md px-1 py-1 text-left hover:bg-white/5"
      >
        <span className={`font-mono text-xs ${eventColor(event.event_type)}`}>
          {event.event_type.padEnd(11, " ")}
        </span>
        <span className="flex-1 truncate text-[var(--color-muted)]">
          {event.mac}
          {event.details ? ` · ${event.details}` : ""}
        </span>
        <span className="text-xs text-[var(--color-muted)]">
          {formatTime(event.occurred_at)}
        </span>
      </button>
      {expanded && (
        <div className="ml-6 mt-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)] p-3 text-xs">
          {!canCorrelate ? (
            <p className="text-[var(--color-muted)]">
              No correlation available for "{event.event_type}" events.
            </p>
          ) : loading ? (
            <p className="text-[var(--color-muted)]">Loading…</p>
          ) : !snap ? (
            <p className="text-[var(--color-muted)]">No data.</p>
          ) : (
            <>
              <p className="mb-2 font-medium">Network state at this moment</p>
              {snap.metrics_before.length === 0 ? (
                <p className="text-[var(--color-muted)]">
                  No samples recorded in the surrounding window yet — run a
                  few scans and the picture will fill in.
                </p>
              ) : (
                <ul className="grid grid-cols-2 gap-x-4 gap-y-1">
                  {snap.metrics_before.map((m) => (
                    <li
                      key={m.metric}
                      className="flex items-center justify-between"
                    >
                      <span className="text-[var(--color-muted)]">
                        {metricLabel(m.metric)}
                      </span>
                      <span className="font-mono">
                        {formatMetric(m.metric, m.value)}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
              {snap.concurrent_events.length > 0 && (
                <>
                  <p className="mb-1 mt-3 font-medium">
                    Other devices that changed state at the same time
                  </p>
                  <ul className="space-y-0.5">
                    {snap.concurrent_events.map((e, i) => (
                      <li
                        key={`${e.mac}-${e.occurred_at}-${i}`}
                        className="flex items-center justify-between gap-2"
                      >
                        <span className={`font-mono ${eventColor(e.event_type)}`}>
                          {e.event_type}
                        </span>
                        <span className="flex-1 truncate text-[var(--color-muted)]">
                          {e.mac}
                          {e.details ? ` · ${e.details}` : ""}
                        </span>
                        <span className="text-[var(--color-muted)]">
                          {formatTime(e.occurred_at)}
                        </span>
                      </li>
                    ))}
                  </ul>
                </>
              )}
            </>
          )}
        </div>
      )}
    </li>
  );
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
            Click any event to see what else was happening
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
              <EventRow
                key={`${e.mac}-${e.occurred_at}-${i}`}
                event={e}
              />
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
