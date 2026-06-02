/**
 * RoamingPanel — sticky-client warning + recent BSSID transitions.
 *
 * Visible in Admin mode. Shows how often the device has roamed between APs
 * with the same SSID, and warns if the device is sticking to a weak AP.
 */
import { Move } from "lucide-react";
import type { RoamingStats } from "../types";

interface Props {
  roaming: RoamingStats | null | undefined;
}

function formatDwell(secs: number | null): string {
  if (secs == null) return "—";
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.round(secs / 60)}m`;
  return `${(secs / 3600).toFixed(1)}h`;
}

function shortBssid(b: string | null): string {
  if (!b) return "—";
  return b.toLowerCase();
}

export default function RoamingPanel({ roaming }: Props) {
  if (!roaming) {
    return (
      <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5">
        <div className="flex items-center gap-2 text-sm font-semibold text-[var(--color-muted)]">
          <Move className="h-4 w-4" />
          Roaming
        </div>
        <p className="mt-2 text-xs text-[var(--color-muted)]">
          No roaming data yet — run a few scans on a multi-AP network.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5">
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm font-semibold">
          <Move className="h-4 w-4 text-[var(--color-accent)]" />
          Roaming history
        </div>
      </div>

      {roaming.sticky_warning && (
        <div className="mb-4 rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-200">
          <strong>Sticky-client warning.</strong> Signal is weak but your device hasn&apos;t
          roamed in a while. Consider toggling WiFi off/on, or check if a closer AP is
          available.
        </div>
      )}

      <div className="grid grid-cols-3 gap-4">
        <Stat label="Last hour" value={`${roaming.events_last_hour}`} unit="roams" />
        <Stat label="Last 24h" value={`${roaming.events_last_24h}`} unit="roams" />
        <Stat label="Avg dwell" value={formatDwell(roaming.avg_dwell_secs)} unit="" />
      </div>

      {roaming.recent_events.length > 0 && (
        <div className="mt-4">
          <div className="mb-2 text-xs uppercase tracking-wide text-[var(--color-muted)]">
            Recent transitions
          </div>
          <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
            {roaming.recent_events.map((e, i) => (
              <div
                key={`${e.at}-${i}`}
                className="flex items-center justify-between rounded-md bg-[var(--color-panel-2)] px-3 py-1.5 text-xs"
              >
                <span className="text-[var(--color-muted)]">
                  {new Date(e.at).toLocaleString()}
                </span>
                <span className="font-mono text-[var(--color-fg)]">
                  {shortBssid(e.from_bssid)} → {shortBssid(e.to_bssid)}
                </span>
                {e.rssi_at_roam_dbm != null && (
                  <span className="text-[var(--color-muted)]">
                    {e.rssi_at_roam_dbm} dBm
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function Stat({ label, value, unit }: { label: string; value: string; unit: string }) {
  return (
    <div>
      <div className="text-xs text-[var(--color-muted)]">{label}</div>
      <div className="mt-0.5 flex items-baseline gap-1">
        <span className="text-xl font-semibold">{value}</span>
        {unit && <span className="text-xs text-[var(--color-muted)]">{unit}</span>}
      </div>
    </div>
  );
}
