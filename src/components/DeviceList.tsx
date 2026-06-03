import { useApp } from "../store";
import clsx from "clsx";

const classLabels: Record<string, string> = {
  pos_terminal: "POS terminal",
  ip_camera: "Camera",
  smart_home: "Smart home",
  printer: "Printer",
  voice_assistant: "Voice",
  thermostat: "Thermostat",
  phone: "Phone",
  laptop: "Laptop",
  tv_streamer: "TV / streamer",
  game_console: "Console",
  nas: "NAS",
  router_ap: "Router / AP",
  unknown: "Unknown",
};

/** Strip the leading underscore and trailing ._tcp / ._udp for display. */
function fmtService(svc: string) {
  return svc.replace(/^_/, "").replace(/\._tcp$/, "").replace(/\._udp$/, "");
}

export function DeviceList() {
  const devices = useApp((s) => s.lastScan?.devices) ?? [];
  if (devices.length === 0) {
    return (
      <div className="atlas-card p-6 text-sm text-[var(--color-muted)]">
        No devices discovered yet.
      </div>
    );
  }
  return (
    <div className="atlas-card overflow-hidden">
      <table className="w-full text-sm">
        <thead className="bg-[var(--color-panel-2)]/60 text-left text-[11px] font-semibold uppercase tracking-[0.12em] text-[var(--color-muted)]">
          <tr>
            <th className="px-4 py-3">Device</th>
            <th className="px-4 py-3">Class</th>
            <th className="px-4 py-3">IP</th>
            <th className="px-4 py-3">MAC</th>
            <th className="px-4 py-3">Latency</th>
            <th className="px-4 py-3">Status</th>
          </tr>
        </thead>
        <tbody>
          {devices.map((d) => (
            <tr
              key={d.mac}
              className="border-t border-[var(--color-border)]/60 transition-colors hover:bg-[var(--color-panel-2)]/40"
            >
              <td className="px-4 py-3">
                <div className="font-medium text-[var(--color-text)]">
                  {d.hostname ?? d.vendor ?? "Unknown device"}
                </div>
                {d.services.length > 0 && (
                  <div className="mt-1 flex flex-wrap gap-1">
                    {d.services.map((s) => (
                      <span
                        key={s}
                        className="rounded border border-[var(--color-border)] bg-[var(--color-panel-2)]/70 px-1.5 py-0.5 font-mono text-[10px] text-[var(--color-muted)]"
                        title={s}
                      >
                        {fmtService(s)}
                      </span>
                    ))}
                  </div>
                )}
              </td>
              <td className="px-4 py-3 text-[var(--color-muted)]">
                {classLabels[d.class] ?? d.class}
              </td>
              <td className="px-4 py-3 font-mono text-xs tabular-nums">
                {d.ip ?? "—"}
              </td>
              <td className="px-4 py-3 font-mono text-xs text-[var(--color-muted)] tabular-nums">
                {d.mac}
              </td>
              <td className="px-4 py-3 tabular-nums">
                {typeof d.latency_ms === "number"
                  ? `${d.latency_ms.toFixed(1)} ms`
                  : "—"}
              </td>
              <td className="px-4 py-3">
                <span
                  className={clsx(
                    "inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] font-medium",
                    d.online
                      ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                      : "border-rose-500/30 bg-rose-500/10 text-rose-300",
                  )}
                >
                  <span
                    className={clsx(
                      "h-1.5 w-1.5 rounded-full",
                      d.online
                        ? "bg-emerald-400 atlas-pulse text-emerald-400"
                        : "bg-rose-400",
                    )}
                  />
                  {d.online ? "online" : "offline"}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
