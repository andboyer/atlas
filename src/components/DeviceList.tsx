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
      <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-6 text-sm text-[var(--color-muted)]">
        No devices discovered yet.
      </div>
    );
  }
  return (
    <div className="overflow-hidden rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)]">
      <table className="w-full text-sm">
        <thead className="bg-[var(--color-panel-2)] text-left text-xs uppercase tracking-wide text-[var(--color-muted)]">
          <tr>
            <th className="px-4 py-2">Device</th>
            <th className="px-4 py-2">Class</th>
            <th className="px-4 py-2">IP</th>
            <th className="px-4 py-2">MAC</th>
            <th className="px-4 py-2">Latency</th>
            <th className="px-4 py-2">Status</th>
          </tr>
        </thead>
        <tbody>
          {devices.map((d) => (
            <tr key={d.mac} className="border-t border-[var(--color-border)]">
              <td className="px-4 py-2">
                <div>{d.hostname ?? d.vendor ?? "Unknown device"}</div>
                {d.services.length > 0 && (
                  <div className="mt-0.5 flex flex-wrap gap-1">
                    {d.services.map((s) => (
                      <span
                        key={s}
                        className="rounded bg-[var(--color-panel-2)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--color-muted)]"
                        title={s}
                      >
                        {fmtService(s)}
                      </span>
                    ))}
                  </div>
                )}
              </td>
              <td className="px-4 py-2 text-[var(--color-muted)]">
                {classLabels[d.class] ?? d.class}
              </td>
              <td className="px-4 py-2 font-mono text-xs">{d.ip ?? "—"}</td>
              <td className="px-4 py-2 font-mono text-xs text-[var(--color-muted)]">
                {d.mac}
              </td>
              <td className="px-4 py-2">
                {typeof d.latency_ms === "number"
                  ? `${d.latency_ms.toFixed(1)} ms`
                  : "—"}
              </td>
              <td className="px-4 py-2">
                <span
                  className={clsx(
                    "inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs",
                    d.online
                      ? "bg-emerald-500/15 text-emerald-300"
                      : "bg-rose-500/15 text-rose-300",
                  )}
                >
                  <span
                    className={clsx(
                      "h-1.5 w-1.5 rounded-full",
                      d.online ? "bg-emerald-400" : "bg-rose-400",
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
