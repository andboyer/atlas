import { Wifi, WifiOff } from "lucide-react";
import { useApp } from "../store";
import { LivePauseControl } from "./LivePauseControl";

export function StatusCard() {
  const lastScan = useApp((s) => s.lastScan);
  const scanning = useApp((s) => s.scanning);
  const monitoring = useApp((s) => s.monitoring);
  const error = useApp((s) => s.error);

  const ssid = lastScan?.link.ssid;
  const rssi = lastScan?.link.rssi_dbm;
  const band = lastScan?.link.band;
  const channel = lastScan?.link.channel;
  const wifiGen = lastScan?.link.wifi_generation;
  const vendor = lastScan?.link.vendor;
  const speedMbps = lastScan?.speed_mbps ?? null;
  const findings = lastScan?.findings ?? [];
  const worst = findings.reduce<string>((acc, f) => {
    const order = ["info", "low", "medium", "high", "critical"];
    return order.indexOf(f.severity) > order.indexOf(acc) ? f.severity : acc;
  }, "info");

  const headline = !lastScan
    ? scanning
      ? "Scanning your network\u2026"
      : monitoring
        ? "Initialising live scan\u2026"
        : "Live scan paused"
    : worst === "info" || worst === "low"
      ? "Your network looks healthy"
      : worst === "medium"
        ? "Minor issues detected"
        : "Action recommended";

  return (
    <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-6">
      <div className="flex items-start justify-between gap-6">
        <div className="flex items-start gap-4">
          <div className="rounded-xl bg-[var(--color-panel-2)] p-3">
            {ssid ? (
              <Wifi className="h-8 w-8 text-[var(--color-accent)]" />
            ) : (
              <WifiOff className="h-8 w-8 text-[var(--color-muted)]" />
            )}
          </div>
          <div>
            <h1 className="text-2xl font-semibold">{headline}</h1>
            <p className="mt-1 text-sm text-[var(--color-muted)]">
              {ssid ? (
                <>
                  Connected to <span className="text-[var(--color-text)]">{ssid}</span>
                  {band && <> · {band} GHz</>}
                  {channel && <> · ch {channel}</>}
                  {typeof rssi === "number" && <> · {rssi} dBm</>}
                  {typeof speedMbps === "number" && (
                    <> · {speedMbps.toFixed(1)} Mbps ↓</>
                  )}
                </>
              ) : (
                "Watching your WiFi link, internet path, and devices in real time."
              )}
            </p>
            {(wifiGen || vendor) && (
              <div className="mt-2 flex flex-wrap items-center gap-2">
                {wifiGen && (
                  <span className="rounded-full bg-[var(--color-panel-2)] px-2.5 py-0.5 text-xs font-medium text-[var(--color-accent)]">
                    {wifiGen}
                  </span>
                )}
                {vendor && (
                  <span className="rounded-full bg-[var(--color-panel-2)] px-2.5 py-0.5 text-xs text-[var(--color-muted)]">
                    AP: {vendor}
                  </span>
                )}
              </div>
            )}
            {error && (
              <p className="mt-2 text-sm text-[var(--color-bad)]">{error}</p>
            )}
          </div>
        </div>
        <LivePauseControl />
      </div>
    </div>
  );
}
