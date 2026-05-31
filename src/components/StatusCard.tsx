import { Wifi, WifiOff, Loader2 } from "lucide-react";
import { useApp } from "../store";

export function StatusCard() {
  const { lastScan, scanning, error, runQuickScan } = useApp();

  const ssid = lastScan?.link.ssid;
  const rssi = lastScan?.link.rssi_dbm;
  const band = lastScan?.link.band;
  const channel = lastScan?.link.channel;
  const speedMbps = lastScan?.speed_mbps ?? null;
  const findings = lastScan?.findings ?? [];
  const worst = findings.reduce<string>((acc, f) => {
    const order = ["info", "low", "medium", "high", "critical"];
    return order.indexOf(f.severity) > order.indexOf(acc) ? f.severity : acc;
  }, "info");

  const headline = scanning
    ? "Scanning…"
    : !lastScan
      ? "Ready to scan"
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
                "Run a quick scan to inspect your WiFi link, internet path, and devices."
              )}
            </p>
            {error && (
              <p className="mt-2 text-sm text-[var(--color-bad)]">{error}</p>
            )}
          </div>
        </div>
        <button
          disabled={scanning}
          onClick={runQuickScan}
          className="inline-flex items-center gap-2 rounded-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-semibold text-slate-900 transition-opacity hover:opacity-90 disabled:opacity-50"
        >
          {scanning && <Loader2 className="h-4 w-4 animate-spin" />}
          {scanning ? "Scanning" : "Run quick scan"}
        </button>
      </div>
    </div>
  );
}
