import { Wifi, WifiOff } from "lucide-react";
import { useApp } from "../store";
import { LivePauseControl } from "./LivePauseControl";

const HEADLINE_TONE: Record<string, string> = {
  info: "text-[var(--color-text)]",
  low: "text-[var(--color-text)]",
  medium: "text-[var(--color-warn)]",
  high: "text-[var(--color-bad)]",
  critical: "text-[var(--color-bad)]",
};

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
    <div className="atlas-card relative overflow-hidden p-6">
      {/* Brass accent stripe down the left edge */}
      <span
        aria-hidden
        className="absolute inset-y-4 left-0 w-[3px] rounded-r bg-gradient-to-b from-[var(--color-accent)] via-[var(--color-accent-2)] to-transparent opacity-80"
      />
      <div className="flex items-start justify-between gap-6">
        <div className="flex items-start gap-4">
          <div className="atlas-brand-chip flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl">
            {ssid ? (
              <Wifi className="h-7 w-7 text-[var(--color-accent)]" />
            ) : (
              <WifiOff className="h-7 w-7 text-[var(--color-muted)]" />
            )}
          </div>
          <div className="min-w-0">
            <h2
              className={`text-2xl font-semibold tracking-tight ${HEADLINE_TONE[worst] ?? "text-[var(--color-text)]"}`}
            >
              {headline}
            </h2>
            <p className="mt-1.5 text-sm leading-relaxed text-[var(--color-muted)]">
              {ssid ? (
                <>
                  Connected to{" "}
                  <span className="font-medium text-[var(--color-text)]">
                    {ssid}
                  </span>
                  {band && (
                    <>
                      {" "}
                      <span className="text-[var(--color-border)]">·</span> {band} GHz
                    </>
                  )}
                  {channel && (
                    <>
                      {" "}
                      <span className="text-[var(--color-border)]">·</span> ch {channel}
                    </>
                  )}
                  {typeof rssi === "number" && (
                    <>
                      {" "}
                      <span className="text-[var(--color-border)]">·</span>{" "}
                      <span className="tabular-nums">{rssi} dBm</span>
                    </>
                  )}
                  {typeof speedMbps === "number" && (
                    <>
                      {" "}
                      <span className="text-[var(--color-border)]">·</span>{" "}
                      <span className="tabular-nums">
                        {speedMbps.toFixed(1)} Mbps ↓
                      </span>
                    </>
                  )}
                </>
              ) : (
                "Watching your Wi-Fi link, internet path, and devices in real time."
              )}
            </p>
            {(wifiGen || vendor) && (
              <div className="mt-3 flex flex-wrap items-center gap-2">
                {wifiGen && (
                  <span className="rounded-full border border-[var(--color-accent)]/30 bg-[var(--color-accent)]/10 px-2.5 py-0.5 text-[11px] font-medium uppercase tracking-wider text-[var(--color-accent)]">
                    {wifiGen}
                  </span>
                )}
                {vendor && (
                  <span className="rounded-full border border-[var(--color-border)] bg-[var(--color-panel-2)] px-2.5 py-0.5 text-[11px] text-[var(--color-muted)]">
                    AP · {vendor}
                  </span>
                )}
              </div>
            )}
            {error && (
              <p className="mt-3 text-sm text-[var(--color-bad)]">{error}</p>
            )}
          </div>
        </div>
        <LivePauseControl />
      </div>
    </div>
  );
}
