import { ArrowRightLeft } from "lucide-react";
import { useApp } from "../store";

export function AlternateApBanner() {
  const alt = useApp((s) => s.lastScan?.alternate_ap ?? null);

  if (!alt) return null;

  return (
    <div className="rounded-2xl border border-amber-500/40 bg-amber-500/10 p-4">
      <div className="flex items-start gap-3">
        <div className="mt-0.5 rounded-lg bg-amber-500/20 p-2">
          <ArrowRightLeft className="h-4 w-4 text-amber-300" />
        </div>
        <div className="flex-1 text-sm">
          <p className="font-semibold text-amber-100">
            A stronger AP on <span className="font-mono">{alt.ssid}</span> is visible
            nearby.
          </p>
          <p className="mt-1 text-amber-200/80">
            Current AP at{" "}
            <span className="font-mono">{alt.current_rssi_dbm} dBm</span> — alternate{" "}
            <span className="font-mono">{alt.alternate_bssid}</span> at{" "}
            <span className="font-mono">{alt.alternate_rssi_dbm} dBm</span>
            {alt.alternate_channel != null && (
              <>
                {" "}
                on ch <span className="font-mono">{alt.alternate_channel}</span>
                {alt.alternate_band && (
                  <>
                    {" "}
                    ({alt.alternate_band} GHz)
                  </>
                )}
              </>
            )}{" "}
            — <span className="font-semibold">+{alt.improvement_db} dB</span>{" "}
            improvement.
          </p>
          <p className="mt-1 text-xs text-amber-200/60">
            Your device should roam automatically, but if not, toggle Wi-Fi off/on
            to force re-association.
          </p>
        </div>
      </div>
    </div>
  );
}
