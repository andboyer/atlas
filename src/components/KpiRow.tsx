import { Signal, Gauge, Activity, Cpu } from "lucide-react";
import { useApp } from "../store";
import { KpiTile } from "./KpiTile";

function signalTone(rssi: number | null | undefined) {
  if (rssi == null) return "neutral" as const;
  if (rssi >= -60) return "good" as const;
  if (rssi >= -70) return "warn" as const;
  return "bad" as const;
}

function latencyTone(ms: number | null | undefined) {
  if (ms == null) return "neutral" as const;
  if (ms <= 30) return "good" as const;
  if (ms <= 80) return "warn" as const;
  return "bad" as const;
}

function speedTone(mbps: number | null | undefined) {
  if (mbps == null) return "neutral" as const;
  if (mbps >= 100) return "good" as const;
  if (mbps >= 25) return "warn" as const;
  return "bad" as const;
}

export function KpiRow() {
  const scan = useApp((s) => s.lastScan);
  if (!scan) return null;
  const link = scan.link;
  const reach = scan.reachability;
  const onlineDevices = scan.devices.filter((d) => d.online).length;

  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
      <KpiTile
        icon={<Signal className="h-4 w-4" />}
        label="Signal"
        value={link.rssi_dbm != null ? `${link.rssi_dbm} dBm` : "—"}
        sublabel={
          link.snr_db != null ? `SNR ${link.snr_db.toFixed(0)} dB` : undefined
        }
        tone={signalTone(link.rssi_dbm)}
      />
      <KpiTile
        icon={<Gauge className="h-4 w-4" />}
        label="Download"
        value={
          scan.speed_mbps != null ? `${scan.speed_mbps.toFixed(0)} Mbps` : "—"
        }
        sublabel={
          scan.quality?.ul_throughput_mbps != null
            ? `Up ${scan.quality.ul_throughput_mbps.toFixed(0)} Mbps`
            : undefined
        }
        tone={speedTone(scan.speed_mbps)}
      />
      <KpiTile
        icon={<Activity className="h-4 w-4" />}
        label="Internet latency"
        value={
          reach.internet_latency_ms != null
            ? `${reach.internet_latency_ms.toFixed(0)} ms`
            : "—"
        }
        sublabel={
          reach.packet_loss_pct != null
            ? `${reach.packet_loss_pct.toFixed(1)}% loss`
            : undefined
        }
        tone={latencyTone(reach.internet_latency_ms)}
      />
      <KpiTile
        icon={<Cpu className="h-4 w-4" />}
        label="Devices"
        value={`${onlineDevices} / ${scan.devices.length}`}
        sublabel="online / known"
      />
    </div>
  );
}
