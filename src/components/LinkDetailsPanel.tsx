/**
 * LinkDetailsPanel — full breakdown of every LinkStats field.
 *
 * Surfaces fields that the hero StatusCard doesn't show: BSSID, security,
 * PHY mode, channel width, noise floor, SNR, tx/rx rates, vendor, Wi-Fi
 * generation.
 */
import { Wifi, Copy, Check } from "lucide-react";
import { useState } from "react";
import type { LinkStats } from "../types";

interface Props {
  link: LinkStats;
}

function copy(text: string, onDone: () => void) {
  navigator.clipboard?.writeText(text).then(onDone).catch(() => {});
}

function snrTone(snr: number | null): string {
  if (snr == null) return "var(--color-muted)";
  if (snr >= 35) return "var(--color-good)";
  if (snr >= 20) return "var(--color-warn)";
  return "var(--color-bad)";
}

function rssiTone(rssi: number | null): string {
  if (rssi == null) return "var(--color-muted)";
  if (rssi >= -60) return "var(--color-good)";
  if (rssi >= -70) return "var(--color-warn)";
  return "var(--color-bad)";
}

export function LinkDetailsPanel({ link }: Props) {
  const [copied, setCopied] = useState(false);

  return (
    <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5">
      <div className="mb-4 flex items-center gap-2 text-sm font-semibold">
        <Wifi className="h-4 w-4 text-[var(--color-accent)]" />
        Wi-Fi link details
      </div>

      <dl className="grid grid-cols-1 gap-x-6 gap-y-3 text-xs sm:grid-cols-2 lg:grid-cols-3">
        <Row label="SSID" value={link.ssid ?? "—"} mono={!!link.ssid} strong />
        <Row
          label="BSSID"
          value={
            link.bssid ? (
              <div className="flex items-center gap-1.5">
                <span className="font-mono">{link.bssid}</span>
                <button
                  onClick={() =>
                    copy(link.bssid!, () => {
                      setCopied(true);
                      setTimeout(() => setCopied(false), 1200);
                    })
                  }
                  title="Copy BSSID"
                  className="text-[var(--color-muted)] hover:text-[var(--color-text)]"
                >
                  {copied ? (
                    <Check className="h-3 w-3 text-emerald-400" />
                  ) : (
                    <Copy className="h-3 w-3" />
                  )}
                </button>
              </div>
            ) : (
              "—"
            )
          }
        />
        <Row label="AP vendor" value={link.vendor ?? "unknown"} />
        <Row label="Wi-Fi generation" value={link.wifi_generation ?? "unknown"} />
        <Row label="PHY mode" value={link.phy_mode ?? "—"} />
        <Row label="Security" value={link.security ?? "—"} />
        <Row
          label="Band"
          value={link.band != null ? `${link.band} GHz` : "—"}
        />
        <Row
          label="Channel"
          value={
            link.channel != null
              ? `${link.channel}${link.channel_width_mhz != null ? ` · ${link.channel_width_mhz} MHz` : ""}`
              : "—"
          }
        />
        <Row
          label="RSSI"
          value={
            <span
              className="font-medium tabular-nums"
              style={{ color: rssiTone(link.rssi_dbm) }}
            >
              {link.rssi_dbm != null ? `${link.rssi_dbm} dBm` : "—"}
            </span>
          }
        />
        <Row
          label="Noise floor"
          value={link.noise_dbm != null ? `${link.noise_dbm} dBm` : "—"}
        />
        <Row
          label="SNR"
          value={
            <span
              className="font-medium tabular-nums"
              style={{ color: snrTone(link.snr_db) }}
            >
              {link.snr_db != null ? `${link.snr_db.toFixed(0)} dB` : "—"}
            </span>
          }
        />
        <Row
          label="TX rate"
          value={
            link.tx_rate_mbps != null
              ? `${link.tx_rate_mbps.toFixed(0)} Mbps`
              : "—"
          }
        />
        <Row
          label="RX rate"
          value={
            link.rx_rate_mbps != null
              ? `${link.rx_rate_mbps.toFixed(0)} Mbps`
              : "—"
          }
        />
      </dl>
    </div>
  );
}

interface RowProps {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
  strong?: boolean;
}

function Row({ label, value, mono, strong }: RowProps) {
  return (
    <div className="flex items-start justify-between gap-3 border-b border-[var(--color-border)]/40 pb-2 last:border-b-0 last:pb-0">
      <dt className="text-[10px] uppercase tracking-wider text-[var(--color-muted)]">
        {label}
      </dt>
      <dd
        className={`text-right ${mono ? "font-mono" : ""} ${strong ? "font-semibold text-[var(--color-text)]" : "text-[var(--color-text)]"}`}
      >
        {value}
      </dd>
    </div>
  );
}
