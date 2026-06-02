/**
 * NetworkPathPanel — visual hop view of the path from this device to the
 * internet. Surfaces ReachabilityStats + MTU + DNS leak + captive portal.
 */
import {
  Smartphone,
  Router,
  Globe,
  Server,
  AlertTriangle,
  CheckCircle2,
} from "lucide-react";
import type { ReachabilityStats } from "../types";

interface Props {
  reachability: ReachabilityStats;
  mtuBytes: number | null;
  dnsLeak: boolean;
  captivePortal: boolean;
}

function latencyTone(ms: number | null): string {
  if (ms == null) return "var(--color-muted)";
  if (ms <= 5) return "var(--color-good)";
  if (ms <= 30) return "var(--color-good)";
  if (ms <= 80) return "var(--color-warn)";
  return "var(--color-bad)";
}

function fmtMs(ms: number | null): string {
  if (ms == null) return "—";
  return `${ms.toFixed(1)} ms`;
}

export function NetworkPathPanel({
  reachability,
  mtuBytes,
  dnsLeak,
  captivePortal,
}: Props) {
  const hops = [
    {
      icon: <Smartphone className="h-4 w-4" />,
      label: "This device",
      sub: null,
      tone: "neutral" as const,
    },
    {
      icon: <Router className="h-4 w-4" />,
      label: "Gateway",
      sub: reachability.gateway_ip
        ? `${reachability.gateway_ip} · ${fmtMs(reachability.gateway_latency_ms)}`
        : "unknown gateway",
      tone: reachability.gateway_latency_ms != null ? "ok" : ("unknown" as const),
      latencyMs: reachability.gateway_latency_ms,
    },
    {
      icon: <Server className="h-4 w-4" />,
      label: "DNS",
      sub: `${fmtMs(reachability.dns_latency_ms)}${dnsLeak ? " · LEAK" : ""}`,
      tone: dnsLeak ? "bad" : reachability.dns_latency_ms != null ? "ok" : "unknown",
      latencyMs: reachability.dns_latency_ms,
    },
    {
      icon: <Globe className="h-4 w-4" />,
      label: "Internet",
      sub: `${fmtMs(reachability.internet_latency_ms)}${
        reachability.packet_loss_pct != null
          ? ` · ${reachability.packet_loss_pct.toFixed(1)}% loss`
          : ""
      }${captivePortal ? " · CAPTIVE" : ""}`,
      tone: captivePortal
        ? "bad"
        : reachability.internet_latency_ms != null
          ? "ok"
          : "unknown",
      latencyMs: reachability.internet_latency_ms,
    },
  ];

  return (
    <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5">
      <div className="mb-1 flex items-center gap-2 text-sm font-semibold">
        <Globe className="h-4 w-4 text-[var(--color-accent)]" />
        Network path
      </div>
      <p className="mb-4 text-xs text-[var(--color-muted)]">
        Latency at each hop from this device out to the open internet.
      </p>

      <div className="flex flex-wrap items-stretch gap-2">
        {hops.map((h, i) => (
          <div
            key={h.label}
            className="flex flex-1 min-w-[140px] items-center gap-3"
          >
            <div className="flex-1 rounded-xl border border-[var(--color-border)] bg-[var(--color-panel-2)] p-3">
              <div className="flex items-center gap-2 text-xs text-[var(--color-muted)]">
                {h.icon}
                <span className="font-semibold uppercase tracking-wider">
                  {h.label}
                </span>
              </div>
              {"latencyMs" in h && h.latencyMs != null && (
                <div
                  className="mt-1 text-lg font-semibold tabular-nums"
                  style={{ color: latencyTone(h.latencyMs) }}
                >
                  {h.latencyMs.toFixed(1)} ms
                </div>
              )}
              {h.sub && (
                <div className="mt-1 text-[10px] text-[var(--color-muted)]">
                  {h.sub}
                </div>
              )}
            </div>
            {i < hops.length - 1 && (
              <div className="flex-shrink-0 text-[var(--color-muted)]">→</div>
            )}
          </div>
        ))}
      </div>

      <div className="mt-4 grid grid-cols-1 gap-2 text-xs sm:grid-cols-3">
        <Diag
          label="MTU"
          value={mtuBytes != null ? `${mtuBytes} bytes` : "—"}
          ok={mtuBytes == null || mtuBytes >= 1500}
          okText={`No fragmentation expected (${mtuBytes ?? "?"} ≥ 1500)`}
          badText={`Path MTU below 1500 — fragmentation likely`}
        />
        <Diag
          label="DNS leak"
          value={dnsLeak ? "Detected" : "None"}
          ok={!dnsLeak}
          okText="DNS queries are routed through your configured resolver"
          badText="Queries are bypassing your VPN / DNS-over-HTTPS"
        />
        <Diag
          label="Captive portal"
          value={captivePortal ? "Detected" : "None"}
          ok={!captivePortal}
          okText="Internet reachable without authentication"
          badText="Open a browser to authenticate"
        />
      </div>
    </div>
  );
}

function Diag({
  label,
  value,
  ok,
  okText,
  badText,
}: {
  label: string;
  value: string;
  ok: boolean;
  okText: string;
  badText: string;
}) {
  return (
    <div
      className={`rounded-lg border p-3 ${
        ok
          ? "border-emerald-500/30 bg-emerald-500/5"
          : "border-rose-500/40 bg-rose-500/10"
      }`}
    >
      <div className="flex items-center justify-between">
        <span className="text-[10px] uppercase tracking-wider text-[var(--color-muted)]">
          {label}
        </span>
        {ok ? (
          <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
        ) : (
          <AlertTriangle className="h-3.5 w-3.5 text-rose-400" />
        )}
      </div>
      <div
        className={`mt-1 text-sm font-semibold ${
          ok ? "text-[var(--color-text)]" : "text-rose-300"
        }`}
      >
        {value}
      </div>
      <div className="mt-1 text-[10px] text-[var(--color-muted)]">
        {ok ? okText : badText}
      </div>
    </div>
  );
}
