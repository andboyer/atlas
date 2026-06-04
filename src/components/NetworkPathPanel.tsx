/**
 * NetworkPathPanel — visual hop view of the path from this device to the
 * internet. Surfaces ReachabilityStats + MTU + DNS leak + captive portal,
 * plus a full IP-layer route trace fetched on demand via the
 * `run_traceroute` Tauri command.
 *
 * Note: L2 switches are intentionally absent from the route trace —
 * they don't decrement IP TTL so they're invisible to every form of
 * traceroute. The directly-attached switch (when discoverable) is
 * surfaced via LLDP in the AV tab.
 */
import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useShallow } from "zustand/react/shallow";
import {
  Smartphone,
  Router,
  Globe,
  Server,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  Info,
} from "lucide-react";
import { useApp } from "../store";
import type { ReachabilityStats, TraceHop } from "../types";

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
  // Full route trace is fetched lazily — kept off the main scan path so
  // quick scans stay snappy. Auto-runs once on mount and exposes a manual
  // Refresh button. Empty array (vs `null`) means "trace completed but
  // returned no hops" — typically a sandboxing / SIP issue on macOS.
  const [hops, setHops] = useState<TraceHop[] | null>(null);
  const [tracing, setTracing] = useState(false);
  const [traceError, setTraceError] = useState<string | null>(null);

  // Pin the trace to whatever NIC the user selected in the header.
  // Empty/whitespace → null (kernel default). We re-run automatically
  // whenever the user changes the NIC so the route view never drifts
  // from the rest of the iface-pinned probes.
  const preferredIface = useApp(
    useShallow((s) => (s.settings.preferred_interface || "").trim() || null),
  );

  async function runTrace() {
    setTracing(true);
    setTraceError(null);
    try {
      const result = await invoke<TraceHop[]>("run_traceroute", {
        target: null,
        iface: preferredIface,
      });
      setHops(result);
    } catch (e) {
      setTraceError(typeof e === "string" ? e : String(e));
    } finally {
      setTracing(false);
    }
  }

  useEffect(() => {
    void runTrace();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [preferredIface]);

  const hopStrip = [
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
    <div className="atlas-card p-5">
      <div className="mb-1 flex items-center gap-2 text-sm font-semibold">
        <Globe className="h-4 w-4 text-[var(--color-accent)]" />
        Network path
      </div>
      <p className="mb-4 text-xs text-[var(--color-muted)]">
        Latency at each hop from this device out to the open internet.
      </p>

      <div className="flex flex-wrap items-stretch gap-2">
        {hopStrip.map((h, i) => (
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
            {i < hopStrip.length - 1 && (
              <div className="flex-shrink-0 text-[var(--color-muted)]">→</div>
            )}
          </div>
        ))}
      </div>

      <TracePanel
        hops={hops}
        tracing={tracing}
        error={traceError}
        onRefresh={runTrace}
      />

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

/**
 * Full IP-layer route trace. Renders the hops returned by
 * `run_traceroute` as a vertical list with per-hop RTT color-coded the
 * same way as the headline path strip. A muted info banner explains why
 * L2 switches are never present — a frequent source of confusion when
 * comparing this view to a vendor switch-management UI.
 */
function TracePanel({
  hops,
  tracing,
  error,
  onRefresh,
}: {
  hops: TraceHop[] | null;
  tracing: boolean;
  error: string | null;
  onRefresh: () => void;
}) {
  return (
    <div className="mt-5 rounded-xl border border-[var(--color-border)] bg-[var(--color-panel-2)] p-3">
      <div className="mb-2 flex items-center justify-between">
        <div className="flex items-center gap-2 text-xs font-semibold text-[var(--color-text)]">
          <Router className="h-3.5 w-3.5 text-[var(--color-accent)]" />
          Full route trace
          {hops && hops.length > 0 && (
            <span className="text-[10px] font-normal text-[var(--color-muted)]">
              · {hops.length} hop{hops.length === 1 ? "" : "s"} to 1.1.1.1
            </span>
          )}
        </div>
        <button
          type="button"
          onClick={onRefresh}
          disabled={tracing}
          className="flex items-center gap-1 rounded-md border border-[var(--color-border)] px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-[var(--color-muted)] transition hover:bg-[var(--color-panel)] disabled:opacity-50"
        >
          <RefreshCw
            className={`h-3 w-3 ${tracing ? "animate-spin" : ""}`}
          />
          {tracing ? "Tracing…" : "Refresh"}
        </button>
      </div>

      <div className="mb-3 flex items-start gap-2 rounded-md border border-[var(--color-border)] bg-[var(--color-panel)] p-2 text-[10px] leading-snug text-[var(--color-muted)]">
        <Info className="mt-0.5 h-3 w-3 flex-shrink-0" />
        <span>
          <strong className="text-[var(--color-text)]">
            L2 switches don't appear here.
          </strong>{" "}
          IP traceroute can only reveal devices that decrement the TTL — i.e.
          L3 routers. Ethernet switches forward frames transparently and are
          invisible by design. Your directly-attached switch, when
          discoverable, is shown via LLDP in the <em>AV diagnostics</em> tab.
        </span>
      </div>

      {error && (
        <p className="mb-2 text-[10px] text-rose-400">Trace failed: {error}</p>
      )}

      {hops == null && !tracing && !error && (
        <p className="text-[10px] text-[var(--color-muted)]">
          Press Refresh to run a route trace.
        </p>
      )}

      {hops != null && hops.length === 0 && !tracing && (
        <p className="text-[10px] text-[var(--color-muted)]">
          No hops resolved. The platform's <code>traceroute</code> /{" "}
          <code>tracert</code> binary may be missing, blocked by a host
          firewall, or sandboxed.
        </p>
      )}

      {hops != null && hops.length > 0 && (
        <ol className="space-y-1">
          {hops.map((hop) => (
            <li
              key={hop.idx}
              className="flex items-center gap-3 rounded-md border border-transparent px-2 py-1 hover:border-[var(--color-border)]"
            >
              <span className="w-6 text-right font-mono text-[10px] text-[var(--color-muted)]">
                {hop.idx}
              </span>
              <span className="flex-1 truncate font-mono text-xs text-[var(--color-text)]">
                {hop.ip ?? (hop.timed_out ? "* * *" : "(unknown)")}
                {hop.hostname && hop.hostname !== hop.ip && (
                  <span className="ml-2 text-[10px] text-[var(--color-muted)]">
                    {hop.hostname}
                  </span>
                )}
              </span>
              <span
                className="w-20 text-right font-mono text-xs tabular-nums"
                style={{ color: latencyTone(hop.rtt_ms) }}
              >
                {fmtMs(hop.rtt_ms)}
              </span>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}
