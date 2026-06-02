import { useEffect, useState } from "react";
import {
  AlertTriangle,
  Cable,
  Lock,
  RefreshCw,
  Signal,
  Wifi,
} from "lucide-react";
import { useApp } from "../store";
import { AvInsights } from "./AvInsights";
import type {
  AvWarning,
  DanteDevice,
  InterfaceMulticast,
  MulticastGroup,
} from "../types";

/**
 * AV-over-IP diagnostics tab. Splits cleanly into:
 *   1. Header + Refresh + last-run timestamp.
 *   2. Heuristic warnings strip (zero-cost rules, run before any LLM call).
 *   3. Dante / AES67 device inventory with redundancy + Wi-Fi flags.
 *   4. Per-interface multicast snapshot (parsed from `netstat -gn`).
 *   5. Deep probes section (privileged IGMP listen via osascript).
 *   6. `<AvInsights />` LLM panel at the bottom.
 *
 * The first sweep auto-runs on tab mount so the user doesn't have to click.
 */
export function AvDiagnostics() {
  const av = useApp((s) => s.avDiagnostics);
  const loading = useApp((s) => s.avDiagnosticsLoading);
  const error = useApp((s) => s.avDiagnosticsError);
  const load = useApp((s) => s.loadAvDiagnostics);
  const runDeep = useApp((s) => s.runDeepProbe);
  const deepRunning = useApp((s) => s.deepProbeRunning);
  const deepError = useApp((s) => s.deepProbeError);

  // Auto-run the first sweep when this tab mounts. The user can re-run via
  // the Refresh button. We deliberately don't auto-refresh on an interval —
  // mDNS browse + netstat parse + TCP probes take ~6s and the network state
  // we report doesn't drift second-to-second.
  useEffect(() => {
    if (!av && !loading) {
      void load();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const generatedAt = av ? new Date(av.generated_at) : null;

  return (
    <div className="space-y-6">
      {/* ── Header ── */}
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-xl font-semibold">AV-over-IP diagnostics</h2>
          <p className="mt-1 text-sm text-[var(--color-muted)]">
            Dante / AES67 discovery, multicast plumbing, PTP sync hints, and
            switch-side hazards — read from your host's view of the network.
          </p>
        </div>
        <div className="flex items-center gap-3">
          {generatedAt && (
            <span className="text-xs text-[var(--color-muted)]">
              Last scan: {generatedAt.toLocaleTimeString()}
            </span>
          )}
          <button
            onClick={() => void load()}
            disabled={loading}
            className="inline-flex items-center gap-2 rounded-lg bg-[var(--color-accent)] px-3.5 py-2 text-sm font-medium text-white hover:opacity-90 disabled:opacity-50"
          >
            <RefreshCw
              className={`h-4 w-4 ${loading ? "animate-spin" : ""}`}
            />
            {loading ? "Scanning…" : av ? "Refresh" : "Run AV diagnostics"}
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-sm text-rose-300">
          {error}
        </div>
      )}

      {/* ── Heuristic warnings strip ── */}
      {av && av.warnings.length > 0 && <WarningStrip warnings={av.warnings} />}

      {/* ── Dante / AES67 devices ── */}
      <DanteDeviceCard
        devices={av?.dante_devices ?? []}
        ddmSeen={av?.ddm_seen ?? false}
        aes67Seen={av?.aes67_seen ?? false}
        loading={loading && !av}
      />

      {/* ── Multicast snapshot ── */}
      <MulticastCard interfaces={av?.multicast ?? []} loading={loading && !av} />

      {/* ── Deep probes (privileged) ── */}
      <DeepProbesCard
        av={av}
        running={deepRunning}
        error={deepError}
        onRun={runDeep}
      />

      {/* ── LLM insights ── */}
      <AvInsights />
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────────
// Warnings
// ────────────────────────────────────────────────────────────────────────

function WarningStrip({ warnings }: { warnings: AvWarning[] }) {
  // Sort critical → warn → info.
  const order = (s: string) =>
    s === "critical" ? 0 : s === "warn" ? 1 : 2;
  const sorted = [...warnings].sort(
    (a, b) => order(a.severity) - order(b.severity),
  );
  return (
    <div className="space-y-2">
      {sorted.map((w, i) => (
        <WarningRow key={i} warning={w} />
      ))}
    </div>
  );
}

function WarningRow({ warning }: { warning: AvWarning }) {
  const tone =
    warning.severity === "critical"
      ? "border-rose-500/40 bg-rose-500/10 text-rose-200"
      : warning.severity === "warn"
        ? "border-amber-500/40 bg-amber-500/10 text-amber-200"
        : "border-sky-500/30 bg-sky-500/10 text-sky-200";
  return (
    <div
      className={`flex items-start gap-3 rounded-lg border p-3 text-sm ${tone}`}
    >
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
      <div className="flex-1">
        <div className="text-[10px] font-semibold uppercase tracking-wide opacity-80">
          {warning.severity} · {warning.category}
        </div>
        <p className="mt-0.5 leading-relaxed">{warning.message}</p>
      </div>
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────────
// Dante device inventory
// ────────────────────────────────────────────────────────────────────────

function DanteDeviceCard({
  devices,
  ddmSeen,
  aes67Seen,
  loading,
}: {
  devices: DanteDevice[];
  ddmSeen: boolean;
  aes67Seen: boolean;
  loading: boolean;
}) {
  return (
    <section className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5">
      <header className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h3 className="flex items-center gap-2 text-sm font-semibold">
            <Cable className="h-4 w-4" />
            Dante / AES67 devices
          </h3>
          <p className="mt-1 text-xs text-[var(--color-muted)]">
            mDNS discovery on{" "}
            <code className="rounded bg-[var(--color-panel-2)] px-1.5 py-0.5 text-[11px]">
              _netaudio
            </code>
            ,{" "}
            <code className="rounded bg-[var(--color-panel-2)] px-1.5 py-0.5 text-[11px]">
              _aes67
            </code>
            , and{" "}
            <code className="rounded bg-[var(--color-panel-2)] px-1.5 py-0.5 text-[11px]">
              _ddm
            </code>{" "}
            service types.
          </p>
        </div>
        <div className="flex gap-2">
          {ddmSeen && (
            <span className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-emerald-300">
              DDM seen
            </span>
          )}
          {aes67Seen && (
            <span className="rounded-full border border-violet-500/30 bg-violet-500/10 px-2.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-violet-300">
              AES67 capable
            </span>
          )}
        </div>
      </header>

      {loading ? (
        <p className="mt-4 text-sm text-[var(--color-muted)]">
          Browsing mDNS for ~5 s…
        </p>
      ) : devices.length === 0 ? (
        <p className="mt-4 text-sm text-[var(--color-muted)]">
          No Dante or AES67 devices found on the current subnet. If you expect
          devices here, check that this host is on the same VLAN and that the
          switch is forwarding mDNS (UDP 5353).
        </p>
      ) : (
        <div className="mt-4 overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-[11px] uppercase tracking-wide text-[var(--color-muted)]">
              <tr>
                <th className="pb-2 pr-3 font-medium">Device</th>
                <th className="pb-2 pr-3 font-medium">IP</th>
                <th className="pb-2 pr-3 font-medium">Channels</th>
                <th className="pb-2 pr-3 font-medium">Sample rate</th>
                <th className="pb-2 pr-3 font-medium">Latency</th>
                <th className="pb-2 pr-3 font-medium">Redundancy</th>
                <th className="pb-2 pr-3 font-medium">Control</th>
                <th className="pb-2 font-medium">Network</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--color-border)]">
              {devices.map((d) => (
                <DanteRow key={d.ip} device={d} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function DanteRow({ device }: { device: DanteDevice }) {
  const redundancyTone =
    device.redundancy === "redundant"
      ? "bg-emerald-500/15 text-emerald-300 border-emerald-500/30"
      : device.redundancy === "primary_only"
        ? "bg-amber-500/15 text-amber-300 border-amber-500/30"
        : "bg-slate-500/15 text-slate-300 border-slate-500/30";
  return (
    <tr className="align-top">
      <td className="py-2 pr-3">
        <div className="font-medium">
          {device.hostname ?? device.model ?? device.ip}
        </div>
        {device.model && (
          <div className="text-[11px] text-[var(--color-muted)]">
            {device.model}
            {device.manufacturer && ` · ${device.manufacturer}`}
          </div>
        )}
      </td>
      <td className="py-2 pr-3 font-mono text-[12px]">{device.ip}</td>
      <td className="py-2 pr-3">
        {device.tx_channels != null || device.rx_channels != null ? (
          <span>
            {device.tx_channels ?? "?"} tx / {device.rx_channels ?? "?"} rx
          </span>
        ) : (
          <span className="text-[var(--color-muted)]">—</span>
        )}
      </td>
      <td className="py-2 pr-3">
        {device.sample_rate_hz != null ? (
          <span>{(device.sample_rate_hz / 1000).toFixed(1)} kHz</span>
        ) : (
          <span className="text-[var(--color-muted)]">—</span>
        )}
      </td>
      <td className="py-2 pr-3">
        {device.latency_profile_ms != null ? (
          <span>{device.latency_profile_ms} ms</span>
        ) : (
          <span className="text-[var(--color-muted)]">—</span>
        )}
      </td>
      <td className="py-2 pr-3">
        <span
          className={`rounded-full border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide ${redundancyTone}`}
        >
          {device.redundancy.replace("_", " ")}
        </span>
      </td>
      <td className="py-2 pr-3 font-mono text-[11px]">
        {device.control_ports_open.length > 0 ? (
          device.control_ports_open.join(", ")
        ) : (
          <span className="font-sans text-[var(--color-muted)]">none</span>
        )}
      </td>
      <td className="py-2">
        {device.on_wifi ? (
          <span className="inline-flex items-center gap-1 rounded-full border border-rose-500/40 bg-rose-500/10 px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide text-rose-300">
            <Wifi className="h-3 w-3" /> Wi-Fi
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide text-emerald-300">
            <Cable className="h-3 w-3" /> Wired
          </span>
        )}
      </td>
    </tr>
  );
}

// ────────────────────────────────────────────────────────────────────────
// Multicast snapshot
// ────────────────────────────────────────────────────────────────────────

function MulticastCard({
  interfaces,
  loading,
}: {
  interfaces: InterfaceMulticast[];
  loading: boolean;
}) {
  return (
    <section className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5">
      <header>
        <h3 className="flex items-center gap-2 text-sm font-semibold">
          <Signal className="h-4 w-4" />
          Multicast snapshot
        </h3>
        <p className="mt-1 text-xs text-[var(--color-muted)]">
          IPv4 multicast groups joined per interface, parsed from{" "}
          <code className="rounded bg-[var(--color-panel-2)] px-1.5 py-0.5 text-[11px]">
            netstat -gn
          </code>
          . Dante audio flows live in <code className="rounded bg-[var(--color-panel-2)] px-1.5 py-0.5 text-[11px]">239.69.x.x</code>;
          PTP on{" "}
          <code className="rounded bg-[var(--color-panel-2)] px-1.5 py-0.5 text-[11px]">
            224.0.1.129–132
          </code>
          .
        </p>
      </header>

      {loading ? (
        <p className="mt-4 text-sm text-[var(--color-muted)]">Loading…</p>
      ) : interfaces.length === 0 ? (
        <p className="mt-4 text-sm text-[var(--color-muted)]">
          No multicast groups joined on any interface.
        </p>
      ) : (
        <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {interfaces.map((i) => (
            <InterfaceCard key={i.iface} iface={i} />
          ))}
        </div>
      )}
    </section>
  );
}

function InterfaceCard({ iface }: { iface: InterfaceMulticast }) {
  const [expanded, setExpanded] = useState(false);
  const danteHighlight = iface.dante_audio_groups > 0;
  return (
    <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)] p-3">
      <div className="flex items-center justify-between">
        <div className="font-medium">{iface.iface}</div>
        <div className="text-[11px] text-[var(--color-muted)]">
          {iface.group_count} group{iface.group_count === 1 ? "" : "s"}
        </div>
      </div>
      <div className="mt-2 flex flex-wrap gap-1.5">
        <Pill
          label={`dante: ${iface.dante_audio_groups}`}
          highlight={danteHighlight}
        />
        <Pill label={`ptp: ${iface.ptp_groups}`} />
      </div>
      <button
        onClick={() => setExpanded((v) => !v)}
        className="mt-2 text-[11px] text-[var(--color-accent)] hover:underline"
      >
        {expanded ? "Hide groups" : "Show groups"}
      </button>
      {expanded && (
        <ul className="mt-2 space-y-1 font-mono text-[11px]">
          {iface.groups.map((g) => (
            <GroupRow key={g.group} group={g} />
          ))}
        </ul>
      )}
    </div>
  );
}

function Pill({ label, highlight }: { label: string; highlight?: boolean }) {
  return (
    <span
      className={`rounded-full border px-2 py-0.5 text-[10px] font-medium ${
        highlight
          ? "border-violet-500/40 bg-violet-500/15 text-violet-300"
          : "border-[var(--color-border)] bg-[var(--color-panel)] text-[var(--color-muted)]"
      }`}
    >
      {label}
    </span>
  );
}

function GroupRow({ group }: { group: MulticastGroup }) {
  return (
    <li className="flex justify-between gap-2">
      <span>{group.group}</span>
      <span className="text-[var(--color-muted)]">{group.purpose}</span>
    </li>
  );
}

// ────────────────────────────────────────────────────────────────────────
// Deep probes (privileged)
// ────────────────────────────────────────────────────────────────────────

function DeepProbesCard({
  av,
  running,
  error,
  onRun,
}: {
  av: ReturnType<typeof useApp.getState>["avDiagnostics"];
  running: boolean;
  error: string | null;
  onRun: (kind: string) => Promise<void>;
}) {
  const result = av?.deep_probe?.igmp ?? null;
  const verdict = result?.verdict ?? null;

  // Severity tint + human-readable headline per verdict.
  const verdictStyle: Record<
    string,
    { label: string; tone: string; explain: string }
  > = {
    querier_present: {
      label: "IGMP querier present",
      tone: "border-emerald-500/30 bg-emerald-500/10 text-emerald-200",
      explain:
        "An IGMP querier is active on this subnet. Switches with IGMP snooping enabled will keep multicast streams (Dante audio, AES67, NDI) flowing without flooding every port.",
    },
    no_querier_observed: {
      label: "Reports seen but NO querier",
      tone: "border-amber-500/30 bg-amber-500/10 text-amber-200",
      explain:
        "Other hosts are joining/leaving multicast groups but no querier is sending General Queries. IGMP-snooping switches will age out the groups in ~5 min and silently drop your audio. Fix: enable an IGMP querier on the L3 device, or disable snooping on the AV VLAN.",
    },
    silent: {
      label: "No IGMP traffic observed",
      tone: "border-sky-500/30 bg-sky-500/10 text-sky-200",
      explain:
        "Nothing on this interface emitted IGMP during the listen window. Likely causes: (a) no multicast subscribers active right now, (b) interface isolated on its own VLAN, or (c) Wi-Fi AP not bridging multicast. Try again with an active Dante session on the wire.",
    },
    error: {
      label: "Probe failed",
      tone: "border-rose-500/30 bg-rose-500/10 text-rose-200",
      explain:
        "The privileged listener could not open a raw socket or bind to the interface. Common causes: the auth prompt was cancelled, the interface name is wrong, or SIP is restricting raw sockets in this environment.",
    },
    not_implemented: {
      label: "Scaffold response",
      tone: "border-zinc-500/30 bg-zinc-500/10 text-zinc-200",
      explain:
        "This build returned a placeholder. Reinstall the latest app bundle to run the real listener.",
    },
  };
  const meta = verdict ? verdictStyle[verdict] : null;

  return (
    <section className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="flex items-center gap-2 text-sm font-semibold">
            <Lock className="h-4 w-4" />
            Deep probes (admin required)
          </h3>
          <p className="mt-1 text-xs text-[var(--color-muted)]">
            Listens for IGMP queriers on the wire — the #1 root cause of
            “Dante devices appear but no audio flows.” macOS will prompt for
            an administrator password.
          </p>
        </div>
        <button
          onClick={() => void onRun("igmp-listen")}
          disabled={running}
          className="inline-flex items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)] px-3.5 py-2 text-sm font-medium hover:bg-[var(--color-panel)] disabled:opacity-50"
        >
          <Lock className="h-4 w-4" />
          {running ? "Listening…" : "Test IGMP querier"}
        </button>
      </header>

      {error && (
        <div className="mt-4 rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-300">
          {error}
        </div>
      )}

      {result && (
        <div className="mt-4 space-y-3">
          <div
            className={`rounded-lg border p-3 text-sm ${
              meta?.tone ??
              "border-[var(--color-border)] bg-[var(--color-panel-2)] text-[var(--color-fg)]"
            }`}
          >
            <div className="font-semibold">
              {meta?.label ?? `Verdict: ${result.verdict}`}
            </div>
            <p className="mt-1 text-[12px] leading-relaxed opacity-90">
              {meta?.explain ??
                "Unrecognised verdict — see raw JSON in the deep_probe payload."}
            </p>
            <div className="mt-2 text-[11px] opacity-80">
              Listened on <code>{result.iface}</code> for {result.listen_secs}s
              · {result.queriers_seen.length} querier(s),{" "}
              {result.reports_seen} report(s), {result.leaves_seen} leave(s)
            </div>
            {result.error && (
              <p className="mt-2 text-xs italic opacity-90">{result.error}</p>
            )}
          </div>

          {result.queriers_seen.length > 0 && (
            <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)] p-3">
              <div className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-[var(--color-muted)]">
                Queriers detected
              </div>
              <div className="space-y-1.5">
                {result.queriers_seen.map((q, i) => (
                  <div
                    key={`${q.from}-${q.group}-${i}`}
                    className="flex flex-wrap items-baseline gap-x-3 gap-y-1 text-xs"
                  >
                    <code className="font-medium text-[var(--color-fg)]">
                      {q.from}
                    </code>
                    <span className="text-[var(--color-muted)]">
                      IGMPv{q.version}
                    </span>
                    <span className="text-[var(--color-muted)]">
                      group <code>{q.group}</code>
                    </span>
                    <span className="text-[var(--color-muted)]">
                      max-resp {(q.max_resp_ds / 10).toFixed(1)}s
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  );
}

export default AvDiagnostics;
