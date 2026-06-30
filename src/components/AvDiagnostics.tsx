import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Activity,
  AlertTriangle,
  Cable,
  Gauge,
  Lock,
  Network,
  Radio,
  RefreshCw,
  Signal,
  Stethoscope,
  Wifi,
  Zap,
} from "lucide-react";
import { useApp } from "../store";
import { AvInsights } from "./AvInsights";
import type {
  AvWarning,
  DanteDevice,
  DscpProbeResult,
  InterfaceMulticast,
  LinkAuditResult,
  LldpProbeResult,
  MulticastGroup,
  PtpProbeResult,
  RunbookSummary,
  SapProbeResult,
  StpProbeResult,
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
      <div className="atlas-card flex flex-col gap-4 p-5">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-[var(--color-accent)]">
              <Wifi className="h-3.5 w-3.5" /> AV / Multicast
            </div>
            <h2 className="mt-1 text-xl font-semibold tracking-tight">
              AV-over-IP diagnostics
            </h2>
            <p className="mt-1 text-sm leading-relaxed text-[var(--color-muted)]">
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
              className="inline-flex items-center gap-2 rounded-lg bg-gradient-to-b from-[var(--color-accent)] to-[#b8893f] px-3.5 py-2 text-sm font-semibold text-[var(--atlas-navy,#0B1F3A)] shadow-[inset_0_1px_0_rgba(255,255,255,0.25),0_6px_14px_-8px_rgba(212,162,76,0.6)] transition-opacity hover:opacity-95 disabled:opacity-50"
            >
              <RefreshCw
                className={`h-4 w-4 ${loading ? "animate-spin" : ""}`}
              />
              {loading ? "Scanning…" : av ? "Refresh" : "Run AV diagnostics"}
            </button>
          </div>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-sm text-rose-300">
          {error}
        </div>
      )}

      {/* ── LLM insights ── */}
      <AvInsights />

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
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────────
// Warnings
// ────────────────────────────────────────────────────────────────────────

function WarningStrip({ warnings }: { warnings: AvWarning[] }) {
  const openRunbook = useApp((s) => s.openRunbook);
  const [suggestions, setSuggestions] = useState<(RunbookSummary | null)[]>([]);

  // Ask the backend (deterministic, no LLM) which runbook best matches each
  // warning so we can offer a one-click "Diagnose" jump into the Runbooks tab.
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const symptoms = warnings.map((w) => `${w.category}: ${w.message}`);
        const res = await invoke<(RunbookSummary | null)[]>(
          "suggest_runbooks",
          { symptoms },
        );
        if (!cancelled) setSuggestions(res);
      } catch {
        if (!cancelled) setSuggestions([]);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [warnings]);

  // Sort critical → warn → info, keeping each warning paired with its match.
  const order = (s: string) => (s === "critical" ? 0 : s === "warn" ? 1 : 2);
  const rows = warnings
    .map((warning, i) => ({ warning, suggestion: suggestions[i] ?? null }))
    .sort((a, b) => order(a.warning.severity) - order(b.warning.severity));
  return (
    <div className="space-y-2">
      {rows.map(({ warning, suggestion }, i) => (
        <WarningRow
          key={i}
          warning={warning}
          suggestion={suggestion}
          onDiagnose={openRunbook}
        />
      ))}
    </div>
  );
}

function WarningRow({
  warning,
  suggestion,
  onDiagnose,
}: {
  warning: AvWarning;
  suggestion: RunbookSummary | null;
  onDiagnose: (id: string) => void;
}) {
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
        {suggestion && (
          <button
            type="button"
            onClick={() => onDiagnose(suggestion.id)}
            title={suggestion.description}
            className="mt-2 inline-flex items-center gap-1.5 rounded-md border border-current/40 bg-black/10 px-2.5 py-1 text-[11px] font-semibold transition-opacity hover:opacity-80"
          >
            <Stethoscope className="h-3.5 w-3.5" />
            Diagnose with “{suggestion.name}”
          </button>
        )}
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
// Deep probes (privileged + unprivileged)
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
  const deep = av?.deep_probe ?? null;
  const igmp = deep?.igmp ?? null;
  const ptp = deep?.ptp ?? null;
  const dscp = deep?.dscp ?? null;
  const lldp = deep?.lldp ?? null;
  const linkAudit = deep?.link_audit ?? null;
  const sap = deep?.sap ?? null;

  return (
    <section className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="flex items-center gap-2 text-sm font-semibold">
            <Lock className="h-4 w-4" />
            Switch readiness probes
          </h3>
          <p className="mt-1 text-xs text-[var(--color-muted)]">
            Active listeners that diagnose the switch fabric behind your AV
            traffic: IGMP queriers, PTP grandmasters, DSCP/TTL preservation,
            neighbour identification, link-layer hygiene, and SAP/SDP stream
            announcements. IGMP requires an admin password; the rest run
            unprivileged.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => void onRun("all")}
            disabled={running}
            className="inline-flex items-center gap-2 rounded-lg bg-[var(--color-accent)] px-3.5 py-2 text-sm font-medium text-white hover:opacity-90 disabled:opacity-50"
          >
            <Activity
              className={`h-4 w-4 ${running ? "animate-pulse" : ""}`}
            />
            {running ? "Probing…" : "Run full switch audit"}
          </button>
        </div>
      </header>

      {error && (
        <div className="mt-4 rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-300">
          {error}
        </div>
      )}

      <div className="mt-4 grid grid-cols-1 gap-3 lg:grid-cols-2">
        <IgmpProbePanel
          result={igmp}
          running={running}
          onRun={() => void onRun("igmp-listen")}
        />
        <PtpProbePanel
          result={ptp}
          running={running}
          onRun={() => void onRun("ptp-listen")}
        />
        <DscpProbePanel
          result={dscp}
          running={running}
          onRun={() => void onRun("dscp-audit")}
        />
        <LldpProbePanel
          result={lldp}
          running={running}
          onRun={() => void onRun("lldp-listen")}
        />
        <LinkAuditPanel
          result={linkAudit}
          running={running}
          onRun={() => void onRun("link-audit")}
        />
        <SapProbePanel
          result={sap}
          running={running}
          onRun={() => void onRun("sap-listen")}
        />
      </div>
    </section>
  );
}

// ────────────────────────────────────────────────────────────────────────
// Per-probe panels
// ────────────────────────────────────────────────────────────────────────

function VerdictBadge({
  tone,
  label,
}: {
  tone: "good" | "warn" | "bad" | "info" | "unknown";
  label: string;
}) {
  const cls =
    tone === "good"
      ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
      : tone === "warn"
        ? "border-amber-500/40 bg-amber-500/10 text-amber-300"
        : tone === "bad"
          ? "border-rose-500/40 bg-rose-500/10 text-rose-300"
          : tone === "info"
            ? "border-sky-500/40 bg-sky-500/10 text-sky-300"
            : "border-zinc-500/30 bg-zinc-500/10 text-zinc-300";
  return (
    <span
      className={`rounded-full border px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide ${cls}`}
    >
      {label}
    </span>
  );
}

function ProbePanelShell({
  icon,
  title,
  hint,
  running,
  onRun,
  buttonLabel,
  children,
  badge,
}: {
  icon: React.ReactNode;
  title: string;
  hint: string;
  running: boolean;
  onRun: () => void;
  buttonLabel: string;
  children: React.ReactNode;
  badge?: React.ReactNode;
}) {
  return (
    <div className="rounded-xl border border-[var(--color-border)] bg-[var(--color-panel-2)] p-4">
      <header className="flex items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="text-[var(--color-muted)]">{icon}</span>
            <h4 className="text-sm font-semibold">{title}</h4>
            {badge}
          </div>
          <p className="mt-1 text-[11px] leading-relaxed text-[var(--color-muted)]">
            {hint}
          </p>
        </div>
        <button
          onClick={onRun}
          disabled={running}
          className="shrink-0 rounded-md border border-[var(--color-border)] bg-[var(--color-panel)] px-2.5 py-1 text-[11px] font-medium hover:bg-[var(--color-panel-2)] disabled:opacity-50"
        >
          {buttonLabel}
        </button>
      </header>
      <div className="mt-3">{children}</div>
    </div>
  );
}

function IgmpProbePanel({
  result,
  running,
  onRun,
}: {
  result: import("../types").IgmpProbeResult | null;
  running: boolean;
  onRun: () => void;
}) {
  const verdict = result?.verdict ?? null;
  const verdictMeta: Record<
    string,
    { label: string; tone: "good" | "warn" | "bad" | "info"; text: string }
  > = {
    querier_present: {
      label: "Querier present",
      tone: "good",
      text: "An IGMP querier is active. Snooping switches will keep Dante/AES67/NDI streams flowing without flooding.",
    },
    no_querier_observed: {
      label: "No querier",
      tone: "warn",
      text: "Reports/leaves observed but no General Query. Snooping switches will age out groups in ~5 min and silently drop audio.",
    },
    silent: {
      label: "Silent",
      tone: "info",
      text: "No IGMP traffic during the ~130s listen window. Most queriers send one General Query every 125s, so a silent result usually means: wrong NIC pinned, the local firewall is dropping IGMP delivery to user-mode (Windows Defender Firewall inbound rules), or the switch's snooping VLAN doesn't reach this segment.",
    },
    error: {
      label: "Error",
      tone: "bad",
      text: "Privileged listener failed (auth cancelled, iface wrong, or raw-socket restriction).",
    },
    not_implemented: {
      label: "Not implemented",
      tone: "info",
      text: "Scaffold response — reinstall to run the real listener.",
    },
  };
  const meta = verdict ? verdictMeta[verdict] : null;

  return (
    <ProbePanelShell
      icon={<Network className="h-4 w-4" />}
      title="IGMP querier"
      hint="Listens on UDP 224.0.0.1 for IGMP General Queries — the #1 cause of 'Dante devices appear but no audio flows'. Listen runs for ~130s so it catches the RFC-default 125s query interval. Requires admin."
      running={running}
      onRun={onRun}
      buttonLabel="Test"
      badge={meta && <VerdictBadge tone={meta.tone} label={meta.label} />}
    >
      {!result ? (
        <p className="text-xs text-[var(--color-muted)]">
          Not run yet. Click <strong>Test</strong> to listen for ~12 s.
        </p>
      ) : (
        <div className="space-y-2 text-xs">
          <p className="leading-relaxed">{meta?.text ?? result.verdict}</p>
          {result.detail && (
            <p className="rounded-md border border-[var(--color-border)] bg-[var(--color-panel)] p-2 leading-relaxed text-[var(--color-muted)]">
              {result.detail}
            </p>
          )}
          <div className="text-[11px] text-[var(--color-muted)]">
            iface <code>{result.iface}</code> · {result.queriers_seen.length}{" "}
            querier(s), {result.reports_seen} report(s),{" "}
            {result.leaves_seen} leave(s)
          </div>
          {result.queriers_seen.length > 0 && (
            <div className="space-y-1 rounded-md border border-[var(--color-border)] bg-[var(--color-panel)] p-2">
              {result.queriers_seen.map((q, i) => (
                <div
                  key={`${q.from}-${q.group}-${i}`}
                  className="text-[11px]"
                >
                  <code>{q.from}</code> · v{q.version} · group{" "}
                  <code>{q.group}</code> · max-resp{" "}
                  {(q.max_resp_ds / 10).toFixed(1)}s
                </div>
              ))}
            </div>
          )}
          {result.error && (
            <p className="text-[11px] italic text-rose-300">{result.error}</p>
          )}
        </div>
      )}
    </ProbePanelShell>
  );
}

/** Map a problem STP verdict to a symptom string the deterministic runbook
 *  matcher can resolve to the L2-loop / STP runbook. Healthy / inconclusive
 *  verdicts return null (no suggestion). */
function stpSymptom(verdict: string): string | null {
  switch (verdict) {
    case "loop_suspected":
      return "switching loop broadcast storm duplicate frames";
    case "topology_unstable":
      return "spanning tree topology change instability flapping";
    case "multiple_roots":
      return "multiple stp root bridges spanning tree";
    case "legacy_stp":
      return "legacy stp spanning tree slow convergence";
    default:
      return null;
  }
}

export function StpProbePanel({
  result,
  running,
  onRun,
}: {
  result: StpProbeResult | null;
  running: boolean;
  onRun: () => void;
}) {
  const openRunbook = useApp((s) => s.openRunbook);
  const [suggestion, setSuggestion] = useState<RunbookSummary | null>(null);
  const symptom = result ? stpSymptom(result.verdict) : null;
  useEffect(() => {
    let cancelled = false;
    if (!symptom) {
      setSuggestion(null);
      return;
    }
    void (async () => {
      try {
        const res = await invoke<(RunbookSummary | null)[]>("suggest_runbooks", {
          symptoms: [symptom],
        });
        if (!cancelled) setSuggestion(res[0] ?? null);
      } catch {
        if (!cancelled) setSuggestion(null);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [symptom]);

  const verdictMeta: Record<
    string,
    { label: string; tone: "good" | "warn" | "bad" | "info"; text: string }
  > = {
    stp_healthy: {
      label: "STP healthy",
      tone: "good",
      text: "Spanning tree is stable: a single root bridge, modern RSTP/MSTP, and few topology changes.",
    },
    legacy_stp: {
      label: "Legacy STP",
      tone: "warn",
      text: "Classic 802.1D STP detected — 30–50 s convergence drops AV streams on any topology change. Move this segment to RSTP/MSTP.",
    },
    multiple_roots: {
      label: "Multiple roots",
      tone: "bad",
      text: "More than one STP root bridge on this segment — usually two spanning-tree domains bridged together, or a misconfigured root.",
    },
    topology_unstable: {
      label: "Topology churn",
      tone: "bad",
      text: "Frequent topology changes — a flapping link or intermittent loop is forcing constant re-convergence (expect brief dropouts).",
    },
    loop_suspected: {
      label: "Loop suspected",
      tone: "bad",
      text: "Broadcast storm and/or duplicate frames — the classic fingerprint of an L2 switching loop. Check for a cabling loop or a port that should be blocking.",
    },
    no_bpdus_observed: {
      label: "No BPDUs",
      tone: "info",
      text: "No BPDUs seen. Edge ports with BPDU Guard/PortFast don't forward them, so this is inconclusive for STP — but the loop signals (broadcast rate, duplicates) remain valid.",
    },
    silent: {
      label: "Silent",
      tone: "info",
      text: "No multicast/broadcast frames captured. On macOS this usually means the test needs admin — run it from this button.",
    },
    not_supported: {
      label: "Unsupported",
      tone: "info",
      text: "Raw L2 capture for STP / loop detection isn't available on this platform yet.",
    },
    error: {
      label: "Error",
      tone: "bad",
      text: "Capture failed to start.",
    },
  };
  const meta = result?.verdict ? verdictMeta[result.verdict] : null;

  return (
    <ProbePanelShell
      icon={<Cable className="h-4 w-4" />}
      title="STP / L2 loop"
      hint="Passively listens for spanning-tree BPDUs plus broadcast / duplicate-frame storms — the signatures of switching loops and an unstable spanning tree. Requires admin (raw capture)."
      running={running}
      onRun={onRun}
      buttonLabel="Test"
      badge={meta && <VerdictBadge tone={meta.tone} label={meta.label} />}
    >
      {!result ? (
        <p className="text-xs text-[var(--color-muted)]">
          Not run yet. Click <strong>Test</strong> to listen for ~30 s.
        </p>
      ) : (
        <div className="space-y-2 text-xs">
          <p className="leading-relaxed">{meta?.text ?? result.verdict}</p>
          {result.detail && (
            <p className="rounded-md border border-[var(--color-border)] bg-[var(--color-panel)] p-2 leading-relaxed text-[var(--color-muted)]">
              {result.detail}
            </p>
          )}
          <div className="text-[11px] text-[var(--color-muted)]">
            iface <code>{result.iface}</code> · {result.bpdus_seen} BPDU(s) ·{" "}
            {result.topology_changes} topo change(s) ·{" "}
            {Math.round(result.broadcast_pps_peak)} bcast/s peak ·{" "}
            {(result.duplicate_frame_ratio * 100).toFixed(0)}% dup
            {result.stp_version ? <> · {result.stp_version}</> : null}
          </div>
          {result.root_bridges.length > 0 && (
            <div className="space-y-1 rounded-md border border-[var(--color-border)] bg-[var(--color-panel)] p-2">
              {result.root_bridges.map((r, i) => (
                <div key={`${r.bridge_id}-${i}`} className="text-[11px]">
                  root <code>{r.bridge_id}</code> · {r.version} · cost{" "}
                  {r.root_path_cost} · {r.announces_seen} BPDU(s)
                </div>
              ))}
            </div>
          )}
          {suggestion && (
            <button
              type="button"
              onClick={() => openRunbook(suggestion.id)}
              title={suggestion.description}
              className="inline-flex items-center gap-1.5 rounded-md border border-[var(--color-accent)]/40 bg-[var(--color-accent)]/10 px-2.5 py-1 text-[11px] font-semibold text-[var(--color-accent)] transition-opacity hover:opacity-80"
            >
              <Stethoscope className="h-3.5 w-3.5" />
              Diagnose with “{suggestion.name}”
            </button>
          )}
          {result.error && (
            <p className="text-[11px] italic text-rose-300">{result.error}</p>
          )}
        </div>
      )}
    </ProbePanelShell>
  );
}

function PtpProbePanel({
  result,
  running,
  onRun,
}: {
  result: PtpProbeResult | null;
  running: boolean;
  onRun: () => void;
}) {
  const verdictMeta: Record<
    string,
    { label: string; tone: "good" | "warn" | "bad" | "info"; text: string }
  > = {
    stable_gm: {
      label: "Stable GM",
      tone: "good",
      text: "Exactly one grandmaster per domain — clean clocking for Dante / AES67.",
    },
    multiple_gms: {
      label: "Competing GMs",
      tone: "warn",
      text: "Multiple grandmasters announcing on the same PTP domain. BMCA will pick one, but rogue GMs cause audio dropouts during failover.",
    },
    jittery_sync: {
      label: "Jittery sync",
      tone: "warn",
      text: "Sync messages arrive with > 1 ms jitter. Likely a non-AV-capable switch in the path; expect audio artefacts.",
    },
    no_ptp: {
      label: "No PTP",
      tone: "info",
      text: "No PTP traffic observed. AES67 / SMPTE 2110 need PTPv2; install / enable a grandmaster.",
    },
    silent: {
      label: "Silent",
      tone: "info",
      text: "Nothing on the wire during the listen window.",
    },
    error: {
      label: "Error",
      tone: "bad",
      text: "Listener failed to bind.",
    },
  };
  const meta = result ? verdictMeta[result.verdict] : null;

  return (
    <ProbePanelShell
      icon={<Activity className="h-4 w-4" />}
      title="PTP grandmaster"
      hint="Listens for IEEE-1588 PTP over UDP 319/320 and L2 Ethernet (ethertype 0x88F7, SMPTE 2110 / AVB) — identifies grandmasters, profile (media vs default), and sync jitter."
      running={running}
      onRun={onRun}
      buttonLabel="Listen"
      badge={meta && <VerdictBadge tone={meta.tone} label={meta.label} />}
    >
      {!result ? (
        <p className="text-xs text-[var(--color-muted)]">Not run yet.</p>
      ) : (
        <div className="space-y-2 text-xs">
          <p className="leading-relaxed">{meta?.text ?? result.verdict}</p>
          <div className="text-[11px] text-[var(--color-muted)]">
            {result.domains.length} domain(s) · {result.total_announces}{" "}
            announce, {result.total_syncs} sync, {result.total_delays} delay
          </div>
          {result.domains.map((d) => (
            <div
              key={`${d.domain}-${d.version}`}
              className="space-y-1 rounded-md border border-[var(--color-border)] bg-[var(--color-panel)] p-2"
            >
              <div className="flex items-center gap-2 text-[11px]">
                <span className="font-semibold">
                  domain {d.domain} · v{d.version}
                </span>
                <span className="rounded bg-[var(--color-panel-2)] px-1.5 text-[10px] uppercase tracking-wide text-[var(--color-muted)]">
                  {d.profile}
                </span>
                {d.sync_jitter_us !== null && (
                  <span className="text-[10px] text-[var(--color-muted)]">
                    jitter ≈ {d.sync_jitter_us.toFixed(0)} µs
                  </span>
                )}
              </div>
              {d.grandmasters.map((gm) => (
                <div
                  key={gm.clock_identity}
                  className="text-[11px] text-[var(--color-muted)]"
                >
                  <code>{gm.clock_identity}</code> · prio1 {gm.priority1} ·
                  class {gm.clock_class} · from <code>{gm.source_ip}</code>
                </div>
              ))}
            </div>
          ))}
          {result.error && (
            <p className="text-[11px] italic text-rose-300">{result.error}</p>
          )}
        </div>
      )}
    </ProbePanelShell>
  );
}

function DscpProbePanel({
  result,
  running,
  onRun,
}: {
  result: DscpProbeResult | null;
  running: boolean;
  onRun: () => void;
}) {
  const verdictMeta: Record<
    string,
    { label: string; tone: "good" | "warn" | "bad" | "info"; text: string }
  > = {
    qos_preserved: {
      label: "QoS preserved",
      tone: "good",
      text: "DSCP markings arrived intact — switches are honouring AV priority.",
    },
    qos_stripped: {
      label: "QoS stripped",
      tone: "bad",
      text: "All observed packets arrived with DSCP = 0. A switch or router on the path is rewriting markings; AV traffic will be best-effort.",
    },
    qos_mixed: {
      label: "QoS mixed",
      tone: "warn",
      text: "Some streams kept their markings, others were stripped. Inspect per-stream below.",
    },
    qos_unavailable_on_platform: {
      label: "Not on Windows v1",
      tone: "info",
      text: "Windows does not expose received IP_TOS via the standard recv path. This release ships full DSCP inspection on macOS & Linux only.",
    },
    silent: {
      label: "Silent",
      tone: "info",
      text: "No PTP/AES67 packets reached the listener during the window.",
    },
    error: {
      label: "Error",
      tone: "bad",
      text: "Listener failed.",
    },
  };
  const meta = result ? verdictMeta[result.verdict] : null;

  return (
    <ProbePanelShell
      icon={<Gauge className="h-4 w-4" />}
      title="DSCP / TTL audit"
      hint="Receives PTP and AES67 multicast and reads IP_TOS / TTL via cmsg — proves whether your switches rewrite QoS markings (the silent killer of AV audio)."
      running={running}
      onRun={onRun}
      buttonLabel="Audit"
      badge={meta && <VerdictBadge tone={meta.tone} label={meta.label} />}
    >
      {!result ? (
        <p className="text-xs text-[var(--color-muted)]">Not run yet.</p>
      ) : (
        <div className="space-y-2 text-xs">
          <p className="leading-relaxed">{meta?.text ?? result.verdict}</p>
          {result.observations.length > 0 && (
            <div className="space-y-1 rounded-md border border-[var(--color-border)] bg-[var(--color-panel)] p-2">
              {result.observations.map((o, i) => (
                <div key={i} className="text-[11px]">
                  <code>{o.stream_kind}</code> · grp {o.dst_group}:{o.dst_port}{" "}
                  · DSCP {o.observed_dscp_median}
                  {o.expected_dscp !== null && (
                    <span className="text-[var(--color-muted)]">
                      {" "}
                      (expected {o.expected_dscp})
                    </span>
                  )}{" "}
                  · TTL {o.observed_ttl_median} (min {o.observed_ttl_min}) ·{" "}
                  <span
                    className={
                      o.qos_status === "preserved"
                        ? "text-emerald-300"
                        : o.qos_status === "stripped"
                          ? "text-rose-300"
                          : "text-amber-300"
                    }
                  >
                    {o.qos_status}
                  </span>
                </div>
              ))}
            </div>
          )}
          {result.error && (
            <p className="text-[11px] italic text-rose-300">{result.error}</p>
          )}
        </div>
      )}
    </ProbePanelShell>
  );
}

function LldpProbePanel({
  result,
  running,
  onRun,
}: {
  result: LldpProbeResult | null;
  running: boolean;
  onRun: () => void;
}) {
  const verdictMeta: Record<
    string,
    { label: string; tone: "good" | "warn" | "bad" | "info"; text: string }
  > = {
    switch_identified: {
      label: "Switch identified",
      tone: "good",
      text: "An L2 neighbour with a switch-vendor OUI is on this subnet.",
    },
    neighbors_only: {
      label: "Neighbours only",
      tone: "info",
      text: "Host neighbours found but no switch-vendor MAC. The upstream switch may not be ARP-visible from this host (typical for managed L3 hops).",
    },
    silent: {
      label: "Silent",
      tone: "info",
      text: "No ARP entries reachable.",
    },
    not_supported: {
      label: "Not supported",
      tone: "info",
      text: "ARP enumeration unavailable on this platform.",
    },
    error: {
      label: "Error",
      tone: "bad",
      text: "Probe failed.",
    },
  };
  const meta = result ? verdictMeta[result.verdict] : null;

  return (
    <ProbePanelShell
      icon={<Radio className="h-4 w-4" />}
      title="Neighbour ID (LLDP fallback)"
      hint="Enumerates same-subnet neighbours via ARP and matches OUIs against switch-vendor lists. Real LLDP/CDP capture requires a raw-socket helper (planned)."
      running={running}
      onRun={onRun}
      buttonLabel="Scan"
      badge={meta && <VerdictBadge tone={meta.tone} label={meta.label} />}
    >
      {!result ? (
        <p className="text-xs text-[var(--color-muted)]">Not run yet.</p>
      ) : (
        <div className="space-y-2 text-xs">
          <p className="leading-relaxed">{meta?.text ?? result.verdict}</p>
          <div className="text-[11px] text-[var(--color-muted)]">
            {result.neighbors.length} neighbour(s) via{" "}
            <code>{result.mechanism}</code>
          </div>
          {result.neighbors.length > 0 && (
            <div className="max-h-40 space-y-1 overflow-y-auto rounded-md border border-[var(--color-border)] bg-[var(--color-panel)] p-2">
              {result.neighbors.map((n, i) => {
                const isSwitch = n.capabilities.includes("inferred-switch");
                return (
                  <div key={`${n.source_mac}-${i}`} className="text-[11px]">
                    <code>{n.source_mac}</code>{" "}
                    {n.source_ip && (
                      <span className="text-[var(--color-muted)]">
                        ({n.source_ip})
                      </span>
                    )}{" "}
                    ·{" "}
                    <span
                      className={
                        isSwitch
                          ? "font-medium text-emerald-300"
                          : "text-[var(--color-muted)]"
                      }
                    >
                      {n.oui_vendor ?? "unknown vendor"}
                    </span>
                    {isSwitch && <span className="ml-1">⇠ switch</span>}
                  </div>
                );
              })}
            </div>
          )}
          {result.error && (
            <p className="text-[11px] italic text-rose-300">{result.error}</p>
          )}
        </div>
      )}
    </ProbePanelShell>
  );
}

function LinkAuditPanel({
  result,
  running,
  onRun,
}: {
  result: LinkAuditResult | null;
  running: boolean;
  onRun: () => void;
}) {
  const verdictMeta: Record<
    string,
    { label: string; tone: "good" | "warn" | "bad" | "info"; text: string }
  > = {
    ready_for_av: {
      label: "Ready",
      tone: "good",
      text: "Link looks clean for AV-over-IP: ≥ 1 Gb/s full-duplex with EEE & flow-control off.",
    },
    needs_attention: {
      label: "Needs attention",
      tone: "warn",
      text: "Link has one or more AV-hostile settings — see issues below.",
    },
    unknown: {
      label: "Unknown",
      tone: "info",
      text: "Could not determine link parameters. Driver may not expose them, or the iface name is wrong.",
    },
    error: {
      label: "Error",
      tone: "bad",
      text: "Audit failed.",
    },
  };
  const meta = result ? verdictMeta[result.verdict] : null;

  return (
    <ProbePanelShell
      icon={<Zap className="h-4 w-4" />}
      title="Link hygiene"
      hint="Checks speed, duplex, MTU, Energy-Efficient Ethernet (EEE), and flow-control — EEE alone causes 50–100 ms packet stalls fatal to Dante."
      running={running}
      onRun={onRun}
      buttonLabel="Audit"
      badge={meta && <VerdictBadge tone={meta.tone} label={meta.label} />}
    >
      {!result ? (
        <p className="text-xs text-[var(--color-muted)]">Not run yet.</p>
      ) : (
        <div className="space-y-2 text-xs">
          <p className="leading-relaxed">{meta?.text ?? result.verdict}</p>
          <div className="grid grid-cols-2 gap-x-3 gap-y-1 rounded-md border border-[var(--color-border)] bg-[var(--color-panel)] p-2 text-[11px]">
            <div>
              speed:{" "}
              <span className="font-medium">
                {result.speed_mbps !== null
                  ? `${result.speed_mbps} Mbps`
                  : "—"}
              </span>
            </div>
            <div>
              duplex:{" "}
              <span className="font-medium">{result.duplex ?? "—"}</span>
            </div>
            <div>
              MTU: <span className="font-medium">{result.mtu ?? "—"}</span>
            </div>
            <div>
              EEE:{" "}
              <span
                className={
                  result.eee_enabled
                    ? "font-medium text-amber-300"
                    : "font-medium"
                }
              >
                {result.eee_enabled === null
                  ? "—"
                  : result.eee_enabled
                    ? "ON ⚠"
                    : "off"}
              </span>
            </div>
            <div>
              flow-ctrl rx:{" "}
              <span
                className={
                  result.flow_control_rx
                    ? "font-medium text-amber-300"
                    : "font-medium"
                }
              >
                {result.flow_control_rx === null
                  ? "—"
                  : result.flow_control_rx
                    ? "on ⚠"
                    : "off"}
              </span>
            </div>
            <div>
              flow-ctrl tx:{" "}
              <span
                className={
                  result.flow_control_tx
                    ? "font-medium text-amber-300"
                    : "font-medium"
                }
              >
                {result.flow_control_tx === null
                  ? "—"
                  : result.flow_control_tx
                    ? "on ⚠"
                    : "off"}
              </span>
            </div>
          </div>
          {result.issues.length > 0 && (
            <ul className="space-y-1 text-[11px] text-amber-300">
              {result.issues.map((i, k) => (
                <li key={k}>• {i}</li>
              ))}
            </ul>
          )}
          {result.error && (
            <p className="text-[11px] italic text-rose-300">{result.error}</p>
          )}
        </div>
      )}
    </ProbePanelShell>
  );
}

function SapProbePanel({
  result,
  running,
  onRun,
}: {
  result: SapProbeResult | null;
  running: boolean;
  onRun: () => void;
}) {
  const verdictMeta: Record<
    string,
    { label: string; tone: "good" | "warn" | "bad" | "info"; text: string }
  > = {
    streams_found: {
      label: "Streams found",
      tone: "good",
      text: "AES67 / SAP / SDP announcements are flowing — receivers can auto-discover transmitters.",
    },
    silent: {
      label: "Silent",
      tone: "info",
      text: "No SAP announcements observed. AES67 transmitters either aren't running or aren't bridging to this VLAN.",
    },
    error: {
      label: "Error",
      tone: "bad",
      text: "Listener failed.",
    },
  };
  const meta = result ? verdictMeta[result.verdict] : null;

  return (
    <ProbePanelShell
      icon={<Signal className="h-4 w-4" />}
      title="SAP / SDP discovery"
      hint="Listens on 224.2.127.254:9875 for Session Announcement Protocol — discovers AES67 streams the way receivers do."
      running={running}
      onRun={onRun}
      buttonLabel="Listen"
      badge={meta && <VerdictBadge tone={meta.tone} label={meta.label} />}
    >
      {!result ? (
        <p className="text-xs text-[var(--color-muted)]">Not run yet.</p>
      ) : (
        <div className="space-y-2 text-xs">
          <p className="leading-relaxed">{meta?.text ?? result.verdict}</p>
          <div className="text-[11px] text-[var(--color-muted)]">
            {result.announcements_seen} announcement(s) ·{" "}
            {result.streams.length} unique stream(s)
          </div>
          {result.streams.length > 0 && (
            <div className="max-h-40 space-y-1 overflow-y-auto rounded-md border border-[var(--color-border)] bg-[var(--color-panel)] p-2">
              {result.streams.map((s, i) => (
                <div key={i} className="text-[11px]">
                  <span className="font-medium">{s.session_name}</span> ·{" "}
                  <code>
                    {s.multicast_group}:{s.port}
                  </code>{" "}
                  · L{s.payload_type}
                  {s.sample_rate_hz && ` @ ${s.sample_rate_hz / 1000} kHz`}
                  {s.channels && ` × ${s.channels}ch`}
                  {s.ptime_ms !== null && ` · ${s.ptime_ms} ms`}
                </div>
              ))}
            </div>
          )}
          {result.error && (
            <p className="text-[11px] italic text-rose-300">{result.error}</p>
          )}
        </div>
      )}
    </ProbePanelShell>
  );
}

export default AvDiagnostics;
