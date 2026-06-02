import { useMemo } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  Activity,
  ArrowDown,
  ArrowRight,
  ArrowUp,
  Globe2,
  Router as RouterIcon,
  Server,
} from "lucide-react";
import { useApp } from "../store";
import type { LiveSample } from "../types";

type MetricKey = "rssi_dbm" | "gateway_ms" | "internet_ms" | "dns_ms";

interface PanelDef {
  key: MetricKey;
  label: string;
  sublabel: string;
  unit: string;
  color: string;
  fillId: string;
  /** lower-is-better metric? */
  lowerIsBetter: boolean;
  /** Threshold lines drawn on the chart (good→warn→bad). */
  thresholds: { warn: number; bad: number };
  /** Optional fixed y-domain; otherwise recharts auto-fits. */
  yDomain?: [number | "auto", number | "auto"];
  Icon: React.ComponentType<{ className?: string }>;
  iconGradient: string;
  format: (v: number) => string;
}

const PANELS: PanelDef[] = [
  {
    key: "rssi_dbm",
    label: "Signal strength",
    sublabel: "RSSI from the access point",
    unit: "dBm",
    color: "#818cf8",
    fillId: "fill-rssi",
    lowerIsBetter: false,
    thresholds: { warn: -70, bad: -80 },
    yDomain: [-90, -30],
    Icon: Activity,
    iconGradient: "from-indigo-500 to-blue-600",
    format: (v) => `${Math.round(v)} dBm`,
  },
  {
    key: "gateway_ms",
    label: "Gateway latency",
    sublabel: "Round-trip to your router",
    unit: "ms",
    color: "#34d399",
    fillId: "fill-gw",
    lowerIsBetter: true,
    thresholds: { warn: 30, bad: 80 },
    Icon: RouterIcon,
    iconGradient: "from-emerald-500 to-teal-600",
    format: (v) => `${v.toFixed(v < 10 ? 1 : 0)} ms`,
  },
  {
    key: "internet_ms",
    label: "Internet latency",
    sublabel: "Round-trip to 1.1.1.1",
    unit: "ms",
    color: "#fbbf24",
    fillId: "fill-inet",
    lowerIsBetter: true,
    thresholds: { warn: 60, bad: 120 },
    Icon: Globe2,
    iconGradient: "from-amber-500 to-orange-600",
    format: (v) => `${v.toFixed(v < 10 ? 1 : 0)} ms`,
  },
  {
    key: "dns_ms",
    label: "DNS resolve",
    sublabel: "getaddrinfo apple.com",
    unit: "ms",
    color: "#f472b6",
    fillId: "fill-dns",
    lowerIsBetter: true,
    thresholds: { warn: 40, bad: 100 },
    Icon: Server,
    iconGradient: "from-pink-500 to-rose-600",
    format: (v) => `${v.toFixed(v < 10 ? 1 : 0)} ms`,
  },
];

interface Row {
  /** seconds before "now" (positive number), used for X scale */
  ago: number;
  /** wall-clock label like "12:04:23" for tooltips */
  clock: string;
  rssi_dbm: number | null;
  gateway_ms: number | null;
  internet_ms: number | null;
  dns_ms: number | null;
  link_up: boolean;
}

function toRows(samples: LiveSample[]): Row[] {
  if (samples.length === 0) return [];
  const newest = new Date(samples[samples.length - 1].ts).getTime();
  return samples.map((s) => {
    const t = new Date(s.ts).getTime();
    return {
      ago: Math.max(0, Math.round((newest - t) / 1000)),
      clock: new Date(s.ts).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      }),
      rssi_dbm: s.rssi_dbm,
      gateway_ms: s.gateway_ms,
      internet_ms: s.internet_ms,
      dns_ms: s.dns_ms,
      link_up: s.link_up,
    };
  });
}

function formatAgo(secsAgo: number): string {
  if (secsAgo <= 5) return "now";
  if (secsAgo < 60) return `-${secsAgo}s`;
  if (secsAgo < 3600) return `-${Math.round(secsAgo / 60)}m`;
  return `-${(secsAgo / 3600).toFixed(1)}h`;
}

/** Tick formatter for the (inverted) X axis — recharts will pass `ago` values. */
function xTickFormatter(value: number): string {
  return formatAgo(value);
}

function statusColor(
  value: number | null,
  panel: PanelDef,
): "good" | "warn" | "bad" | "muted" {
  if (value == null) return "muted";
  if (panel.lowerIsBetter) {
    if (value < panel.thresholds.warn) return "good";
    if (value < panel.thresholds.bad) return "warn";
    return "bad";
  }
  if (value > panel.thresholds.warn) return "good";
  if (value > panel.thresholds.bad) return "warn";
  return "bad";
}

const STATUS_RING: Record<"good" | "warn" | "bad" | "muted", string> = {
  good: "ring-emerald-400/50 text-emerald-300",
  warn: "ring-amber-400/50 text-amber-300",
  bad: "ring-rose-400/60 text-rose-300",
  muted: "ring-slate-600/40 text-slate-400",
};

function latestValue(rows: Row[], key: MetricKey): number | null {
  for (let i = rows.length - 1; i >= 0; i--) {
    const v = rows[i][key];
    if (v != null) return v;
  }
  return null;
}

function trendDirection(
  rows: Row[],
  key: MetricKey,
  panel: PanelDef,
): "up" | "down" | "flat" | "none" {
  // Compare median of last 10s vs median of the prior 50s.
  const recent: number[] = [];
  const baseline: number[] = [];
  for (let i = rows.length - 1; i >= 0; i--) {
    const v = rows[i][key];
    if (v == null) continue;
    if (recent.length < 10) recent.push(v);
    else if (baseline.length < 50) baseline.push(v);
    else break;
  }
  if (recent.length === 0 || baseline.length === 0) return "none";
  const med = (xs: number[]) =>
    xs.slice().sort((a, b) => a - b)[Math.floor(xs.length / 2)];
  const r = med(recent);
  const b = med(baseline);
  const eps = panel.lowerIsBetter
    ? Math.max(2, Math.abs(b) * 0.05)
    : Math.max(2, Math.abs(b) * 0.03);
  if (Math.abs(r - b) < eps) return "flat";
  return r > b ? "up" : "down";
}

function TrendArrow({
  dir,
  isImproving,
}: {
  dir: "up" | "down" | "flat" | "none";
  isImproving: boolean;
}) {
  if (dir === "none")
    return (
      <span className="inline-flex h-5 w-5 items-center justify-center text-slate-500">
        <ArrowRight className="h-3.5 w-3.5" />
      </span>
    );
  if (dir === "flat")
    return (
      <span className="inline-flex h-5 w-5 items-center justify-center rounded-full bg-slate-700/50 text-slate-300">
        <ArrowRight className="h-3.5 w-3.5" />
      </span>
    );
  const colorCls = isImproving
    ? "bg-emerald-500/15 text-emerald-300"
    : "bg-rose-500/15 text-rose-300";
  return (
    <span
      className={`inline-flex h-5 w-5 items-center justify-center rounded-full ${colorCls}`}
      title={isImproving ? "improving" : "degrading"}
    >
      {dir === "up" ? (
        <ArrowUp className="h-3.5 w-3.5" />
      ) : (
        <ArrowDown className="h-3.5 w-3.5" />
      )}
    </span>
  );
}

interface PanelProps {
  panel: PanelDef;
  rows: Row[];
}

function Panel({ panel, rows }: PanelProps) {
  const value = latestValue(rows, panel.key);
  const status = statusColor(value, panel);
  const dir = trendDirection(rows, panel.key, panel);
  // Whether the observed change is good. For "lower-is-better" metrics, a
  // downward trend is improving; for "higher-is-better", upward is improving.
  const isImproving = panel.lowerIsBetter ? dir === "down" : dir === "up";

  const chartData = useMemo(
    () =>
      rows.map((r) => ({
        ago: r.ago,
        clock: r.clock,
        v: r[panel.key],
      })),
    [rows, panel.key],
  );

  // Compute axis ticks: 60m, 45m, 30m, 15m, now.
  const ageRange =
    chartData.length > 0 ? chartData[0].ago : 0; // first row = oldest = largest ago
  const ticks = useMemo(() => {
    const candidates = [3600, 2700, 1800, 900, 0];
    return candidates.filter((t) => t <= ageRange + 5);
  }, [ageRange]);

  const Icon = panel.Icon;

  return (
    <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-4 shadow-sm">
      <div className="flex items-start gap-3">
        <div
          className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br ${panel.iconGradient} text-white shadow-md`}
        >
          <Icon className="h-4 w-4" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center justify-between gap-2">
            <div className="min-w-0">
              <p className="truncate text-xs font-medium uppercase tracking-wider text-[var(--color-muted)]">
                {panel.label}
              </p>
              <p className="truncate text-[10px] text-slate-500">
                {panel.sublabel}
              </p>
            </div>
            <TrendArrow dir={dir} isImproving={isImproving} />
          </div>
          <div className="mt-1.5 flex items-baseline gap-2">
            <span
              className={`inline-flex items-center rounded-lg px-2 py-0.5 text-lg font-semibold tabular-nums ring-1 ring-inset ${STATUS_RING[status]}`}
            >
              {value == null ? "—" : panel.format(value)}
            </span>
            {value == null && (
              <span className="text-[10px] uppercase tracking-wider text-slate-500">
                no data
              </span>
            )}
          </div>
        </div>
      </div>

      <div className="mt-3 h-28 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart
            data={chartData}
            margin={{ top: 6, right: 4, bottom: 0, left: -16 }}
          >
            <defs>
              <linearGradient id={panel.fillId} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={panel.color} stopOpacity={0.45} />
                <stop offset="100%" stopColor={panel.color} stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid
              strokeDasharray="2 4"
              stroke="rgba(148,163,184,0.12)"
              vertical={false}
            />
            <XAxis
              dataKey="ago"
              type="number"
              domain={[3600, 0]}
              ticks={ticks}
              tickFormatter={xTickFormatter}
              tick={{ fill: "rgba(148,163,184,0.65)", fontSize: 10 }}
              axisLine={false}
              tickLine={false}
              reversed
            />
            <YAxis
              tick={{ fill: "rgba(148,163,184,0.65)", fontSize: 10 }}
              axisLine={false}
              tickLine={false}
              width={42}
              domain={panel.yDomain ?? ["auto", "auto"]}
            />
            <Tooltip
              cursor={{ stroke: panel.color, strokeOpacity: 0.3 }}
              contentStyle={{
                background: "rgba(15,23,42,0.95)",
                border: "1px solid rgba(148,163,184,0.2)",
                borderRadius: 8,
                fontSize: 11,
                padding: "6px 10px",
              }}
              labelStyle={{ color: "rgba(226,232,240,0.8)" }}
              itemStyle={{ color: panel.color }}
              labelFormatter={(_label, payload) => {
                const p = payload?.[0]?.payload as
                  | { clock?: string; ago?: number }
                  | undefined;
                if (!p) return "";
                return `${p.clock} (${formatAgo(p.ago ?? 0)})`;
              }}
              formatter={(v) => {
                if (typeof v !== "number" || Number.isNaN(v)) {
                  return ["—", panel.unit];
                }
                return [panel.format(v), panel.unit];
              }}
            />
            <ReferenceLine
              y={panel.thresholds.warn}
              stroke="rgba(251,191,36,0.5)"
              strokeDasharray="3 3"
              ifOverflow="extendDomain"
            />
            <ReferenceLine
              y={panel.thresholds.bad}
              stroke="rgba(244,63,94,0.55)"
              strokeDasharray="3 3"
              ifOverflow="extendDomain"
            />
            <Area
              type="monotone"
              dataKey="v"
              stroke={panel.color}
              strokeWidth={1.75}
              fill={`url(#${panel.fillId})`}
              isAnimationActive={false}
              connectNulls={false}
              dot={false}
              activeDot={{
                r: 3,
                stroke: panel.color,
                strokeWidth: 2,
                fill: "rgba(15,23,42,0.95)",
              }}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

/**
 * Live 60-minute rolling chart panel. Subscribes to the 1 Hz `metric:tick`
 * Tauri event via `useApp` and renders four area charts (signal, gateway,
 * internet, DNS) with current value, trend arrow vs the prior minute, and
 * dashed warn/bad threshold lines.
 *
 * Empty state shows a hint that the live sampler will populate within ~1s
 * of monitoring being on.
 */
export function LiveMetricsChart() {
  const liveSamples = useApp((s) => s.liveSamples);
  const monitoring = useApp((s) => s.monitoring);
  const rows = useMemo(() => toRows(liveSamples), [liveSamples]);

  const seconds = liveSamples.length;
  const coverage = seconds === 0 ? "—" : formatAgo(seconds - 1);

  return (
    <section>
      <div className="mb-3 flex items-end justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold uppercase tracking-wider text-[var(--color-muted)]">
            Live network telemetry
          </h2>
          <p className="mt-0.5 text-xs text-slate-500">
            1 Hz sampler · rolling 60 min · threshold lines mark{" "}
            <span className="text-amber-400/80">warn</span> and{" "}
            <span className="text-rose-400/80">critical</span>
          </p>
        </div>
        <div className="flex items-center gap-3 text-xs">
          <span className="text-slate-500 tabular-nums">
            history: <span className="text-slate-300">{coverage}</span>
          </span>
          <span
            className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs ${
              monitoring
                ? "bg-emerald-500/15 text-emerald-300"
                : "bg-slate-600/30 text-slate-400"
            }`}
          >
            <span
              className={`h-1.5 w-1.5 rounded-full ${
                monitoring ? "animate-pulse bg-emerald-400" : "bg-slate-500"
              }`}
            />
            {monitoring ? "live" : "paused"}
          </span>
        </div>
      </div>

      {seconds === 0 ? (
        <div className="rounded-2xl border border-dashed border-[var(--color-border)] bg-[var(--color-panel)]/60 px-6 py-10 text-center">
          <p className="text-sm text-[var(--color-muted)]">
            Warming up the live sampler…
          </p>
          <p className="mt-1 text-xs text-slate-500">
            The first telemetry tick should arrive within a second of
            monitoring being on. If this hint stays, check that monitoring is
            enabled.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          {PANELS.map((panel) => (
            <Panel key={panel.key} panel={panel} rows={rows} />
          ))}
        </div>
      )}
    </section>
  );
}
