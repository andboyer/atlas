import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from "recharts";
import type { MetricSample } from "../types";

interface ChartConfig {
  metric: string;
  label: string;
  color: string;
  unit: string;
  /** Optional horizontal reference line (e.g. -70 dBm threshold). */
  threshold?: number;
  thresholdLabel?: string;
}

const CHARTS: ChartConfig[] = [
  {
    metric: "link.rssi_dbm",
    label: "Signal strength (RSSI)",
    color: "#818cf8",
    unit: "dBm",
    threshold: -70,
    thresholdLabel: "Weak (-70)",
  },
  {
    metric: "reach.gateway_ms",
    label: "Gateway latency",
    color: "#34d399",
    unit: "ms",
    threshold: 80,
    thresholdLabel: "High (80ms)",
  },
  {
    metric: "reach.loss_pct",
    label: "Packet loss",
    color: "#f87171",
    unit: "%",
    threshold: 2,
    thresholdLabel: "2%",
  },
];

function Sparkline({ config }: { config: ChartConfig }) {
  const [data, setData] = useState<MetricSample[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    invoke<MetricSample[]>("get_metric_history", {
      metric: config.metric,
      limit: 30,
    })
      .then((s) => setData(s))
      .catch(() => setData([]))
      .finally(() => setLoading(false));
  }, [config.metric]);

  const chartData = data.map((s) => ({
    value: +s.value.toFixed(1),
    time: new Date(s.sampled_at).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    }),
  }));

  const latest = data.length > 0 ? data[data.length - 1].value : undefined;

  return (
    <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-4">
      <div className="mb-2 flex items-baseline justify-between">
        <span className="text-xs font-semibold uppercase tracking-wide text-[var(--color-muted)]">
          {config.label}
        </span>
        {latest != null && (
          <span className="text-sm font-mono" style={{ color: config.color }}>
            {latest.toFixed(1)} {config.unit}
          </span>
        )}
      </div>

      {loading ? (
        <div className="flex h-20 items-center justify-center text-xs text-[var(--color-muted)]">
          Loading…
        </div>
      ) : chartData.length < 2 ? (
        <div className="flex h-20 items-center justify-center text-xs text-[var(--color-muted)]">
          Not enough history yet — run a few scans.
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={80}>
          <LineChart data={chartData} margin={{ top: 4, right: 4, left: -30, bottom: 0 }}>
            <XAxis dataKey="time" tick={{ fontSize: 9, fill: "#64748b" }} interval="preserveStartEnd" />
            <YAxis tick={{ fontSize: 9, fill: "#64748b" }} />
            <Tooltip
              contentStyle={{
                background: "var(--color-panel-2)",
                border: "1px solid var(--color-border)",
                borderRadius: 8,
                fontSize: 12,
              }}
              formatter={(v) => [`${Number(v).toFixed(1)} ${config.unit}`, config.label]}
            />
            {config.threshold != null && (
              <ReferenceLine
                y={config.threshold}
                stroke="#ef4444"
                strokeDasharray="4 2"
                label={{
                  value: config.thresholdLabel,
                  fill: "#ef4444",
                  fontSize: 9,
                  position: "insideTopRight",
                }}
              />
            )}
            <Line
              type="monotone"
              dataKey="value"
              stroke={config.color}
              dot={false}
              strokeWidth={2}
              isAnimationActive={false}
            />
          </LineChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}

export function MetricCharts() {
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
      {CHARTS.map((c) => (
        <Sparkline key={c.metric} config={c} />
      ))}
    </div>
  );
}
