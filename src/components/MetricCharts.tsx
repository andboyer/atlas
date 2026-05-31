import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from "recharts";
import type { DeviceEvent, MetricSample } from "../types";

interface ChartConfig {
  metric: string;
  label: string;
  color: string;
  unit: string;
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

function eventStroke(type: string): string {
  if (type === "offline") return "#f87171";
  if (type === "online") return "#34d399";
  return "#818cf8";
}

function Sparkline({ config }: { config: ChartConfig }) {
  const [data, setData] = useState<MetricSample[]>([]);
  const [events, setEvents] = useState<DeviceEvent[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchData = () =>
    invoke<MetricSample[]>("get_metric_history", {
      metric: config.metric,
      limit: 30,
    })
      .then((s) => setData(s))
      .catch(() => setData([]))
      .finally(() => setLoading(false));

  const fetchEvents = () =>
    invoke<DeviceEvent[]>("get_recent_device_events", { limit: 50 })
      .then((evts) => setEvents(evts))
      .catch(() => setEvents([]));

  useEffect(() => {
    fetchData();
    fetchEvents();
    let unlisten: (() => void) | undefined;
    listen("scan:completed", () => {
      void fetchData();
      void fetchEvents();
    }).then((fn) => {
      unlisten = fn;
    });
    return () => { unlisten?.(); };
  }, [config.metric]);

  const chartData = data.map((s) => ({
    value: +s.value.toFixed(1),
    time: new Date(s.sampled_at).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    }),
    isoTime: s.sampled_at,
  }));

  const latest = data.length > 0 ? data[data.length - 1].value : undefined;

  // Events that fall within the chart time window.
  const chartStart = data.length > 0 ? new Date(data[0].sampled_at).getTime() : 0;
  const chartEnd = data.length > 0 ? new Date(data[data.length - 1].sampled_at).getTime() : 0;
  const overlayEvents = events.filter((e) => {
    const t = new Date(e.occurred_at).getTime();
    return t >= chartStart && t <= chartEnd;
  });

  // Map each event to the nearest chart x-axis tick.
  const overlayLines = overlayEvents.map((e) => {
    const t = new Date(e.occurred_at).getTime();
    let nearest = chartData[0];
    for (const d of chartData) {
      if (
        Math.abs(new Date(d.isoTime).getTime() - t) <
        Math.abs(new Date(nearest.isoTime).getTime() - t)
      ) {
        nearest = d;
      }
    }
    return { time: nearest.time, type: e.event_type };
  });

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
            <XAxis
              dataKey="time"
              tick={{ fontSize: 9, fill: "#64748b" }}
              interval="preserveStartEnd"
            />
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
            {overlayLines.map((ol, i) => (
              <ReferenceLine
                key={i}
                x={ol.time}
                stroke={eventStroke(ol.type)}
                strokeDasharray="3 2"
                strokeWidth={1.5}
                label={{
                  value: ol.type === "offline" ? "✕" : "↑",
                  fill: eventStroke(ol.type),
                  fontSize: 9,
                  position: "insideTopLeft",
                }}
              />
            ))}
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
