/**
 * ChannelMap — bar chart of nearby AP counts per Wi-Fi channel.
 *
 * Shown in Admin mode. Helps the user pick the least-congested channel.
 * Non-overlapping 2.4 GHz channels (1, 6, 11) are highlighted in teal;
 * the device's own channel is highlighted in amber.
 */
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell,
  ResponsiveContainer,
  ReferenceLine,
} from "recharts";
import type { NearbyAp } from "../types";

interface Props {
  nearbyAps: NearbyAp[];
  ownChannel: number | null;
}

interface ChannelBucket {
  channel: number;
  count: number;
  band: "2.4" | "5";
}

const NON_OVERLAPPING_24 = new Set([1, 6, 11]);

function buildBuckets(aps: NearbyAp[]): ChannelBucket[] {
  const counts: Record<number, { count: number; band: "2.4" | "5" }> = {};
  for (const ap of aps) {
    if (ap.channel == null) continue;
    const band: "2.4" | "5" = ap.band === "2.4" ? "2.4" : "5";
    if (!counts[ap.channel]) counts[ap.channel] = { count: 0, band };
    counts[ap.channel].count++;
  }
  return Object.entries(counts)
    .map(([ch, v]) => ({ channel: Number(ch), count: v.count, band: v.band }))
    .sort((a, b) => a.channel - b.channel);
}

function barColor(bucket: ChannelBucket, ownChannel: number | null): string {
  if (bucket.channel === ownChannel) return "#f59e0b"; // amber — own channel
  if (bucket.band === "2.4" && NON_OVERLAPPING_24.has(bucket.channel))
    return "#0d9488"; // teal — non-overlapping 2.4 GHz
  return "#6366f1"; // indigo — all others
}

export default function ChannelMap({ nearbyAps, ownChannel }: Props) {
  const buckets = buildBuckets(nearbyAps);

  if (buckets.length === 0) {
    return (
      <div className="rounded-xl bg-white dark:bg-gray-800 p-4 shadow-sm">
        <h3 className="font-semibold text-sm text-gray-700 dark:text-gray-300 mb-2">
          Channel Map
        </h3>
        <p className="text-xs text-gray-500 dark:text-gray-400">
          No nearby APs detected — channel scan data is not available on all
          platforms without elevated permissions.
        </p>
      </div>
    );
  }

  const maxCount = Math.max(...buckets.map((b) => b.count), 1);

  return (
    <div className="rounded-xl bg-white dark:bg-gray-800 p-4 shadow-sm">
      <h3 className="font-semibold text-sm text-gray-700 dark:text-gray-300 mb-1">
        Channel Map
      </h3>
      <p className="text-xs text-gray-500 dark:text-gray-400 mb-3">
        Nearby APs per channel. Fewer is better.{" "}
        <span className="text-teal-600 dark:text-teal-400 font-medium">
          Teal = non-overlapping 2.4 GHz (1, 6, 11)
        </span>
        {ownChannel != null && (
          <>
            {" · "}
            <span className="text-amber-500 font-medium">
              Amber = your channel ({ownChannel})
            </span>
          </>
        )}
      </p>
      <ResponsiveContainer width="100%" height={160}>
        <BarChart
          data={buckets}
          margin={{ top: 4, right: 8, left: -16, bottom: 0 }}
        >
          <XAxis
            dataKey="channel"
            tick={{ fontSize: 10 }}
            tickLine={false}
            axisLine={false}
          />
          <YAxis
            allowDecimals={false}
            domain={[0, maxCount + 1]}
            tick={{ fontSize: 10 }}
            tickLine={false}
            axisLine={false}
          />
          <Tooltip
            formatter={(value) => {
              const n = typeof value === "number" ? value : 0;
              return [`${n} AP${n !== 1 ? "s" : ""}`, "Count"] as [string, string];
            }}
            labelFormatter={(label) => `Channel ${label}`}
            contentStyle={{ fontSize: 12 }}
          />
          {ownChannel != null && (
            <ReferenceLine
              x={ownChannel}
              stroke="#f59e0b"
              strokeDasharray="4 2"
              strokeWidth={2}
            />
          )}
          <Bar dataKey="count" radius={[3, 3, 0, 0]}>
            {buckets.map((bucket) => (
              <Cell
                key={bucket.channel}
                fill={barColor(bucket, ownChannel)}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
