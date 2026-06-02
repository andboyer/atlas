/**
 * ChannelMap — frequency-axis spectrum view of nearby APs.
 *
 * Each AP is rendered as a rounded trapezoid centered on its operating
 * frequency, with the trapezoid width matching the channel width (20/40/80/160
 * MHz) and the peak height proportional to RSSI. This is the classic
 * "WiFi Analyzer" view and makes channel overlap visible at a glance.
 *
 * Sub-tabs for 2.4 / 5 / 6 GHz (only shown when APs exist on that band).
 */
import { useMemo, useState } from "react";
import type { InterferenceReport, NearbyAp } from "../types";

interface Props {
  nearbyAps: NearbyAp[];
  ownChannel: number | null;
  ownBssid?: string | null;
  interference?: InterferenceReport | null;
}

type BandId = "2.4" | "5" | "6";

interface BandConfig {
  id: BandId;
  label: string;
  /** [minMHz, maxMHz] x-axis range */
  range: [number, number];
  /** Channel numbers to draw as ticks on the x-axis */
  ticks: number[];
  /** Channel-number → frequency-MHz */
  freq: (ch: number) => number;
  /** Non-overlapping channels to highlight on x-axis */
  preferred?: Set<number>;
}

const BAND_CONFIG: Record<BandId, BandConfig> = {
  "2.4": {
    id: "2.4",
    label: "2.4 GHz",
    range: [2400, 2495],
    ticks: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14],
    freq: (ch) => (ch === 14 ? 2484 : 2407 + ch * 5),
    preferred: new Set([1, 6, 11]),
  },
  "5": {
    id: "5",
    label: "5 GHz",
    range: [5160, 5890],
    ticks: [36, 40, 44, 48, 52, 56, 60, 64, 100, 116, 132, 149, 157, 165, 173],
    freq: (ch) => 5000 + ch * 5,
  },
  "6": {
    id: "6",
    label: "6 GHz",
    range: [5945, 7125],
    ticks: [1, 17, 33, 49, 65, 81, 97, 113, 129, 145, 161, 177, 193, 209, 225],
    freq: (ch) => 5950 + ch * 5,
  },
};

const RSSI_MIN = -100;
const RSSI_MAX = -30;

function defaultWidth(band: BandId): number {
  if (band === "2.4") return 20;
  return 80;
}

function hueFromKey(key: string): number {
  let h = 0;
  for (let i = 0; i < key.length; i++) h = (h * 31 + key.charCodeAt(i)) >>> 0;
  return h % 360;
}

function normalizeBand(band: string | null | undefined): BandId | null {
  if (band == null) return null;
  if (band.startsWith("2")) return "2.4";
  if (band.startsWith("6")) return "6";
  if (band.startsWith("5")) return "5";
  return null;
}

export default function ChannelMap({
  nearbyAps,
  ownChannel,
  ownBssid,
  interference,
}: Props) {
  const presentBands = useMemo<BandId[]>(() => {
    const set = new Set<BandId>();
    for (const ap of nearbyAps) {
      const b = normalizeBand(ap.band);
      if (b) set.add(b);
    }
    const ordered: BandId[] = [];
    for (const b of ["2.4", "5", "6"] as BandId[]) {
      if (set.has(b)) ordered.push(b);
    }
    return ordered;
  }, [nearbyAps]);

  const [activeBand, setActiveBand] = useState<BandId>(
    presentBands[0] ?? "2.4"
  );
  const effectiveBand = presentBands.includes(activeBand)
    ? activeBand
    : presentBands[0] ?? "2.4";

  const rec24 = interference?.recommended_24 ?? null;
  const rec5 = interference?.recommended_5 ?? null;
  const curScore = interference?.current_channel_score ?? null;

  const stats = useMemo(() => {
    const total = nearbyAps.length;
    const byBand: Record<BandId, number> = { "2.4": 0, "5": 0, "6": 0 };
    const ssids = new Set<string>();
    for (const ap of nearbyAps) {
      const b = normalizeBand(ap.band);
      if (b) byBand[b]++;
      if (ap.ssid) ssids.add(ap.ssid);
    }
    return { total, byBand, uniqueSsids: ssids.size };
  }, [nearbyAps]);

  return (
    <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold">Spectrum map</h3>
          <p className="mt-0.5 text-xs text-[var(--color-muted)]">
            {stats.total} AP{stats.total !== 1 ? "s" : ""} detected across{" "}
            {stats.uniqueSsids} unique SSID
            {stats.uniqueSsids !== 1 ? "s" : ""}.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-1.5 text-xs">
          {curScore != null && (
            <span className="rounded-full bg-[var(--color-panel-2)] px-2.5 py-1 text-[var(--color-muted)]">
              Current channel:{" "}
              <span className="font-semibold text-[var(--color-text)]">
                {curScore.toFixed(0)}/100
              </span>
            </span>
          )}
          {rec24 != null && (
            <span className="rounded-full border border-teal-500/40 bg-teal-500/10 px-2.5 py-1 text-teal-300">
              Best 2.4: <strong>ch {rec24}</strong>
            </span>
          )}
          {rec5 != null && (
            <span className="rounded-full border border-indigo-500/40 bg-indigo-500/10 px-2.5 py-1 text-indigo-300">
              Best 5: <strong>ch {rec5}</strong>
            </span>
          )}
        </div>
      </div>

      {presentBands.length === 0 ? (
        <p className="rounded-lg border border-dashed border-[var(--color-border)] p-6 text-center text-xs text-[var(--color-muted)]">
          No nearby APs detected — channel scan data is not available on all
          platforms without elevated permissions.
        </p>
      ) : (
        <>
          <div className="mb-3 flex items-center gap-2 text-xs">
            {presentBands.map((b) => (
              <button
                key={b}
                onClick={() => setActiveBand(b)}
                className={`rounded-full px-3 py-1 transition-colors ${
                  b === effectiveBand
                    ? "bg-[var(--color-accent)]/20 text-[var(--color-accent)]"
                    : "bg-[var(--color-panel-2)] text-[var(--color-muted)] hover:text-[var(--color-text)]"
                }`}
              >
                {BAND_CONFIG[b].label} · {stats.byBand[b]}
              </button>
            ))}
          </div>
          <SpectrumPlot
            band={BAND_CONFIG[effectiveBand]}
            aps={nearbyAps.filter(
              (ap) => normalizeBand(ap.band) === effectiveBand
            )}
            ownChannel={ownChannel}
            ownBssid={ownBssid ?? null}
          />
          <Legend />
        </>
      )}
    </div>
  );
}

interface PlotProps {
  band: BandConfig;
  aps: NearbyAp[];
  ownChannel: number | null;
  ownBssid: string | null;
}

function SpectrumPlot({ band, aps, ownChannel, ownBssid }: PlotProps) {
  const W = 1000;
  const H = 320;
  const PAD_L = 40;
  const PAD_R = 12;
  const PAD_T = 18;
  const PAD_B = 38;
  const plotW = W - PAD_L - PAD_R;
  const plotH = H - PAD_T - PAD_B;

  const [minF, maxF] = band.range;
  const xOfFreq = (f: number) =>
    PAD_L + ((f - minF) / (maxF - minF)) * plotW;
  const yOfRssi = (rssi: number) => {
    const clamped = Math.max(RSSI_MIN, Math.min(RSSI_MAX, rssi));
    const t = (clamped - RSSI_MIN) / (RSSI_MAX - RSSI_MIN);
    return PAD_T + (1 - t) * plotH;
  };
  const baselineY = PAD_T + plotH;

  // Strongest on top so weaker APs don't fully occlude them.
  const sortedAps = [...aps].sort(
    (a, b) => (a.rssi_dbm ?? RSSI_MIN) - (b.rssi_dbm ?? RSSI_MIN)
  );

  const yTicks: number[] = [];
  for (let r = RSSI_MIN; r <= RSSI_MAX; r += 10) yTicks.push(r);

  return (
    <div className="overflow-x-auto">
      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="block min-w-[640px] w-full"
        style={{ maxHeight: 360 }}
      >
        {yTicks.map((r) => {
          const y = yOfRssi(r);
          return (
            <g key={r}>
              <line
                x1={PAD_L}
                x2={W - PAD_R}
                y1={y}
                y2={y}
                stroke="var(--color-border)"
                strokeOpacity="0.4"
                strokeDasharray="2 4"
              />
              <text
                x={PAD_L - 6}
                y={y + 3}
                textAnchor="end"
                fontSize="9"
                fill="var(--color-muted)"
              >
                {r}
              </text>
            </g>
          );
        })}
        <text
          x={8}
          y={PAD_T - 6}
          fontSize="9"
          fill="var(--color-muted)"
          fontWeight="600"
        >
          dBm
        </text>

        {band.ticks.map((ch) => {
          const f = band.freq(ch);
          if (f < minF || f > maxF) return null;
          const x = xOfFreq(f);
          const preferred = band.preferred?.has(ch);
          const isOwn = ownChannel === ch;
          const tickColor = isOwn
            ? "var(--color-warn)"
            : preferred
              ? "var(--color-good)"
              : "var(--color-muted)";
          return (
            <g key={ch}>
              <line
                x1={x}
                x2={x}
                y1={baselineY}
                y2={baselineY + 5}
                stroke={tickColor}
                strokeWidth={isOwn ? 2 : 1}
              />
              <text
                x={x}
                y={baselineY + 16}
                textAnchor="middle"
                fontSize="9"
                fill={tickColor}
                fontWeight={isOwn ? 700 : 400}
              >
                {ch}
              </text>
            </g>
          );
        })}
        <text
          x={W - PAD_R}
          y={H - 4}
          textAnchor="end"
          fontSize="9"
          fill="var(--color-muted)"
        >
          channel
        </text>

        <line
          x1={PAD_L}
          x2={W - PAD_R}
          y1={baselineY}
          y2={baselineY}
          stroke="var(--color-border)"
        />

        {sortedAps.map((ap, idx) => {
          if (ap.channel == null) return null;
          const cf = band.freq(ap.channel);
          if (cf < minF || cf > maxF) return null;
          const width = ap.width_mhz ?? defaultWidth(band.id);
          const rssi = ap.rssi_dbm ?? RSSI_MIN;
          const xL = xOfFreq(cf - width / 2);
          const xR = xOfFreq(cf + width / 2);
          const xCenter = xOfFreq(cf);
          const yPeak = yOfRssi(rssi);

          const shoulder = (xR - xL) * 0.18;
          const path = `M ${xL.toFixed(1)} ${baselineY.toFixed(1)} C ${(xL + shoulder).toFixed(1)} ${baselineY.toFixed(1)}, ${(xL + shoulder).toFixed(1)} ${yPeak.toFixed(1)}, ${(xL + shoulder * 2).toFixed(1)} ${yPeak.toFixed(1)} L ${(xR - shoulder * 2).toFixed(1)} ${yPeak.toFixed(1)} C ${(xR - shoulder).toFixed(1)} ${yPeak.toFixed(1)}, ${(xR - shoulder).toFixed(1)} ${baselineY.toFixed(1)}, ${xR.toFixed(1)} ${baselineY.toFixed(1)} Z`;

          const key = ap.bssid ?? ap.ssid ?? `ap-${idx}`;
          const hue = hueFromKey(key);
          const isOwn =
            (ownBssid != null && ap.bssid === ownBssid) ||
            (ownBssid == null && ap.channel === ownChannel);
          const strokeColor = isOwn
            ? "var(--color-accent)"
            : `hsl(${hue} 70% 65%)`;
          const fillColor = `hsl(${hue} 70% 60% / 0.18)`;

          const ssidLabel = ap.ssid ?? "(hidden)";
          const labelText =
            ssidLabel.length > 18 ? `${ssidLabel.slice(0, 17)}…` : ssidLabel;

          return (
            <g key={`${key}-${idx}`}>
              <path
                d={path}
                fill={fillColor}
                stroke={strokeColor}
                strokeWidth={isOwn ? 2.5 : 1.25}
              />
              <circle
                cx={xCenter}
                cy={yPeak}
                r={isOwn ? 4 : 2.5}
                fill={strokeColor}
              />
              <text
                x={xCenter}
                y={yPeak - 6}
                textAnchor="middle"
                fontSize={isOwn ? 11 : 10}
                fontWeight={isOwn ? 700 : 500}
                fill="var(--color-text)"
                style={{
                  paintOrder: "stroke",
                  stroke: "var(--color-panel)",
                  strokeWidth: 3,
                }}
              >
                {labelText}
              </text>
              <title>
                {`${ssidLabel}\nch ${ap.channel} · ${ap.band ?? "?"} GHz · ${width} MHz wide\n${ap.rssi_dbm ?? "?"} dBm${ap.security ? ` · ${ap.security}` : ""}${ap.phy_mode ? ` · ${ap.phy_mode}` : ""}${ap.vendor ? ` · ${ap.vendor}` : ""}${ap.bssid ? `\n${ap.bssid}` : ""}`}
              </title>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

function Legend() {
  return (
    <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[10px] text-[var(--color-muted)]">
      <span className="flex items-center gap-1.5">
        <span className="inline-block h-2 w-2 rounded-full bg-[var(--color-accent)]" />
        Your AP
      </span>
      <span className="flex items-center gap-1.5">
        <span className="inline-block h-2 w-2 rounded-full bg-[var(--color-good)]" />
        Non-overlapping 2.4 GHz (1, 6, 11)
      </span>
      <span className="flex items-center gap-1.5">
        <span className="inline-block h-2 w-2 rounded-full bg-[var(--color-warn)]" />
        Your channel
      </span>
      <span>Width = channel width (MHz) · Peak height = RSSI (dBm)</span>
    </div>
  );
}
