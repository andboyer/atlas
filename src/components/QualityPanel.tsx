/**
 * QualityPanel — bufferbloat / responsiveness display (macOS networkQuality).
 *
 * Visible in all modes. Shows RPM (round-trips per minute), throughput, and
 * idle latency. Color-codes the responsiveness as a quick green/amber/red.
 *
 * Empty state branches:
 *   • non-macOS         → "not supported on this platform" explainer
 *   • macOS, no result  → "didn't finish this scan" + Run Test button
 *   • macOS, result     → metrics grid + interpretation
 */
import { useState } from "react";
import { Gauge, Loader2, Play } from "lucide-react";
import { invoke } from "@tauri-apps/api/core";
import type { QualityStats } from "../types";

interface Props {
  quality: QualityStats | null | undefined;
}

function rpmColor(rpm: number | null): string {
  if (rpm == null) return "text-[var(--color-muted)]";
  if (rpm >= 450) return "text-emerald-400";
  if (rpm >= 100) return "text-amber-400";
  return "text-rose-400";
}

function rpmInterpretation(rpm: number | null): string {
  if (rpm == null) return "—";
  if (rpm >= 450) return "Excellent — minimal bufferbloat";
  if (rpm >= 100) return "Moderate — noticeable on video calls";
  return "Poor — heavy bufferbloat, expect lag spikes";
}

// Cheap UA sniff — macOS Tauri webview always reports "Macintosh" / "Mac OS X".
function isMac(): boolean {
  return typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.userAgent);
}

const BUFFERBLOAT_EXPLAINER =
  "Bufferbloat is when routers and modems queue too many packets under load, " +
  "spiking latency for everything else even when bandwidth is fine. It's the " +
  "reason a Zoom call can stutter while a download is running.";

export default function QualityPanel({ quality }: Props) {
  const [override, setOverride] = useState<QualityStats | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const effective = override ?? quality ?? null;

  async function runManual() {
    setRunning(true);
    setError(null);
    try {
      const result = await invoke<QualityStats>("run_quality_test");
      setOverride(result);
    } catch (e) {
      // Backend returns a real reason string in the Err arm — show it.
      setError(typeof e === "string" ? e : String(e));
    } finally {
      setRunning(false);
    }
  }

  // ── Empty state ────────────────────────────────────────────────────────────
  if (!effective) {
    const mac = isMac();
    return (
      <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5">
        <div className="flex items-center gap-2 text-sm font-semibold">
          <Gauge className="h-4 w-4 text-[var(--color-accent)]" />
          Bufferbloat &amp; responsiveness
        </div>
        <p className="mt-2 text-xs text-[var(--color-muted)]">
          {BUFFERBLOAT_EXPLAINER}
        </p>
        <p className="mt-2 text-xs text-[var(--color-muted)]">
          {mac ? (
            <>
              The test isn&apos;t run automatically &mdash; it uses
              Apple&apos;s built-in <code>networkQuality</code> tool and
              saturates your connection for about 40&ndash;50 seconds. Click
              below when you have a moment.
            </>
          ) : (
            <>
              Bufferbloat measurement requires macOS 12 or later (it shells out
              to Apple&apos;s <code>networkQuality</code> CLI). No equivalent
              tool ships on Windows or Linux yet.
            </>
          )}
        </p>
        {mac && (
          <div className="mt-3 flex items-center gap-2">
            <button
              type="button"
              onClick={runManual}
              disabled={running}
              className="inline-flex items-center gap-1.5 rounded-md border border-[var(--color-border)] bg-[var(--color-panel-2)] px-3 py-1.5 text-xs font-medium hover:bg-[var(--color-panel-3)] disabled:cursor-not-allowed disabled:opacity-50"
            >
              {running ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  Measuring… (~45 s)
                </>
              ) : (
                <>
                  <Play className="h-3.5 w-3.5" />
                  Run bufferbloat test
                </>
              )}
            </button>
            {error && <span className="text-xs text-rose-400">{error}</span>}
          </div>
        )}
      </div>
    );
  }

  // ── Result state ───────────────────────────────────────────────────────────
  const rpm = effective.responsiveness_rpm;
  const dl = effective.dl_throughput_mbps;
  const ul = effective.ul_throughput_mbps;
  const idle = effective.idle_latency_ms;

  return (
    <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5">
      <div className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm font-semibold">
          <Gauge className="h-4 w-4 text-[var(--color-accent)]" />
          Bufferbloat &amp; responsiveness
        </div>
        <div className="flex items-center gap-2">
          {effective.responsiveness_label && (
            <span className="rounded-full bg-[var(--color-panel-2)] px-2 py-0.5 text-xs text-[var(--color-muted)]">
              {effective.responsiveness_label}
            </span>
          )}
          {isMac() && (
            <button
              type="button"
              onClick={runManual}
              disabled={running}
              title="Re-run the bufferbloat test now"
              className="inline-flex items-center gap-1 rounded-md border border-[var(--color-border)] bg-[var(--color-panel-2)] px-2 py-0.5 text-xs hover:bg-[var(--color-panel-3)] disabled:cursor-not-allowed disabled:opacity-50"
            >
              {running ? (
                <Loader2 className="h-3 w-3 animate-spin" />
              ) : (
                <Play className="h-3 w-3" />
              )}
              <span>{running ? "Running…" : "Re-test"}</span>
            </button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <Stat
          label="Responsiveness"
          value={rpm != null ? `${rpm}` : "—"}
          unit="RPM"
          valueClass={rpmColor(rpm ?? null)}
        />
        <Stat
          label="Idle latency"
          value={idle != null ? idle.toFixed(0) : "—"}
          unit="ms"
        />
        <Stat
          label="Download"
          value={dl != null ? dl.toFixed(0) : "—"}
          unit="Mbps"
        />
        <Stat
          label="Upload"
          value={ul != null ? ul.toFixed(0) : "—"}
          unit="Mbps"
        />
      </div>

      <p className="mt-3 text-xs text-[var(--color-muted)]">
        {rpmInterpretation(rpm ?? null)}
      </p>
      {error && <p className="mt-2 text-xs text-rose-400">{error}</p>}
    </div>
  );
}

function Stat({
  label,
  value,
  unit,
  valueClass,
}: {
  label: string;
  value: string;
  unit: string;
  valueClass?: string;
}) {
  return (
    <div>
      <div className="text-xs text-[var(--color-muted)]">{label}</div>
      <div className="mt-0.5 flex items-baseline gap-1">
        <span className={`text-xl font-semibold ${valueClass ?? ""}`}>{value}</span>
        <span className="text-xs text-[var(--color-muted)]">{unit}</span>
      </div>
    </div>
  );
}
