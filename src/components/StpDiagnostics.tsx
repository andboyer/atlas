import { useEffect } from "react";
import { Cable, RefreshCw } from "lucide-react";
import { useApp } from "../store";
import { StpProbePanel } from "./AvDiagnostics";

/**
 * Standalone STP / L2-loop diagnostics tab. The STP probe lives on the same
 * `av.deep_probe.stp` result as the AV switch-readiness probes, but is given
 * its own destination so loop/spanning-tree investigations aren't buried
 * inside the AV multicast view.
 */
export function StpDiagnostics() {
  const av = useApp((s) => s.avDiagnostics);
  const loading = useApp((s) => s.avDiagnosticsLoading);
  const load = useApp((s) => s.loadAvDiagnostics);
  const runDeep = useApp((s) => s.runDeepProbe);
  const deepRunning = useApp((s) => s.deepProbeRunning);
  const deepError = useApp((s) => s.deepProbeError);

  // Ensure the deep-probe container exists (the STP result hangs off it).
  useEffect(() => {
    if (!av && !loading) void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const stp = av?.deep_probe?.stp ?? null;

  return (
    <div className="space-y-6">
      {/* ── Header ── */}
      <div className="atlas-card flex flex-col gap-4 p-5">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-[var(--color-accent)]">
              <Cable className="h-3.5 w-3.5" /> Spanning tree
            </div>
            <h2 className="mt-1 text-xl font-semibold tracking-tight">
              STP / L2 loop detection
            </h2>
            <p className="mt-1 text-sm leading-relaxed text-[var(--color-muted)]">
              Passively listens for spanning-tree BPDUs plus broadcast and
              duplicate-frame storms — the signatures of switching loops and an
              unstable spanning tree. Requires admin (raw L2 capture).
            </p>
          </div>
          <button
            onClick={() => void runDeep("stp-listen")}
            disabled={deepRunning}
            className="inline-flex items-center gap-2 rounded-lg bg-gradient-to-b from-[var(--color-accent)] to-[#b8893f] px-3.5 py-2 text-sm font-semibold text-[var(--atlas-navy,#0B1F3A)] shadow-[inset_0_1px_0_rgba(255,255,255,0.25),0_6px_14px_-8px_rgba(212,162,76,0.6)] transition-opacity hover:opacity-95 disabled:opacity-50"
          >
            <RefreshCw
              className={`h-4 w-4 ${deepRunning ? "animate-spin" : ""}`}
            />
            {deepRunning
              ? "Listening…"
              : stp
                ? "Re-run STP test"
                : "Run STP test"}
          </button>
        </div>
      </div>

      {deepError && (
        <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-sm text-rose-300">
          {deepError}
        </div>
      )}

      <StpProbePanel
        result={stp}
        running={deepRunning}
        onRun={() => void runDeep("stp-listen")}
      />
    </div>
  );
}

export default StpDiagnostics;
