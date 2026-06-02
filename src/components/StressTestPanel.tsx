import { useEffect, useState } from "react";
import { Play, CheckCircle2, XCircle, Loader2, ChevronDown, ChevronRight } from "lucide-react";
import { useApp } from "../store";
import type { StressTestResult } from "../types";

function fmtMs(v: number | null): string {
  if (v == null) return "—";
  if (v < 10) return v.toFixed(1) + " ms";
  return Math.round(v) + " ms";
}

function fmtPct(v: number): string {
  return v.toFixed(0) + "%";
}

function ResultCard({ r }: { r: StressTestResult }) {
  const [open, setOpen] = useState(false);
  const StatusIcon = r.success ? CheckCircle2 : XCircle;
  const tone = r.success ? "text-emerald-300" : "text-rose-300";
  const ring = r.success
    ? "border-emerald-500/40 bg-emerald-500/5"
    : "border-rose-500/40 bg-rose-500/5";

  return (
    <article className={`rounded-xl border ${ring} p-3`}>
      <header
        className="flex cursor-pointer items-start justify-between gap-3"
        onClick={() => setOpen(!open)}
      >
        <div className="flex items-start gap-2">
          <StatusIcon className={`mt-0.5 h-4 w-4 ${tone}`} />
          <div>
            <div className="flex items-center gap-2">
              <h4 className="text-sm font-semibold text-[var(--color-text)]">
                {r.label}
              </h4>
              <span className="text-[10px] uppercase tracking-wider text-slate-500">
                {(r.duration_ms / 1000).toFixed(1)}s
              </span>
            </div>
            <p className={`mt-0.5 text-xs ${tone}`}>{r.headline}</p>
          </div>
        </div>
        {open ? (
          <ChevronDown className="h-4 w-4 text-slate-500" />
        ) : (
          <ChevronRight className="h-4 w-4 text-slate-500" />
        )}
      </header>

      <div className="mt-2 grid grid-cols-3 gap-2 text-xs text-slate-400 sm:grid-cols-6">
        <div>
          <div className="text-[10px] uppercase tracking-wider text-slate-500">
            attempts
          </div>
          <div className="tabular-nums text-slate-200">{r.stats.attempted}</div>
        </div>
        <div>
          <div className="text-[10px] uppercase tracking-wider text-slate-500">
            loss
          </div>
          <div className="tabular-nums text-slate-200">{fmtPct(r.stats.loss_pct)}</div>
        </div>
        <div>
          <div className="text-[10px] uppercase tracking-wider text-slate-500">
            avg
          </div>
          <div className="tabular-nums text-slate-200">{fmtMs(r.stats.avg_ms)}</div>
        </div>
        <div>
          <div className="text-[10px] uppercase tracking-wider text-slate-500">
            p95
          </div>
          <div className="tabular-nums text-slate-200">{fmtMs(r.stats.p95_ms)}</div>
        </div>
        <div>
          <div className="text-[10px] uppercase tracking-wider text-slate-500">
            max
          </div>
          <div className="tabular-nums text-slate-200">{fmtMs(r.stats.max_ms)}</div>
        </div>
        <div>
          <div className="text-[10px] uppercase tracking-wider text-slate-500">
            jitter
          </div>
          <div className="tabular-nums text-slate-200">{fmtMs(r.stats.jitter_ms)}</div>
        </div>
      </div>

      {open && (
        <div className="mt-3 space-y-2">
          <p className="text-xs text-slate-400">{r.details}</p>
          <div className="max-h-52 overflow-auto rounded-lg border border-[var(--color-border)] bg-black/30">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-[var(--color-panel)] text-[10px] uppercase tracking-wider text-slate-500">
                <tr>
                  <th className="px-2 py-1 text-left">+ms</th>
                  <th className="px-2 py-1 text-left">target</th>
                  <th className="px-2 py-1 text-right">latency</th>
                  <th className="px-2 py-1 text-right">ok</th>
                </tr>
              </thead>
              <tbody>
                {r.samples.map((s, i) => (
                  <tr key={i} className="border-t border-[var(--color-border)]/50">
                    <td className="px-2 py-1 tabular-nums text-slate-400">{s.offset_ms}</td>
                    <td className="px-2 py-1 font-mono text-slate-300">{s.label}</td>
                    <td className="px-2 py-1 text-right tabular-nums text-slate-300">
                      {fmtMs(s.latency_ms)}
                    </td>
                    <td className="px-2 py-1 text-right">
                      {s.success ? (
                        <span className="text-emerald-400">✓</span>
                      ) : (
                        <span className="text-rose-400">✗</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </article>
  );
}

/**
 * Active stress-test panel (Play B). Lists the available tests, lets the
 * user run one at a time, shows live progress via `stress:tick`, and pins
 * historical results below.
 */
export function StressTestPanel() {
  const available = useApp((s) => s.availableStressTests);
  const load = useApp((s) => s.loadStressTestList);
  const run = useApp((s) => s.runStressTest);
  const running = useApp((s) => s.runningStressKind);
  const results = useApp((s) => s.stressResults);
  const liveSamples = useApp((s) => s.liveStressSamples);

  useEffect(() => {
    if (available.length === 0) load();
  }, [available.length, load]);

  return (
    <section>
      <div className="mb-3 flex items-end justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold uppercase tracking-wider text-[var(--color-muted)]">
            Active stress tests
          </h2>
          <p className="mt-0.5 text-xs text-slate-500">
            Inject load to surface intermittent problems that passive sampling
            won't catch.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        {available.length === 0 ? (
          <div className="col-span-full rounded-xl border border-dashed border-[var(--color-border)] bg-[var(--color-panel)]/60 px-4 py-6 text-center text-xs text-slate-500">
            Loading tests…
          </div>
        ) : (
          available.map((d) => {
            const isRunning = running === d.kind;
            const disabled = running != null;
            return (
              <button
                key={d.kind}
                onClick={() => run(d.kind)}
                disabled={disabled}
                className="group flex flex-col items-start gap-2 rounded-xl border border-[var(--color-border)] bg-[var(--color-panel)] p-3 text-left transition-colors hover:border-indigo-500/40 hover:bg-indigo-500/5 disabled:cursor-not-allowed disabled:opacity-50"
              >
                <div className="flex w-full items-center justify-between">
                  <span className="text-sm font-semibold text-[var(--color-text)]">
                    {d.label}
                  </span>
                  {isRunning ? (
                    <Loader2 className="h-4 w-4 animate-spin text-indigo-300" />
                  ) : (
                    <Play className="h-4 w-4 text-slate-500 group-hover:text-indigo-300" />
                  )}
                </div>
                <p className="text-xs text-slate-400">{d.description}</p>
                {isRunning && (
                  <div className="w-full">
                    <div className="text-[10px] uppercase tracking-wider text-indigo-300">
                      {liveSamples.length} samples
                    </div>
                  </div>
                )}
              </button>
            );
          })
        )}
      </div>

      {results.length > 0 && (
        <div className="mt-4 space-y-2">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500">
            Recent results
          </h3>
          {[...results].reverse().slice(0, 5).map((r) => (
            <ResultCard key={r.id} r={r} />
          ))}
        </div>
      )}
    </section>
  );
}
