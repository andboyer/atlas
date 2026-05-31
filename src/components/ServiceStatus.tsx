import { useApp } from "../store";

export function ServiceStatus() {
  const lastScan = useApp((s) => s.lastScan);
  const probes = lastScan?.service_reachability ?? [];

  if (probes.length === 0) {
    return (
      <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-6 text-sm text-[var(--color-muted)]">
        No services are being probed. Pick an industry profile in Settings, or
        add custom <span className="font-mono">host:port</span> targets, to monitor
        SaaS reachability (payment processors, voice APIs, collaboration tools).
      </div>
    );
  }

  const reachable = probes.filter((p) => p.reachable).length;
  const failing = probes.length - reachable;

  return (
    <div className="overflow-hidden rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)]">
      <div className="flex items-center justify-between border-b border-[var(--color-border)] px-5 py-3">
        <span className="text-sm text-[var(--color-muted)]">
          {reachable} / {probes.length} reachable
        </span>
        {failing > 0 && (
          <span className="rounded-full bg-rose-500/15 px-2.5 py-0.5 text-xs text-rose-300">
            {failing} failing
          </span>
        )}
      </div>
      <table className="w-full text-sm">
        <thead className="text-left text-xs uppercase tracking-wide text-[var(--color-muted)]">
          <tr>
            <th className="px-5 py-2 font-medium">Target</th>
            <th className="px-5 py-2 font-medium">Status</th>
            <th className="px-5 py-2 font-medium text-right">Latency</th>
          </tr>
        </thead>
        <tbody>
          {probes.map((p) => (
            <tr
              key={p.target}
              className="border-t border-[var(--color-border)] hover:bg-white/[0.02]"
            >
              <td className="px-5 py-2 font-mono text-xs">{p.target}</td>
              <td className="px-5 py-2">
                {p.reachable ? (
                  <span className="inline-flex items-center gap-1.5 text-emerald-300">
                    <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                    reachable
                  </span>
                ) : (
                  <span
                    className="inline-flex items-center gap-1.5 text-rose-300"
                    title={p.error ?? undefined}
                  >
                    <span className="h-1.5 w-1.5 rounded-full bg-rose-400" />
                    {p.error ?? "unreachable"}
                  </span>
                )}
              </td>
              <td className="px-5 py-2 text-right text-[var(--color-muted)]">
                {p.latency_ms != null ? `${Math.round(p.latency_ms)} ms` : "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
