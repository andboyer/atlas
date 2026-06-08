import { useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  ScrollText,
  Trash2,
  RefreshCw,
  Filter,
  ShieldAlert,
  ShieldCheck,
  Shield,
  Hash,
} from "lucide-react";

interface AuditEntry {
  ts: string;
  runbook_id: string;
  run_id: string;
  host_id: string;
  skill: string;
  command_id: string;
  rendered: string;
  risk: "read" | "mutate" | "dangerous";
  stdout_sha256: string;
  stdout_bytes: number;
  exit: number | null;
  duration_ms: number;
  approval: string;
  model: string;
}

const RISK_META: Record<
  AuditEntry["risk"],
  { label: string; tone: string; icon: typeof Shield }
> = {
  read: {
    label: "Read",
    tone: "border-emerald-500/40 bg-emerald-500/10 text-emerald-200",
    icon: ShieldCheck,
  },
  mutate: {
    label: "Mutate",
    tone: "border-amber-500/40 bg-amber-500/10 text-amber-200",
    icon: Shield,
  },
  dangerous: {
    label: "Dangerous",
    tone: "border-rose-500/40 bg-rose-500/10 text-rose-200",
    icon: ShieldAlert,
  },
};

export function AuditLogPanel() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filterRisk, setFilterRisk] = useState<AuditEntry["risk"] | "all">(
    "all",
  );
  const [filterHost, setFilterHost] = useState<string>("");
  const [limit, setLimit] = useState(200);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const rows = await invoke<AuditEntry[]>("list_audit", { lastN: limit });
      setEntries(rows);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [limit]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const handleClear = async () => {
    if (
      !confirm(
        "Permanently delete the audit log? This action is recorded only in memory.",
      )
    )
      return;
    try {
      await invoke<void>("clear_audit");
      await refresh();
    } catch (e) {
      setError(String(e));
    }
  };

  const filtered = useMemo(() => {
    return entries.filter((e) => {
      if (filterRisk !== "all" && e.risk !== filterRisk) return false;
      if (
        filterHost &&
        !e.host_id.toLowerCase().includes(filterHost.toLowerCase())
      )
        return false;
      return true;
    });
  }, [entries, filterRisk, filterHost]);

  return (
    <section className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wide">
            <ScrollText className="h-4 w-4 text-[var(--color-accent)]" />
            Device audit log
          </h3>
          <p className="mt-1 text-xs text-[var(--color-muted)]">
            Every <code>device.exec</code> invocation is recorded with the
            rendered command, an SHA-256 of the stdout, and the operator's
            approval verdict. Stored at{" "}
            <code>&lt;app-data&gt;/device/audit.jsonl</code>.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={refresh}
            disabled={loading}
            className="inline-flex items-center gap-1 rounded border border-[var(--color-border)] px-2 py-1 text-[11px] hover:border-[var(--color-accent)]/40 disabled:opacity-50"
          >
            <RefreshCw className={`h-3 w-3 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          <button
            type="button"
            onClick={handleClear}
            className="inline-flex items-center gap-1 rounded border border-rose-500/40 px-2 py-1 text-[11px] text-rose-300 hover:bg-rose-500/15"
          >
            <Trash2 className="h-3 w-3" />
            Clear
          </button>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <span className="inline-flex items-center gap-1 text-[11px] text-[var(--color-muted)]">
          <Filter className="h-3 w-3" />
          Filter:
        </span>
        <select
          value={filterRisk}
          onChange={(e) =>
            setFilterRisk(e.target.value as AuditEntry["risk"] | "all")
          }
          className="rounded border border-[var(--color-border)] bg-black/30 px-2 py-1 text-[11px]"
        >
          <option value="all">All risks</option>
          <option value="read">Read</option>
          <option value="mutate">Mutate</option>
          <option value="dangerous">Dangerous</option>
        </select>
        <input
          value={filterHost}
          onChange={(e) => setFilterHost(e.target.value)}
          placeholder="host id contains…"
          className="rounded border border-[var(--color-border)] bg-black/30 px-2 py-1 text-[11px]"
        />
        <label className="ml-auto flex items-center gap-1 text-[11px] text-[var(--color-muted)]">
          Last
          <input
            type="number"
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value) || 200)}
            className="w-16 rounded border border-[var(--color-border)] bg-black/30 px-1 py-0.5 text-right text-[11px]"
          />
          entries
        </label>
      </div>

      {error && (
        <div className="rounded border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-200">
          {error}
        </div>
      )}

      {filtered.length === 0 ? (
        <div className="rounded-lg border border-dashed border-[var(--color-border)] bg-[var(--color-panel)]/50 px-4 py-6 text-center text-sm text-[var(--color-muted)]">
          No audit entries match the current filters.
        </div>
      ) : (
        <div className="overflow-hidden rounded-lg border border-[var(--color-border)]">
          <table className="w-full text-xs">
            <thead className="bg-[var(--color-panel)] text-[10px] uppercase tracking-wide text-[var(--color-muted)]">
              <tr>
                <th className="px-2 py-2 text-left">When</th>
                <th className="px-2 py-2 text-left">Risk</th>
                <th className="px-2 py-2 text-left">Host</th>
                <th className="px-2 py-2 text-left">Skill</th>
                <th className="px-2 py-2 text-left">Command</th>
                <th className="px-2 py-2 text-left">Rendered</th>
                <th className="px-2 py-2 text-right">Bytes</th>
                <th className="px-2 py-2 text-right">ms</th>
                <th className="px-2 py-2 text-left">Approval</th>
                <th className="px-2 py-2 text-left">SHA256</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((e, i) => {
                const meta = RISK_META[e.risk];
                const Icon = meta.icon;
                return (
                  <tr
                    key={`${e.run_id}-${i}`}
                    className="border-t border-[var(--color-border)] align-top hover:bg-[var(--color-panel)]/50"
                  >
                    <td className="px-2 py-1.5 font-mono text-[10px] text-[var(--color-muted)]">
                      {e.ts.replace("T", " ").replace(/\..*$/, "")}
                    </td>
                    <td className="px-2 py-1.5">
                      <span
                        className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] uppercase ${meta.tone}`}
                      >
                        <Icon className="h-3 w-3" />
                        {meta.label}
                      </span>
                    </td>
                    <td className="px-2 py-1.5">
                      <code className="text-[11px]">{e.host_id}</code>
                    </td>
                    <td className="px-2 py-1.5">
                      <code className="text-[10px] text-[var(--color-muted)]">
                        {e.skill}
                      </code>
                    </td>
                    <td className="px-2 py-1.5">
                      <code className="text-[11px]">{e.command_id}</code>
                    </td>
                    <td
                      className="max-w-[280px] truncate px-2 py-1.5 font-mono text-[10px] text-slate-300"
                      title={e.rendered}
                    >
                      {e.rendered}
                    </td>
                    <td className="px-2 py-1.5 text-right text-[10px] text-[var(--color-muted)]">
                      {e.stdout_bytes}
                    </td>
                    <td className="px-2 py-1.5 text-right text-[10px] text-[var(--color-muted)]">
                      {e.duration_ms}
                    </td>
                    <td className="px-2 py-1.5">
                      <code className="text-[10px]">{e.approval}</code>
                    </td>
                    <td className="px-2 py-1.5">
                      <code
                        className="inline-flex items-center gap-1 text-[10px] text-[var(--color-muted)]"
                        title={e.stdout_sha256}
                      >
                        <Hash className="h-2.5 w-2.5" />
                        {e.stdout_sha256.slice(0, 8)}…
                      </code>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

export default AuditLogPanel;
