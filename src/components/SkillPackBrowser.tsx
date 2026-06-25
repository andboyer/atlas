import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  BookOpen,
  ShieldCheck,
  Shield,
  ShieldAlert,
  ChevronDown,
  ChevronRight,
  Cable,
  Globe,
} from "lucide-react";

type Risk = "read" | "mutate" | "dangerous";
type TransportKind = "ssh" | "https" | "http";

interface ArgSpec {
  name: string;
  // serde-renamed from `type` on the wire.
  type: string;
  required: boolean;
  default: string | null;
}

interface CommandSpec {
  id: string;
  purpose: string;
  risk: Risk;
  template: string;
  method: string;
  body_template: string | null;
  args: ArgSpec[];
  parser: string | null;
}

interface LoginSpec {
  path: string;
  username_field: string | null;
  password_field: string | null;
  api_key_header: string | null;
}

interface SkillPack {
  id: string;
  name: string;
  transport: TransportKind;
  description: string;
  login: LoginSpec | null;
  commands: CommandSpec[];
}

const RISK_META: Record<
  Risk,
  { label: string; tone: string; Icon: typeof Shield }
> = {
  read: {
    label: "Read",
    tone: "border-emerald-500/40 bg-emerald-500/10 text-emerald-200",
    Icon: ShieldCheck,
  },
  mutate: {
    label: "Mutate",
    tone: "border-amber-500/40 bg-amber-500/10 text-amber-200",
    Icon: Shield,
  },
  dangerous: {
    label: "Dangerous",
    tone: "border-rose-500/40 bg-rose-500/10 text-rose-200",
    Icon: ShieldAlert,
  },
};

export function SkillPackBrowser() {
  const [packs, setPacks] = useState<SkillPack[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [filterRisk, setFilterRisk] = useState<Risk | "all">("all");
  const [search, setSearch] = useState("");

  useEffect(() => {
    invoke<SkillPack[]>("list_skill_packs")
      .then(setPacks)
      .catch((e) => setError(String(e)));
  }, []);

  const stats = useMemo(() => {
    let read = 0;
    let mutate = 0;
    let dangerous = 0;
    for (const p of packs) {
      for (const c of p.commands) {
        if (c.risk === "read") read++;
        else if (c.risk === "mutate") mutate++;
        else dangerous++;
      }
    }
    return { read, mutate, dangerous, total: read + mutate + dangerous };
  }, [packs]);

  return (
    <section className="space-y-4">
      <div>
        <h3 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wide">
          <BookOpen className="h-4 w-4 text-[var(--color-accent)]" />
          Skill packs
        </h3>
        <p className="mt-1 text-xs text-[var(--color-muted)]">
          Vendor command catalogues bundled with Atlas. Each command declares
          its risk; the operator approves any non-Read invocation at runtime.
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-3 text-[11px] text-[var(--color-muted)]">
        <span>
          {packs.length} packs · {stats.total} commands ·{" "}
          <span className="text-emerald-300">{stats.read} read</span>
          {stats.mutate > 0 && (
            <>
              {" "}·{" "}
              <span className="text-amber-300">{stats.mutate} mutate</span>
            </>
          )}
          {stats.dangerous > 0 && (
            <>
              {" "}·{" "}
              <span className="text-rose-300">
                {stats.dangerous} dangerous
              </span>
            </>
          )}
        </span>
        <select
          value={filterRisk}
          onChange={(e) => setFilterRisk(e.target.value as Risk | "all")}
          className="rounded border border-[var(--color-border)] bg-black/30 px-2 py-1 text-[11px]"
        >
          <option value="all">All risks</option>
          <option value="read">Read only</option>
          <option value="mutate">Mutate</option>
          <option value="dangerous">Dangerous</option>
        </select>
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="search commands…"
          className="rounded border border-[var(--color-border)] bg-black/30 px-2 py-1 text-[11px]"
        />
      </div>

      {error && (
        <div className="rounded border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-200">
          {error}
        </div>
      )}

      <div className="space-y-2">
        {packs.map((pack) => {
          const open = !!expanded[pack.id];
          const visibleCommands = pack.commands.filter((c) => {
            if (filterRisk !== "all" && c.risk !== filterRisk) return false;
            if (search) {
              const q = search.toLowerCase();
              return (
                c.id.toLowerCase().includes(q) ||
                c.purpose.toLowerCase().includes(q) ||
                c.template.toLowerCase().includes(q)
              );
            }
            return true;
          });
          return (
            <article
              key={pack.id}
              className="overflow-hidden rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)]"
            >
              <button
                type="button"
                onClick={() =>
                  setExpanded((m) => ({ ...m, [pack.id]: !m[pack.id] }))
                }
                className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left"
              >
                <div className="flex flex-1 items-center gap-3">
                  {open ? (
                    <ChevronDown className="h-4 w-4 text-[var(--color-muted)]" />
                  ) : (
                    <ChevronRight className="h-4 w-4 text-[var(--color-muted)]" />
                  )}
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold">
                        {pack.name}
                      </span>
                      <code className="rounded bg-black/30 px-1.5 py-0.5 text-[10px] text-[var(--color-muted)]">
                        {pack.id}
                      </code>
                      <span className="inline-flex items-center gap-1 rounded border border-[var(--color-border)] px-1.5 py-0.5 text-[10px] uppercase text-[var(--color-muted)]">
                        {pack.transport === "ssh" ? (
                          <Cable className="h-2.5 w-2.5" />
                        ) : (
                          <Globe className="h-2.5 w-2.5" />
                        )}
                        {pack.transport}
                      </span>
                    </div>
                    <p className="mt-0.5 text-xs text-[var(--color-muted)]">
                      {pack.description}
                    </p>
                  </div>
                </div>
                <span className="text-[10px] uppercase tracking-wide text-[var(--color-muted)]">
                  {visibleCommands.length} / {pack.commands.length} cmds
                </span>
              </button>

              {open && (
                <div className="border-t border-[var(--color-border)] px-4 py-3">
                  {pack.login && (
                    <div className="mb-3 rounded border border-sky-500/30 bg-sky-500/10 px-3 py-2 text-[11px] text-sky-200">
                      <span className="font-semibold uppercase tracking-wide text-[10px] mr-2">
                        Login
                      </span>
                      {pack.login.api_key_header
                        ? `API key sent in header ${pack.login.api_key_header}`
                        : `POST ${pack.login.path} with ${pack.login.username_field}/${pack.login.password_field}`}
                    </div>
                  )}
                  <div className="space-y-2">
                    {visibleCommands.map((cmd) => {
                      const meta = RISK_META[cmd.risk];
                      const Icon = meta.Icon;
                      return (
                        <div
                          key={cmd.id}
                          className="rounded border border-[var(--color-border)] bg-black/20 p-3"
                        >
                          <div className="flex flex-wrap items-center gap-2">
                            <code className="text-xs font-semibold text-[var(--color-text)]">
                              {cmd.id}
                            </code>
                            <span
                              className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] uppercase ${meta.tone}`}
                            >
                              <Icon className="h-3 w-3" />
                              {meta.label}
                            </span>
                            {pack.transport === "https" && (
                              <code className="rounded bg-black/40 px-1.5 py-0.5 text-[10px] text-[var(--color-muted)]">
                                {cmd.method}
                              </code>
                            )}
                            {cmd.parser && (
                              <span className="rounded border border-[var(--color-border)] px-1.5 py-0.5 text-[10px] text-[var(--color-muted)]">
                                parser: {cmd.parser}
                              </span>
                            )}
                          </div>
                          <p className="mt-1 text-[11px] text-[var(--color-muted)]">
                            {cmd.purpose}
                          </p>
                          <pre className="mt-2 overflow-x-auto rounded bg-black/40 p-2 font-mono text-[10px] leading-relaxed text-slate-300">
                            {cmd.template}
                          </pre>
                          {cmd.body_template && (
                            <pre className="mt-1 overflow-x-auto rounded bg-black/40 p-2 font-mono text-[10px] leading-relaxed text-slate-300">
                              body: {cmd.body_template}
                            </pre>
                          )}
                          {cmd.args.length > 0 && (
                            <div className="mt-2 flex flex-wrap gap-1">
                              {cmd.args.map((a) => (
                                <span
                                  key={a.name}
                                  className="rounded border border-[var(--color-border)] px-1.5 py-0.5 text-[10px] text-[var(--color-muted)]"
                                  title={`type: ${a.type}${a.required ? " · required" : ""}${a.default ? ` · default: ${a.default}` : ""}`}
                                >
                                  {a.name}: {a.type}
                                  {!a.required && "?"}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      );
                    })}
                    {visibleCommands.length === 0 && (
                      <p className="text-xs text-[var(--color-muted)]">
                        No commands match the current filter.
                      </p>
                    )}
                  </div>
                </div>
              )}
            </article>
          );
        })}
      </div>
    </section>
  );
}

export default SkillPackBrowser;
