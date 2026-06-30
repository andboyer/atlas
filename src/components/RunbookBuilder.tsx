import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Wand2,
  Plus,
  Trash2,
  Save,
  X,
  AlertTriangle,
  CheckCircle2,
  FileCode,
} from "lucide-react";

/** A user-authored runbook on disk (mirrors the `list_user_runbooks` row). */
interface UserRunbook {
  id: string;
  name: string;
  path: string;
  bytes: number;
}

/** Frontend catalog of the diagnostic tools a step can run. Mirrors the
 *  Rust tool registry (runbook/tools.rs). `iface` is auto-filled with the
 *  pinned NIC; `host` tools ask for a target instead. */
type ToolDef = {
  id: string;
  label: string;
  duration: boolean;
  defDur?: number;
  host?: boolean;
  admin?: boolean;
};

const TOOLS: ToolDef[] = [
  { id: "local.linkaudit", label: "Link audit — speed / duplex / MTU", duration: false },
  { id: "local.reachability", label: "Reachability — gateway + internet", duration: false },
  { id: "local.gateway", label: "Default gateway", duration: false },
  { id: "local.ping", label: "Ping a host", duration: false, host: true },
  { id: "local.multicast_groups", label: "Multicast group snapshot", duration: false },
  { id: "local.dante_browse", label: "Dante / AES67 discovery", duration: false },
  { id: "local.lldp_probe", label: "LLDP / CDP neighbours", duration: true, defDur: 30 },
  { id: "local.ptp_probe", label: "PTP grandmaster / jitter", duration: true, defDur: 8 },
  { id: "local.dscp_probe", label: "DSCP / QoS audit", duration: true, defDur: 10 },
  { id: "local.sap_listen", label: "SAP / SDP stream announcements", duration: true, defDur: 8 },
  { id: "local.igmp_listen", label: "IGMP querier listen (needs admin)", duration: true, defDur: 130, admin: true },
  { id: "local.stp_listen", label: "STP / L2 loop (needs admin)", duration: true, defDur: 30, admin: true },
];

const CATEGORIES = ["general", "wifi", "multicast", "switching", "av", "internet"];

type StepForm = {
  tool: string;
  duration: number;
  host: string;
  warnVerdict: string;
  warnMsg: string;
};

function emptyStep(): StepForm {
  return { tool: TOOLS[0].id, duration: 0, host: "1.1.1.1", warnVerdict: "", warnMsg: "" };
}

const toolDef = (id: string) => TOOLS.find((t) => t.id === id) ?? TOOLS[0];

function slugify(name: string): string {
  const s = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return s || "custom-runbook";
}

/** Double-quote a YAML scalar, escaping embedded quotes/backslashes. */
function yq(s: string): string {
  return `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function buildYaml(form: {
  name: string;
  category: string;
  description: string;
  symptoms: string;
  steps: StepForm[];
}): { id: string; yaml: string } {
  const id = slugify(form.name);
  const lines: string[] = [];
  lines.push(`id: ${id}`);
  lines.push(`name: ${yq(form.name.trim())}`);
  lines.push(`category: ${form.category || "general"}`);
  lines.push(`description: ${yq(form.description.trim() || form.name.trim())}`);

  const syms = form.symptoms
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
  if (syms.length) {
    lines.push("symptoms:");
    syms.forEach((s) => lines.push(`  - ${yq(s)}`));
  }

  lines.push("steps:");
  form.steps.forEach((st, i) => {
    const def = toolDef(st.tool);
    const bind = `step${i + 1}`;
    lines.push(`  - id: ${bind}`);
    lines.push(`    tool: ${st.tool}`);
    const args: string[] = [];
    if (def.host) args.push(`host: ${yq(st.host.trim() || "1.1.1.1")}`);
    else args.push(`iface: "{nic}"`);
    if (def.duration) args.push(`duration_s: ${st.duration || def.defDur || 12}`);
    lines.push(`    args: { ${args.join(", ")} }`);
    lines.push(`    bind: ${bind}`);
    const verdict = st.warnVerdict.trim();
    if (verdict) {
      lines.push(`    warn_if: ${bind}.verdict == '${verdict.replace(/'/g, "")}'`);
      lines.push(
        `    warn_msg: ${yq(st.warnMsg.trim() || `${def.label} returned '${verdict}'.`)}`,
      );
    }
  });
  return { id, yaml: lines.join("\n") + "\n" };
}

/**
 * Form-driven runbook author — no YAML/JSON required. The user names the
 * runbook, adds diagnostic steps from a dropdown, and optionally sets a
 * "warn when the result is X" rule per step; we generate valid runbook YAML
 * and persist it via `save_user_runbook`. Also lists/deletes saved runbooks.
 */
export function RunbookBuilder() {
  const [list, setList] = useState<UserRunbook[]>([]);
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [category, setCategory] = useState("general");
  const [description, setDescription] = useState("");
  const [symptoms, setSymptoms] = useState("");
  const [steps, setSteps] = useState<StepForm[]>([emptyStep()]);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setList(await invoke<UserRunbook[]>("list_user_runbooks"));
    } catch (e) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const reset = () => {
    setName("");
    setCategory("general");
    setDescription("");
    setSymptoms("");
    setSteps([emptyStep()]);
    setError(null);
  };

  const updateStep = (i: number, patch: Partial<StepForm>) =>
    setSteps((prev) => prev.map((s, idx) => (idx === i ? { ...s, ...patch } : s)));

  const save = async () => {
    setError(null);
    setInfo(null);
    if (!name.trim()) {
      setError("Give the runbook a name.");
      return;
    }
    if (steps.length === 0) {
      setError("Add at least one step.");
      return;
    }
    setSaving(true);
    try {
      const { id, yaml } = buildYaml({ name, category, description, symptoms, steps });
      await invoke("save_user_runbook", { id, yaml });
      setInfo(`Saved “${name.trim()}”. It now appears in the runbook list above.`);
      setOpen(false);
      reset();
      await refresh();
    } catch (e) {
      setError(String(e));
    } finally {
      setSaving(false);
    }
  };

  const remove = async (id: string) => {
    if (!confirm(`Delete the runbook “${id}”?`)) return;
    try {
      await invoke("delete_user_runbook", { id });
      await refresh();
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <section className="atlas-card p-5">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="flex items-center gap-2 text-sm font-semibold">
            <Wand2 className="h-4 w-4 text-[var(--color-accent)]" />
            Build your own runbook
          </h3>
          <p className="mt-1 text-xs text-[var(--color-muted)]">
            Stack diagnostic steps from a menu — no JSON or YAML to write. Saved
            runbooks show up in the runbook list to run on demand.
          </p>
        </div>
        {!open && (
          <button
            onClick={() => {
              reset();
              setOpen(true);
              setInfo(null);
            }}
            className="inline-flex items-center gap-2 rounded-lg bg-[var(--color-accent)] px-3.5 py-2 text-sm font-medium text-white hover:opacity-90"
          >
            <Plus className="h-4 w-4" /> New runbook
          </button>
        )}
      </header>

      {info && (
        <div className="mt-3 flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-2.5 text-xs text-emerald-300">
          <CheckCircle2 className="h-4 w-4 shrink-0" /> {info}
        </div>
      )}

      {open && (
        <div className="mt-4 space-y-4">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <label className="text-xs font-medium text-[var(--color-muted)]">
              Name
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. Dante dropout triage"
                className="mt-1 w-full rounded-md border border-[var(--color-border)] bg-[var(--color-panel-2)] px-2.5 py-1.5 text-sm text-[var(--color-text)]"
              />
            </label>
            <label className="text-xs font-medium text-[var(--color-muted)]">
              Category
              <select
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                className="mt-1 w-full rounded-md border border-[var(--color-border)] bg-[var(--color-panel-2)] px-2.5 py-1.5 text-sm text-[var(--color-text)]"
              >
                {CATEGORIES.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </select>
            </label>
          </div>

          <label className="block text-xs font-medium text-[var(--color-muted)]">
            What it investigates (optional)
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={2}
              placeholder="One or two sentences describing the problem this runbook diagnoses."
              className="mt-1 w-full rounded-md border border-[var(--color-border)] bg-[var(--color-panel-2)] px-2.5 py-1.5 text-sm text-[var(--color-text)]"
            />
          </label>

          <label className="block text-xs font-medium text-[var(--color-muted)]">
            Symptoms — one per line (helps the “Diagnose with…” matcher)
            <textarea
              value={symptoms}
              onChange={(e) => setSymptoms(e.target.value)}
              rows={2}
              placeholder={"audio drops out\ndevice keeps disconnecting"}
              className="mt-1 w-full rounded-md border border-[var(--color-border)] bg-[var(--color-panel-2)] px-2.5 py-1.5 text-sm text-[var(--color-text)]"
            />
          </label>

          <div>
            <div className="mb-2 flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wide text-[var(--color-muted)]">
                Steps
              </span>
              <button
                onClick={() => setSteps((s) => [...s, emptyStep()])}
                className="inline-flex items-center gap-1.5 rounded-md border border-[var(--color-border)] bg-[var(--color-panel)] px-2 py-1 text-[11px] font-medium hover:bg-[var(--color-panel-2)]"
              >
                <Plus className="h-3.5 w-3.5" /> Add step
              </button>
            </div>
            <div className="space-y-3">
              {steps.map((st, i) => {
                const def = toolDef(st.tool);
                return (
                  <div
                    key={i}
                    className="rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)]/50 p-3"
                  >
                    <div className="flex items-start gap-2">
                      <span className="mt-2 text-[11px] font-semibold text-[var(--color-muted)]">
                        {i + 1}
                      </span>
                      <div className="flex-1 space-y-2">
                        <div className="flex flex-wrap items-center gap-2">
                          <select
                            value={st.tool}
                            onChange={(e) => updateStep(i, { tool: e.target.value })}
                            className="flex-1 rounded-md border border-[var(--color-border)] bg-[var(--color-panel)] px-2 py-1.5 text-sm"
                          >
                            {TOOLS.map((t) => (
                              <option key={t.id} value={t.id}>
                                {t.label}
                              </option>
                            ))}
                          </select>
                          {def.host && (
                            <input
                              value={st.host}
                              onChange={(e) => updateStep(i, { host: e.target.value })}
                              placeholder="host / IP"
                              className="w-32 rounded-md border border-[var(--color-border)] bg-[var(--color-panel)] px-2 py-1.5 text-sm"
                            />
                          )}
                          {def.duration && (
                            <label className="flex items-center gap-1 text-[11px] text-[var(--color-muted)]">
                              listen
                              <input
                                type="number"
                                value={st.duration || def.defDur || 12}
                                onChange={(e) =>
                                  updateStep(i, { duration: Number(e.target.value) })
                                }
                                className="w-16 rounded-md border border-[var(--color-border)] bg-[var(--color-panel)] px-1.5 py-1 text-sm"
                              />
                              s
                            </label>
                          )}
                          {steps.length > 1 && (
                            <button
                              onClick={() =>
                                setSteps((s) => s.filter((_, idx) => idx !== i))
                              }
                              title="Remove step"
                              className="rounded-md border border-[var(--color-border)] p-1.5 text-rose-300 hover:bg-rose-500/10"
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </button>
                          )}
                        </div>
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-[11px] text-[var(--color-muted)]">
                            Warn when result is
                          </span>
                          <input
                            value={st.warnVerdict}
                            onChange={(e) =>
                              updateStep(i, { warnVerdict: e.target.value })
                            }
                            placeholder="verdict e.g. loop_suspected (optional)"
                            className="w-56 rounded-md border border-[var(--color-border)] bg-[var(--color-panel)] px-2 py-1 text-xs"
                          />
                          {st.warnVerdict.trim() && (
                            <input
                              value={st.warnMsg}
                              onChange={(e) =>
                                updateStep(i, { warnMsg: e.target.value })
                              }
                              placeholder="warning message"
                              className="flex-1 rounded-md border border-[var(--color-border)] bg-[var(--color-panel)] px-2 py-1 text-xs"
                            />
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {error && (
            <div className="flex items-center gap-2 rounded-lg border border-rose-500/30 bg-rose-500/10 p-2.5 text-xs text-rose-300">
              <AlertTriangle className="h-4 w-4 shrink-0" /> {error}
            </div>
          )}

          <div className="flex items-center gap-2">
            <button
              onClick={() => void save()}
              disabled={saving}
              className="inline-flex items-center gap-2 rounded-lg bg-[var(--color-accent)] px-3.5 py-2 text-sm font-medium text-white hover:opacity-90 disabled:opacity-50"
            >
              <Save className="h-4 w-4" /> {saving ? "Saving…" : "Save runbook"}
            </button>
            <button
              onClick={() => {
                setOpen(false);
                reset();
              }}
              className="inline-flex items-center gap-2 rounded-lg border border-[var(--color-border)] px-3 py-2 text-sm hover:bg-[var(--color-panel-2)]"
            >
              <X className="h-4 w-4" /> Cancel
            </button>
          </div>
        </div>
      )}

      {list.length > 0 && (
        <div className="mt-4 border-t border-[var(--color-border)] pt-3">
          <div className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-[var(--color-muted)]">
            Your saved runbooks
          </div>
          <div className="space-y-1.5">
            {list.map((rb) => (
              <div
                key={rb.id}
                className="flex items-center justify-between gap-2 rounded-md border border-[var(--color-border)] bg-[var(--color-panel-2)]/40 px-3 py-2 text-sm"
              >
                <span className="flex items-center gap-2 min-w-0">
                  <FileCode className="h-3.5 w-3.5 shrink-0 text-[var(--color-muted)]" />
                  <span className="truncate">{rb.name}</span>
                  <code className="shrink-0 text-[10px] text-[var(--color-muted)]">
                    {rb.id}
                  </code>
                </span>
                <button
                  onClick={() => void remove(rb.id)}
                  title="Delete"
                  className="rounded-md p-1.5 text-rose-300 hover:bg-rose-500/10"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
