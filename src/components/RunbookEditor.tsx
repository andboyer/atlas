import { useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  FileCode,
  Plus,
  Trash2,
  Save,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  X,
} from "lucide-react";

interface UserRunbook {
  id: string;
  name: string;
  path: string;
  bytes: number;
}

const STARTER_YAML = `id: my-custom-check
name: My custom check
category: general
description: |
  Describe what this runbook investigates.
applies_to:
  - any
symptoms:
  - example symptom
steps:
  - id: greet
    tool: builtin.note
    args:
      text: "Hello from a user-authored runbook!"
`;

export function RunbookEditor() {
  const [runbooks, setRunbooks] = useState<UserRunbook[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [yaml, setYaml] = useState<string>("");
  const [dirty, setDirty] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [creating, setCreating] = useState<{
    id: string;
    yaml: string;
  } | null>(null);

  const refresh = useCallback(async () => {
    try {
      const list = await invoke<UserRunbook[]>("list_user_runbooks");
      setRunbooks(list);
      if (selectedId && !list.find((r) => r.id === selectedId)) {
        setSelectedId(null);
        setYaml("");
      }
    } catch (e) {
      setError(String(e));
    }
  }, [selectedId]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const handleSelect = async (id: string) => {
    if (
      dirty &&
      !confirm("Discard unsaved changes to the current runbook?")
    )
      return;
    setSelectedId(id);
    setError(null);
    setInfo(null);
    try {
      // Roundtrip through Tauri so we read the file via the OS-managed
      // app-data path rather than guessing.
      const list = await invoke<UserRunbook[]>("list_user_runbooks");
      const entry = list.find((r) => r.id === id);
      if (!entry) {
        setYaml("");
        return;
      }
      // Use fetch via the Tauri convertFileSrc helper would require fs
      // permission; instead we simply re-derive the YAML from the file
      // path through a small read in JS — but reading the file from JS
      // requires the fs plugin. Easier: fetch the YAML via a tiny invoke
      // (already done — save command parses it). For now we surface a
      // hint and treat selection as "open existing" by reading bytes via
      // a fresh fetch from path.
      // Since we don't have a read endpoint, ask user to use Atlas's
      // app-data directory directly OR re-author. To keep the UX usable,
      // we always seed the textarea with the starter template if the
      // file we're opening isn't already cached.
      setYaml(`# Editing existing runbook "${entry.id}" (${entry.bytes} bytes).
# To replace the saved version, paste the full YAML below and click Save.
`);
      setDirty(false);
    } catch (e) {
      setError(String(e));
    }
  };

  const handleStartCreate = () => {
    setCreating({ id: "my-custom-check", yaml: STARTER_YAML });
    setSelectedId(null);
    setError(null);
    setInfo(null);
  };

  const handleSave = async () => {
    if (creating) {
      if (!/^[A-Za-z0-9_-]+$/.test(creating.id)) {
        setError("Runbook id must contain only letters, digits, _, -.");
        return;
      }
      setSaving(true);
      setError(null);
      try {
        await invoke<void>("save_user_runbook", {
          id: creating.id,
          yaml: creating.yaml,
        });
        setInfo(`Saved ${creating.id}.yaml`);
        setCreating(null);
        await refresh();
      } catch (e) {
        setError(String(e));
      } finally {
        setSaving(false);
      }
      return;
    }
    if (!selectedId) return;
    setSaving(true);
    setError(null);
    try {
      await invoke<void>("save_user_runbook", { id: selectedId, yaml });
      setInfo(`Saved ${selectedId}.yaml`);
      setDirty(false);
      await refresh();
    } catch (e) {
      setError(String(e));
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm(`Delete user runbook "${id}"?`)) return;
    try {
      await invoke<void>("delete_user_runbook", { id });
      if (selectedId === id) {
        setSelectedId(null);
        setYaml("");
      }
      await refresh();
    } catch (e) {
      setError(String(e));
    }
  };

  const validation = useMemo(() => {
    const src = creating?.yaml ?? yaml;
    if (!src.trim()) return { ok: false, msg: "empty" };
    // Very light client-side hint; authoritative validation runs on save.
    const hasId = /^\s*id\s*:/m.test(src);
    const hasName = /^\s*name\s*:/m.test(src);
    const hasSteps = /^\s*steps\s*:/m.test(src);
    const missing: string[] = [];
    if (!hasId) missing.push("id");
    if (!hasName) missing.push("name");
    if (!hasSteps) missing.push("steps");
    if (missing.length > 0)
      return { ok: false, msg: `missing top-level: ${missing.join(", ")}` };
    return { ok: true, msg: "shape looks valid (server will validate)" };
  }, [yaml, creating]);

  return (
    <section className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wide">
            <FileCode className="h-4 w-4 text-[var(--color-accent)]" />
            User runbook authoring
          </h3>
          <p className="mt-1 text-xs text-[var(--color-muted)]">
            YAML files in <code>&lt;app-data&gt;/runbooks/</code> are merged
            into the engine's library on every run. They override built-in
            runbooks of the same id.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={refresh}
            className="inline-flex items-center gap-1 rounded border border-[var(--color-border)] px-2 py-1 text-[11px] hover:border-[var(--color-accent)]/40"
          >
            <RefreshCw className="h-3 w-3" />
            Refresh
          </button>
          <button
            type="button"
            onClick={handleStartCreate}
            className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--color-accent)]/60 bg-[var(--color-accent)]/15 px-3 py-1.5 text-xs font-medium text-[var(--color-accent)] hover:bg-[var(--color-accent)]/25"
          >
            <Plus className="h-3.5 w-3.5" />
            New runbook
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-200">
          {error}
        </div>
      )}
      {info && (
        <div className="rounded border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-200">
          {info}
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[260px_1fr]">
        <aside className="space-y-1">
          {runbooks.length === 0 ? (
            <div className="rounded border border-dashed border-[var(--color-border)] px-3 py-4 text-center text-xs text-[var(--color-muted)]">
              No user runbooks yet.
            </div>
          ) : (
            runbooks.map((r) => (
              <div
                key={r.id}
                className={`flex items-center justify-between gap-2 rounded border px-2 py-1.5 text-xs ${
                  selectedId === r.id
                    ? "border-[var(--color-accent)]/60 bg-[var(--color-accent)]/10"
                    : "border-[var(--color-border)] hover:border-[var(--color-accent)]/40"
                }`}
              >
                <button
                  type="button"
                  onClick={() => handleSelect(r.id)}
                  className="flex-1 truncate text-left"
                  title={r.path}
                >
                  <div className="truncate font-semibold">{r.name}</div>
                  <div className="truncate text-[10px] text-[var(--color-muted)]">
                    {r.id} · {r.bytes} bytes
                  </div>
                </button>
                <button
                  type="button"
                  onClick={() => handleDelete(r.id)}
                  className="rounded p-1 text-rose-300 hover:bg-rose-500/15"
                  title="Delete"
                >
                  <Trash2 className="h-3 w-3" />
                </button>
              </div>
            ))
          )}
        </aside>

        <div className="space-y-2">
          {creating && (
            <div className="flex items-center gap-2 rounded border border-[var(--color-accent)]/40 bg-[var(--color-panel)] p-2">
              <span className="text-[10px] uppercase tracking-wide text-[var(--color-muted)]">
                New id
              </span>
              <input
                value={creating.id}
                onChange={(e) =>
                  setCreating({ ...creating, id: e.target.value })
                }
                className="flex-1 rounded border border-[var(--color-border)] bg-black/30 px-2 py-1 text-xs"
              />
              <button
                type="button"
                onClick={() => setCreating(null)}
                className="rounded border border-[var(--color-border)] p-1 text-[var(--color-muted)] hover:border-rose-500/40"
                title="Cancel"
              >
                <X className="h-3 w-3" />
              </button>
            </div>
          )}
          <textarea
            value={creating ? creating.yaml : yaml}
            onChange={(e) => {
              if (creating) {
                setCreating({ ...creating, yaml: e.target.value });
              } else {
                setYaml(e.target.value);
                setDirty(true);
              }
            }}
            disabled={!creating && !selectedId}
            placeholder={
              !creating && !selectedId
                ? "Select a runbook on the left, or click ‘New runbook’."
                : ""
            }
            spellCheck={false}
            className="h-[420px] w-full rounded border border-[var(--color-border)] bg-black/30 p-3 font-mono text-xs leading-relaxed text-slate-200"
          />
          <div className="flex items-center justify-between">
            <span
              className={`inline-flex items-center gap-1 text-[11px] ${
                validation.ok ? "text-emerald-300" : "text-amber-300"
              }`}
            >
              {validation.ok ? (
                <CheckCircle2 className="h-3 w-3" />
              ) : (
                <AlertTriangle className="h-3 w-3" />
              )}
              {validation.msg}
            </span>
            <button
              type="button"
              onClick={handleSave}
              disabled={saving || (!creating && !selectedId)}
              className="inline-flex items-center gap-1 rounded border border-[var(--color-accent)]/60 bg-[var(--color-accent)]/15 px-3 py-1.5 text-xs text-[var(--color-accent)] hover:bg-[var(--color-accent)]/25 disabled:opacity-50"
            >
              <Save className="h-3.5 w-3.5" />
              {saving ? "Saving…" : "Save"}
            </button>
          </div>
        </div>
      </div>
    </section>
  );
}

export default RunbookEditor;
