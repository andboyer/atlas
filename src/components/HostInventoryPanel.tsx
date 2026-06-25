import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Server,
  Plus,
  Trash2,
  KeyRound,
  ShieldCheck,
  ShieldAlert,
  Pencil,
  X,
  Save,
  PlugZap,
} from "lucide-react";
import { useApp } from "../store";

// Mirror of crate::device::inventory::{HostEntry, TransportKind, AuthKind, Roles}.
type TransportKind = "ssh" | "https" | "http";
type AuthKind = "password" | "key" | "api_key" | "basic";

interface HostRoles {
  av_switch?: boolean;
  spine?: boolean;
  edge?: boolean;
  wifi_controller?: boolean;
  audio_dsp?: boolean;
  router?: boolean;
}

interface HostEntry {
  id: string;
  alias: string;
  hostname: string;
  port: number;
  transport: TransportKind;
  skill: string;
  username: string;
  auth: AuthKind;
  key_path: string | null;
  site: string | null;
  roles: HostRoles;
  av_switch_uplink_port: string | null;
  timeout_seconds: number;
  tls_verify: boolean;
}

interface SkillPackLite {
  id: string;
  name: string;
  transport: TransportKind;
  description: string;
}

const SKILL_HINT: Record<string, { transport: TransportKind; port: number }> = {
  "cisco-ios": { transport: "ssh", port: 22 },
  "cisco-nxos": { transport: "ssh", port: 22 },
  "extreme-exos": { transport: "ssh", port: 22 },
  "netgear-avline": { transport: "ssh", port: 22 },
  "mikrotik-routeros": { transport: "ssh", port: 22 },
  "tplink-omada": { transport: "https", port: 443 },
  "unifi": { transport: "https", port: 443 },
  "luminex-gigacore": { transport: "http", port: 80 },
  "q-sys-core": { transport: "https", port: 443 },
};

function emptyHost(): HostEntry {
  return {
    id: "",
    alias: "",
    hostname: "",
    port: 22,
    transport: "ssh",
    skill: "cisco-ios",
    username: "admin",
    auth: "password",
    key_path: null,
    site: null,
    roles: {},
    av_switch_uplink_port: null,
    timeout_seconds: 30,
    tls_verify: true,
  };
}

function slugifyId(alias: string, hostname: string): string {
  const seed = (alias || hostname || "host").toLowerCase();
  return seed.replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 48);
}

// ── Wire <-> form adapters ──────────────────────────────────────────────
// The Rust `HostEntry` represents roles as a string array (e.g.
// ["av_switch","router"]) and key_path/site/av_switch_uplink_port as plain
// (possibly empty) strings. The form models roles as a checkbox object and
// uses `null` for empty optional fields, so we translate at the boundary.
const ROLE_KEYS: Array<keyof HostRoles> = [
  "av_switch",
  "spine",
  "edge",
  "wifi_controller",
  "audio_dsp",
  "router",
];

/** Shape sent to / received from Rust (`crate::device::inventory::HostEntry`). */
interface WireHostEntry extends Omit<HostEntry, "roles" | "key_path" | "site" | "av_switch_uplink_port"> {
  roles: string[];
  key_path: string;
  site: string;
  av_switch_uplink_port: string;
}

function rolesToArray(r: HostRoles): string[] {
  return ROLE_KEYS.filter((k) => !!r[k]);
}

function rolesFromArray(a: string[]): HostRoles {
  const out: HostRoles = {};
  for (const k of a) {
    if ((ROLE_KEYS as string[]).includes(k)) out[k as keyof HostRoles] = true;
  }
  return out;
}

/** Form entry → Rust payload (objects/nulls → arrays/empty strings). */
function toWire(e: HostEntry): WireHostEntry {
  return {
    ...e,
    key_path: e.key_path ?? "",
    site: e.site ?? "",
    av_switch_uplink_port: e.av_switch_uplink_port ?? "",
    roles: rolesToArray(e.roles),
  };
}

/** Rust payload → form entry (arrays/empty strings → objects/nulls). */
function fromWire(raw: WireHostEntry): HostEntry {
  return {
    ...raw,
    key_path: raw.key_path || null,
    site: raw.site || null,
    av_switch_uplink_port: raw.av_switch_uplink_port || null,
    roles: Array.isArray(raw.roles) ? rolesFromArray(raw.roles) : {},
  };
}

interface HostFormProps {
  draft: HostEntry;
  packs: SkillPackLite[];
  onChange: (next: HostEntry) => void;
  onCancel: () => void;
  onSave: () => Promise<void>;
  onSavePassword?: (password: string) => Promise<void>;
  saving: boolean;
}

function HostForm({
  draft,
  packs,
  onChange,
  onCancel,
  onSave,
  onSavePassword,
  saving,
}: HostFormProps) {
  const [password, setPassword] = useState("");
  const [savingPw, setSavingPw] = useState(false);
  const [pwMsg, setPwMsg] = useState<string | null>(null);

  const set = <K extends keyof HostEntry>(k: K, v: HostEntry[K]) =>
    onChange({ ...draft, [k]: v });

  const setRole = (k: keyof HostRoles, v: boolean) =>
    onChange({ ...draft, roles: { ...draft.roles, [k]: v } });

  const handleSkillChange = (skill: string) => {
    const hint = SKILL_HINT[skill];
    onChange({
      ...draft,
      skill,
      transport: hint?.transport ?? draft.transport,
      port: hint?.port ?? draft.port,
      auth:
        skill === "q-sys-core"
          ? "api_key"
          : skill === "luminex-gigacore"
          ? "basic"
          : hint?.transport === "https"
          ? "password"
          : draft.auth,
    });
  };

  const handleSavePw = async () => {
    if (!onSavePassword || !password) return;
    setSavingPw(true);
    setPwMsg(null);
    try {
      await onSavePassword(password);
      setPassword("");
      setPwMsg("Saved to OS keychain.");
    } catch (e) {
      setPwMsg(`Failed: ${String(e)}`);
    } finally {
      setSavingPw(false);
    }
  };

  return (
    <div className="space-y-4 rounded-lg border border-[var(--color-accent)]/40 bg-[var(--color-panel)] p-4">
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <label className="flex flex-col gap-1 text-xs">
          <span className="font-semibold uppercase tracking-wide text-[var(--color-muted)]">
            Alias
          </span>
          <input
            value={draft.alias}
            onChange={(e) => set("alias", e.target.value)}
            placeholder="Main AV switch"
            className="rounded border border-[var(--color-border)] bg-black/30 px-2 py-1.5 text-sm"
          />
        </label>
        <label className="flex flex-col gap-1 text-xs">
          <span className="font-semibold uppercase tracking-wide text-[var(--color-muted)]">
            Hostname / IP
          </span>
          <input
            value={draft.hostname}
            onChange={(e) => set("hostname", e.target.value)}
            placeholder="10.0.0.10"
            className="rounded border border-[var(--color-border)] bg-black/30 px-2 py-1.5 text-sm"
          />
        </label>
        <label className="flex flex-col gap-1 text-xs">
          <span className="font-semibold uppercase tracking-wide text-[var(--color-muted)]">
            Port
          </span>
          <input
            type="number"
            value={draft.port}
            onChange={(e) => set("port", Number(e.target.value) || 22)}
            className="rounded border border-[var(--color-border)] bg-black/30 px-2 py-1.5 text-sm"
          />
        </label>
        <label className="flex flex-col gap-1 text-xs">
          <span className="font-semibold uppercase tracking-wide text-[var(--color-muted)]">
            Skill pack
          </span>
          <select
            value={draft.skill}
            onChange={(e) => handleSkillChange(e.target.value)}
            className="rounded border border-[var(--color-border)] bg-black/30 px-2 py-1.5 text-sm"
          >
            {packs.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name} ({p.transport})
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1 text-xs">
          <span className="font-semibold uppercase tracking-wide text-[var(--color-muted)]">
            Transport
          </span>
          <select
            value={draft.transport}
            onChange={(e) => set("transport", e.target.value as TransportKind)}
            className="rounded border border-[var(--color-border)] bg-black/30 px-2 py-1.5 text-sm"
          >
            <option value="ssh">SSH</option>
            <option value="https">HTTPS</option>
            <option value="http">HTTP</option>
          </select>
        </label>
        <label className="flex flex-col gap-1 text-xs">
          <span className="font-semibold uppercase tracking-wide text-[var(--color-muted)]">
            Auth
          </span>
          <select
            value={draft.auth}
            onChange={(e) => set("auth", e.target.value as AuthKind)}
            className="rounded border border-[var(--color-border)] bg-black/30 px-2 py-1.5 text-sm"
          >
            <option value="password">Password</option>
            <option value="key">SSH key</option>
            <option value="api_key">API key</option>
            <option value="basic">HTTP Basic</option>
          </select>
        </label>
        <label className="flex flex-col gap-1 text-xs">
          <span className="font-semibold uppercase tracking-wide text-[var(--color-muted)]">
            Username
          </span>
          <input
            value={draft.username}
            onChange={(e) => set("username", e.target.value)}
            className="rounded border border-[var(--color-border)] bg-black/30 px-2 py-1.5 text-sm"
          />
        </label>
        {draft.auth === "key" && (
          <label className="flex flex-col gap-1 text-xs">
            <span className="font-semibold uppercase tracking-wide text-[var(--color-muted)]">
              Key path
            </span>
            <input
              value={draft.key_path ?? ""}
              onChange={(e) => set("key_path", e.target.value || null)}
              placeholder="~/.ssh/id_ed25519"
              className="rounded border border-[var(--color-border)] bg-black/30 px-2 py-1.5 text-sm"
            />
          </label>
        )}
        <label className="flex flex-col gap-1 text-xs">
          <span className="font-semibold uppercase tracking-wide text-[var(--color-muted)]">
            Site (optional)
          </span>
          <input
            value={draft.site ?? ""}
            onChange={(e) => set("site", e.target.value || null)}
            placeholder="HQ / Studio A"
            className="rounded border border-[var(--color-border)] bg-black/30 px-2 py-1.5 text-sm"
          />
        </label>
        <label className="flex flex-col gap-1 text-xs">
          <span className="font-semibold uppercase tracking-wide text-[var(--color-muted)]">
            Timeout (seconds)
          </span>
          <input
            type="number"
            value={draft.timeout_seconds}
            onChange={(e) =>
              set("timeout_seconds", Number(e.target.value) || 30)
            }
            className="rounded border border-[var(--color-border)] bg-black/30 px-2 py-1.5 text-sm"
          />
        </label>
        {draft.transport === "https" && (
          <label className="flex items-center gap-2 text-xs">
            <input
              type="checkbox"
              checked={draft.tls_verify}
              onChange={(e) => set("tls_verify", e.target.checked)}
            />
            <span>Verify TLS certificate</span>
          </label>
        )}
        {draft.roles.av_switch && (
          <label className="flex flex-col gap-1 text-xs">
            <span className="font-semibold uppercase tracking-wide text-[var(--color-muted)]">
              AV switch uplink interface
            </span>
            <input
              value={draft.av_switch_uplink_port ?? ""}
              onChange={(e) =>
                set("av_switch_uplink_port", e.target.value || null)
              }
              placeholder="Gi1/0/1"
              className="rounded border border-[var(--color-border)] bg-black/30 px-2 py-1.5 text-sm"
            />
          </label>
        )}
      </div>

      <fieldset className="rounded border border-[var(--color-border)] p-3">
        <legend className="px-1 text-[10px] font-semibold uppercase tracking-wide text-[var(--color-muted)]">
          Roles (used by runbooks as host.&lt;role&gt;)
        </legend>
        <div className="mt-1 grid grid-cols-2 gap-2 md:grid-cols-3">
          {(
            [
              ["av_switch", "AV switch"],
              ["spine", "Spine"],
              ["edge", "Edge"],
              ["wifi_controller", "Wi-Fi controller"],
              ["audio_dsp", "Audio DSP"],
              ["router", "Router"],
            ] as Array<[keyof HostRoles, string]>
          ).map(([k, label]) => (
            <label key={k} className="flex items-center gap-2 text-xs">
              <input
                type="checkbox"
                checked={!!draft.roles[k]}
                onChange={(e) => setRole(k, e.target.checked)}
              />
              <span>{label}</span>
            </label>
          ))}
        </div>
      </fieldset>

      {onSavePassword && draft.auth !== "key" && (
        <fieldset className="rounded border border-[var(--color-border)] p-3">
          <legend className="px-1 text-[10px] font-semibold uppercase tracking-wide text-[var(--color-muted)]">
            <KeyRound className="mr-1 inline h-3 w-3" />
            {draft.auth === "api_key" ? "API key" : "Password"} (stored in OS
            keychain)
          </legend>
          <div className="flex gap-2">
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              className="flex-1 rounded border border-[var(--color-border)] bg-black/30 px-2 py-1.5 text-sm"
            />
            <button
              type="button"
              disabled={!password || savingPw}
              onClick={handleSavePw}
              className="inline-flex items-center gap-1 rounded border border-[var(--color-border)] bg-[var(--color-panel)] px-3 py-1.5 text-xs hover:border-[var(--color-accent)]/40 disabled:opacity-50"
            >
              <Save className="h-3.5 w-3.5" />
              Save
            </button>
          </div>
          {pwMsg && (
            <p className="mt-2 text-[11px] text-[var(--color-muted)]">{pwMsg}</p>
          )}
        </fieldset>
      )}

      <div className="flex items-center justify-end gap-2">
        <button
          type="button"
          onClick={onCancel}
          className="inline-flex items-center gap-1 rounded border border-[var(--color-border)] px-3 py-1.5 text-xs"
        >
          <X className="h-3.5 w-3.5" />
          Cancel
        </button>
        <button
          type="button"
          onClick={onSave}
          disabled={saving || !draft.hostname || !draft.alias}
          className="inline-flex items-center gap-1 rounded border border-[var(--color-accent)]/60 bg-[var(--color-accent)]/15 px-3 py-1.5 text-xs text-[var(--color-accent)] hover:bg-[var(--color-accent)]/25 disabled:opacity-50"
        >
          <Save className="h-3.5 w-3.5" />
          {saving ? "Saving…" : "Save host"}
        </button>
      </div>
    </div>
  );
}

export function HostInventoryPanel() {
  const [hosts, setHosts] = useState<HostEntry[]>([]);
  const [packs, setPacks] = useState<SkillPackLite[]>([]);
  const [editing, setEditing] = useState<HostEntry | null>(null);
  const [creating, setCreating] = useState<HostEntry | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState<string | null>(null);
  const [testMsg, setTestMsg] = useState<Record<string, string>>({});
  // Host id awaiting a second click to confirm deletion. `window.confirm`
  // is unreliable inside the Tauri webview (it silently returns false), so
  // we use an inline two-step confirm instead.
  const [confirmingDelete, setConfirmingDelete] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);

  const prefillHost = useApp((s) => s.prefillHost);
  const clearPrefillHost = useApp((s) => s.clearPrefillHost);

  const refresh = useCallback(async () => {
    try {
      const [hs, ps] = await Promise.all([
        invoke<WireHostEntry[]>("list_hosts"),
        invoke<SkillPackLite[]>("list_skill_packs"),
      ]);
      setHosts(hs.map(fromWire));
      setPacks(ps);
    } catch (e) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // When the IP Scanner asks to add a host, open the create form pre-filled
  // with its IP/alias and clear the request so it fires only once.
  useEffect(() => {
    if (!prefillHost) return;
    setCreating({
      ...emptyHost(),
      hostname: prefillHost.hostname,
      alias: prefillHost.alias ?? prefillHost.hostname,
    });
    setEditing(null);
    clearPrefillHost();
  }, [prefillHost, clearPrefillHost]);

  const handleStartCreate = () => {
    setCreating(emptyHost());
    setEditing(null);
  };

  const handleSaveNew = async () => {
    if (!creating) return;
    setSaving(true);
    setError(null);
    try {
      const entry = { ...creating };
      if (!entry.id) entry.id = slugifyId(entry.alias, entry.hostname);
      await invoke<WireHostEntry>("upsert_host", { entry: toWire(entry) });
      setCreating(null);
      await refresh();
    } catch (e) {
      setError(String(e));
    } finally {
      setSaving(false);
    }
  };

  const handleSaveEdit = async () => {
    if (!editing) return;
    setSaving(true);
    setError(null);
    try {
      await invoke<WireHostEntry>("upsert_host", { entry: toWire(editing) });
      setEditing(null);
      await refresh();
    } catch (e) {
      setError(String(e));
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id: string) => {
    setDeleting(id);
    setError(null);
    try {
      await invoke<void>("delete_host", { hostId: id });
      setConfirmingDelete(null);
      await refresh();
    } catch (e) {
      setError(String(e));
    } finally {
      setDeleting(null);
    }
  };

  const handleTest = async (host: HostEntry) => {
    setTesting(host.id);
    setTestMsg((m) => ({ ...m, [host.id]: "Testing…" }));
    try {
      const msg = await invoke<string>("test_host", { hostId: host.id });
      setTestMsg((m) => ({ ...m, [host.id]: msg }));
    } catch (e) {
      setTestMsg((m) => ({ ...m, [host.id]: `Failed: ${String(e)}` }));
    } finally {
      setTesting(null);
    }
  };

  const handleSavePassword = async (id: string, password: string) => {
    await invoke<void>("set_host_password", { hostId: id, password });
  };

  return (
    <section className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wide">
            <Server className="h-4 w-4 text-[var(--color-accent)]" />
            Host inventory
          </h3>
          <p className="mt-1 text-xs text-[var(--color-muted)]">
            Devices that runbooks may query. Credentials live in the OS
            keychain (macOS Keychain / Windows Credential Manager / Secret
            Service).
          </p>
        </div>
        <button
          type="button"
          onClick={handleStartCreate}
          className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--color-accent)]/60 bg-[var(--color-accent)]/15 px-3 py-1.5 text-xs font-medium text-[var(--color-accent)] hover:bg-[var(--color-accent)]/25"
        >
          <Plus className="h-3.5 w-3.5" />
          Add host
        </button>
      </div>

      {error && (
        <div className="rounded border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-200">
          {error}
        </div>
      )}

      {creating && (
        <HostForm
          draft={creating}
          packs={packs}
          onChange={setCreating}
          onCancel={() => setCreating(null)}
          onSave={handleSaveNew}
          saving={saving}
        />
      )}

      {hosts.length === 0 && !creating && (
        <div className="rounded-lg border border-dashed border-[var(--color-border)] bg-[var(--color-panel)]/50 px-4 py-6 text-center text-sm text-[var(--color-muted)]">
          No hosts configured yet. Click <strong>Add host</strong> to point
          Atlas at a switch, controller, or DSP.
        </div>
      )}

      <div className="space-y-2">
        {hosts.map((h) => {
          const isEditing = editing?.id === h.id;
          if (isEditing && editing) {
            return (
              <HostForm
                key={h.id}
                draft={editing}
                packs={packs}
                onChange={setEditing}
                onCancel={() => setEditing(null)}
                onSave={handleSaveEdit}
                onSavePassword={(p) => handleSavePassword(h.id, p)}
                saving={saving}
              />
            );
          }
          return (
            <article
              key={h.id}
              className="rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)] p-3"
            >
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-semibold">{h.alias}</span>
                    <code className="rounded bg-black/30 px-1.5 py-0.5 text-[10px] text-[var(--color-muted)]">
                      {h.id}
                    </code>
                    <span className="rounded border border-[var(--color-border)] px-1.5 py-0.5 text-[10px] uppercase text-[var(--color-muted)]">
                      {h.transport}
                    </span>
                    <span className="rounded border border-[var(--color-border)] px-1.5 py-0.5 text-[10px] uppercase text-[var(--color-muted)]">
                      {h.skill}
                    </span>
                  </div>
                  <div className="mt-1 text-[11px] text-[var(--color-muted)]">
                    {h.username}@{h.hostname}:{h.port}
                    {h.site && ` · ${h.site}`}
                    {Object.entries(h.roles)
                      .filter(([, v]) => v)
                      .map(([k]) => k)
                      .join(", ") &&
                      ` · ${Object.entries(h.roles)
                        .filter(([, v]) => v)
                        .map(([k]) => k)
                        .join(", ")}`}
                  </div>
                  {testMsg[h.id] && (
                    <div
                      className={`mt-2 inline-flex items-center gap-1 rounded border px-2 py-0.5 text-[11px] ${
                        testMsg[h.id].startsWith("OK")
                          ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-200"
                          : testMsg[h.id] === "Testing…"
                          ? "border-sky-500/40 bg-sky-500/10 text-sky-200"
                          : "border-rose-500/40 bg-rose-500/10 text-rose-200"
                      }`}
                    >
                      {testMsg[h.id].startsWith("OK") ? (
                        <ShieldCheck className="h-3 w-3" />
                      ) : testMsg[h.id] === "Testing…" ? (
                        <PlugZap className="h-3 w-3" />
                      ) : (
                        <ShieldAlert className="h-3 w-3" />
                      )}
                      {testMsg[h.id]}
                    </div>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => handleTest(h)}
                    disabled={testing === h.id}
                    className="inline-flex items-center gap-1 rounded border border-[var(--color-border)] px-2 py-1 text-[11px] hover:border-[var(--color-accent)]/40 disabled:opacity-50"
                  >
                    <PlugZap className="h-3 w-3" />
                    Test
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setEditing(h);
                      setCreating(null);
                    }}
                    className="inline-flex items-center gap-1 rounded border border-[var(--color-border)] px-2 py-1 text-[11px] hover:border-[var(--color-accent)]/40"
                  >
                    <Pencil className="h-3 w-3" />
                    Edit
                  </button>
                  {confirmingDelete === h.id ? (
                    <div className="inline-flex items-center gap-1">
                      <button
                        type="button"
                        onClick={() => handleDelete(h.id)}
                        disabled={deleting === h.id}
                        className="inline-flex items-center gap-1 rounded border border-rose-500/60 bg-rose-500/15 px-2 py-1 text-[11px] font-medium text-rose-200 hover:bg-rose-500/25 disabled:opacity-50"
                      >
                        <Trash2 className="h-3 w-3" />
                        {deleting === h.id ? "Deleting…" : "Confirm"}
                      </button>
                      <button
                        type="button"
                        onClick={() => setConfirmingDelete(null)}
                        disabled={deleting === h.id}
                        className="inline-flex items-center gap-1 rounded border border-[var(--color-border)] px-2 py-1 text-[11px] hover:border-[var(--color-accent)]/40 disabled:opacity-50"
                      >
                        Cancel
                      </button>
                    </div>
                  ) : (
                    <button
                      type="button"
                      onClick={() => setConfirmingDelete(h.id)}
                      className="inline-flex items-center gap-1 rounded border border-rose-500/40 px-2 py-1 text-[11px] text-rose-300 hover:bg-rose-500/15"
                    >
                      <Trash2 className="h-3 w-3" />
                      Delete
                    </button>
                  )}
                </div>
              </div>
            </article>
          );
        })}
      </div>
    </section>
  );
}

export default HostInventoryPanel;
