import { useState, useEffect } from "react";
import { useShallow } from "zustand/react/shallow";
import { useApp } from "../store";
import type { Settings } from "../types";

interface Props {
  onClose: () => void;
}

const INTERVALS = [
  { label: "30 seconds", value: 30 },
  { label: "1 minute", value: 60 },
  { label: "2 minutes", value: 120 },
  { label: "5 minutes", value: 300 },
  { label: "10 minutes", value: 600 },
  { label: "30 minutes", value: 1800 },
];

const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;

const PROVIDERS = [
  { id: "openai", label: "OpenAI", placeholder: "sk-..." },
  { id: "anthropic", label: "Anthropic", placeholder: "sk-ant-..." },
  { id: "ollama", label: "Ollama (local)", placeholder: "" },
];

const DEFAULT_MODELS: Record<string, string> = {
  openai: "gpt-4o-mini",
  anthropic: "claude-3-haiku-20240307",
  ollama: "llama3",
};

const PROFILES = [
  { id: "home", label: "Home / General" },
  { id: "retail_pos", label: "Retail / Restaurant POS" },
  { id: "smart_home", label: "Smart Home" },
  { id: "office", label: "Small Office" },
];

export function SettingsPanel({ onClose }: Props) {
  const { settings, saveSettings, startMonitoring, stopMonitoring, monitoring } = useApp(useShallow((s) => ({
    settings: s.settings,
    saveSettings: s.saveSettings,
    startMonitoring: s.startMonitoring,
    stopMonitoring: s.stopMonitoring,
    monitoring: s.monitoring,
  })));

  const [draft, setDraft] = useState<Settings>(settings);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [keyVisible, setKeyVisible] = useState(false);

  useEffect(() => { setDraft(settings); }, [settings]);

  const update = (patch: Partial<Settings>) =>
    setDraft((d) => ({ ...d, ...patch }));

  const handleSave = async () => {
    setSaving(true);
    await saveSettings(draft);
    setSaving(false);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const toggleMonitoring = async () => {
    if (monitoring) {
      await stopMonitoring();
    } else {
      // Save interval first so the monitor picks it up.
      await saveSettings(draft);
      await startMonitoring();
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="relative w-full max-w-lg rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-[var(--color-border)] px-6 py-4">
          <h2 className="text-base font-semibold">Settings</h2>
          <button
            onClick={onClose}
            className="text-[var(--color-muted)] hover:text-[var(--color-fg)] text-lg leading-none"
          >
            ✕
          </button>
        </div>

        <div className="max-h-[70vh] overflow-y-auto px-6 py-5 space-y-6">
          {/* Background Monitoring */}
          <section>
            <h3 className="mb-3 text-xs font-semibold uppercase tracking-wide text-[var(--color-muted)]">
              Background monitoring
            </h3>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm">Scan interval</span>
                <select
                  value={draft.scan_interval_secs}
                  onChange={(e) => update({ scan_interval_secs: Number(e.target.value) })}
                  className="rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)] px-3 py-1.5 text-sm"
                >
                  {INTERVALS.map((i) => (
                    <option key={i.value} value={i.value}>{i.label}</option>
                  ))}
                </select>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-sm">
                  {monitoring ? "Monitoring is active" : "Monitoring is off"}
                </span>
                <button
                  onClick={toggleMonitoring}
                  className={`rounded-full px-4 py-1.5 text-sm font-medium transition-colors ${
                    monitoring
                      ? "bg-rose-500/20 text-rose-300 hover:bg-rose-500/30"
                      : "bg-emerald-500/20 text-emerald-300 hover:bg-emerald-500/30"
                  }`}
                >
                  {monitoring ? "Stop monitoring" : "Start monitoring"}
                </button>
              </div>
            </div>
          </section>

          {/* Notifications */}
          <section>
            <h3 className="mb-3 text-xs font-semibold uppercase tracking-wide text-[var(--color-muted)]">
              Notifications
            </h3>
            <div className="space-y-3">
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={draft.notifications_enabled}
                  onChange={(e) => update({ notifications_enabled: e.target.checked })}
                  className="h-4 w-4 rounded"
                />
                <span className="text-sm">Enable OS notifications for new findings</span>
              </label>

              {draft.notifications_enabled && (
                <div className="flex items-center justify-between">
                  <span className="text-sm">Minimum severity</span>
                  <select
                    value={draft.notification_min_severity}
                    onChange={(e) => update({ notification_min_severity: e.target.value as Settings["notification_min_severity"] })}
                    className="rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)] px-3 py-1.5 text-sm"
                  >
                    {SEVERITIES.map((s) => (
                      <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
                    ))}
                  </select>
                </div>
              )}
            </div>
          </section>

          {/* Industry profile, watchlist, POS targets */}
          <section>
            <h3 className="mb-3 text-xs font-semibold uppercase tracking-wide text-[var(--color-muted)]">
              Industry profile
            </h3>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm">Profile</span>
                <select
                  value={draft.industry_profile ?? "home"}
                  onChange={(e) => update({ industry_profile: e.target.value })}
                  className="rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)] px-3 py-1.5 text-sm"
                >
                  {PROFILES.map((p) => (
                    <option key={p.id} value={p.id}>{p.label}</option>
                  ))}
                </select>
              </div>
              <p className="text-xs text-[var(--color-muted)]">
                Profiles tune detection thresholds and the default list of SaaS endpoints to probe (payment processors for POS, voice/cloud APIs for Smart Home, collaboration tools for Office).
              </p>
            </div>
          </section>

          <section>
            <h3 className="mb-3 text-xs font-semibold uppercase tracking-wide text-[var(--color-muted)]">
              Device watchlist
            </h3>
            <p className="mb-2 text-xs text-[var(--color-muted)]">
              MAC addresses (one per line) of critical devices — POS terminals, kitchen printers, NVRs. Watched devices fire a <span className="font-mono">critical</span> finding when offline.
            </p>
            <textarea
              value={(draft.watchlist ?? []).join("\n")}
              onChange={(e) =>
                update({
                  watchlist: e.target.value
                    .split(/\r?\n/)
                    .map((s) => s.trim())
                    .filter(Boolean),
                })
              }
              rows={4}
              placeholder="aa:bb:cc:dd:ee:ff"
              className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)] px-3 py-2 text-sm font-mono"
            />
          </section>

          <section>
            <h3 className="mb-3 text-xs font-semibold uppercase tracking-wide text-[var(--color-muted)]">
              Service reachability targets
            </h3>
            <p className="mb-2 text-xs text-[var(--color-muted)]">
              <span className="font-mono">host:port</span> per line. Leave empty to use the selected profile's defaults.
            </p>
            <textarea
              value={(draft.pos_targets ?? []).join("\n")}
              onChange={(e) =>
                update({
                  pos_targets: e.target.value
                    .split(/\r?\n/)
                    .map((s) => s.trim())
                    .filter(Boolean),
                })
              }
              rows={5}
              placeholder="api.clover.com:443"
              className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)] px-3 py-2 text-sm font-mono"
            />
            <div className="mt-2 flex justify-end">
              <button
                onClick={() => update({ pos_targets: [] })}
                className="text-xs text-[var(--color-muted)] hover:text-[var(--color-fg)] underline"
              >
                Reset to profile defaults
              </button>
            </div>
          </section>

          <section>
            <h3 className="mb-3 text-xs font-semibold uppercase tracking-wide text-[var(--color-muted)]">
              AI explanations (optional)
            </h3>
            <p className="mb-3 text-xs text-[var(--color-muted)]">
              Add an API key to get plain-language explanations of findings. Only aggregated metrics are sent — no hostnames, SSIDs, or raw traffic.
            </p>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm">Provider</span>
                <select
                  value={draft.llm_provider ?? "openai"}
                  onChange={(e) => {
                    const p = e.target.value;
                    update({ llm_provider: p, llm_model: DEFAULT_MODELS[p] ?? null });
                  }}
                  className="rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)] px-3 py-1.5 text-sm"
                >
                  {PROVIDERS.map((p) => (
                    <option key={p.id} value={p.id}>{p.label}</option>
                  ))}
                </select>
              </div>

              {(draft.llm_provider ?? "openai") !== "ollama" && (
                <div className="space-y-1">
                  <label className="text-xs text-[var(--color-muted)]">API key</label>
                  <div className="flex gap-2">
                    <input
                      type={keyVisible ? "text" : "password"}
                      value={draft.llm_api_key ?? ""}
                      onChange={(e) => update({ llm_api_key: e.target.value || null })}
                      placeholder={PROVIDERS.find((p) => p.id === (draft.llm_provider ?? "openai"))?.placeholder}
                      className="flex-1 rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)] px-3 py-1.5 text-sm font-mono"
                    />
                    <button
                      onClick={() => setKeyVisible((v) => !v)}
                      className="rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)] px-2 text-xs text-[var(--color-muted)]"
                    >
                      {keyVisible ? "Hide" : "Show"}
                    </button>
                  </div>
                </div>
              )}

              {(draft.llm_provider ?? "openai") === "ollama" && (
                <div className="space-y-1">
                  <label className="text-xs text-[var(--color-muted)]">Ollama base URL</label>
                  <input
                    type="text"
                    value={draft.llm_base_url ?? "http://localhost:11434"}
                    onChange={(e) => update({ llm_base_url: e.target.value || null })}
                    className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)] px-3 py-1.5 text-sm font-mono"
                  />
                </div>
              )}

              <div className="space-y-1">
                <label className="text-xs text-[var(--color-muted)]">Model</label>
                <input
                  type="text"
                  value={draft.llm_model ?? DEFAULT_MODELS[draft.llm_provider ?? "openai"]}
                  onChange={(e) => update({ llm_model: e.target.value || null })}
                  className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)] px-3 py-1.5 text-sm font-mono"
                />
              </div>
            </div>
          </section>
        </div>

        {/* Footer */}
        <div className="flex justify-end gap-3 border-t border-[var(--color-border)] px-6 py-4">
          <button
            onClick={onClose}
            className="rounded-lg px-4 py-2 text-sm text-[var(--color-muted)] hover:text-[var(--color-fg)]"
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            disabled={saving}
            className="rounded-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-medium text-white hover:opacity-90 disabled:opacity-50"
          >
            {saved ? "Saved ✓" : saving ? "Saving…" : "Save settings"}
          </button>
        </div>
      </div>
    </div>
  );
}
