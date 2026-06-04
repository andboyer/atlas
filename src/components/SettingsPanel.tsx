import { useState, useEffect, useCallback } from "react";
import { useShallow } from "zustand/react/shallow";
import { Channel, invoke } from "@tauri-apps/api/core";
import { useApp } from "../store";
import type { InstallProgress, OllamaStatus, Settings } from "../types";

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

  // —— Ollama status / install plumbing ——
  // We poll `check_ollama_status` whenever the user opens settings or
  // changes the base URL / provider, so the status badge stays honest.
  // The install modal opens on "Install Ollama" and listens on a Tauri
  // `Channel<InstallProgress>` for streaming download progress.
  const [ollamaStatus, setOllamaStatus] = useState<OllamaStatus | null>(null);
  const [ollamaChecking, setOllamaChecking] = useState(false);
  const [installOpen, setInstallOpen] = useState(false);
  const [installProgress, setInstallProgress] = useState<InstallProgress | null>(null);
  const [installRunning, setInstallRunning] = useState(false);
  const [useCustomModel, setUseCustomModel] = useState(false);

  const refreshOllamaStatus = useCallback(async () => {
    setOllamaChecking(true);
    try {
      const status = await invoke<OllamaStatus>("check_ollama_status", {
        baseUrl: draft.llm_base_url || null,
      });
      setOllamaStatus(status);
    } catch {
      // The command is no-error by design; if invoke itself fails
      // (Tauri bridge down) we just show "unknown" — not a hard failure.
      setOllamaStatus(null);
    } finally {
      setOllamaChecking(false);
    }
  }, [draft.llm_base_url]);

  // Re-check whenever the user switches to Ollama or edits the URL.
  useEffect(() => {
    if ((draft.llm_provider ?? "openai") === "ollama") {
      void refreshOllamaStatus();
    }
  }, [draft.llm_provider, refreshOllamaStatus]);

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
                    onBlur={() => void refreshOllamaStatus()}
                    className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)] px-3 py-1.5 text-sm font-mono"
                  />
                  <OllamaStatusRow
                    status={ollamaStatus}
                    checking={ollamaChecking}
                    onRefresh={refreshOllamaStatus}
                    onInstall={() => { setInstallProgress(null); setInstallOpen(true); }}
                    onLaunch={async () => {
                      try {
                        await invoke("launch_ollama");
                        // Daemon takes ~2s to bind :11434 on first launch.
                        setTimeout(() => void refreshOllamaStatus(), 2500);
                      } catch (e) {
                        alert(`Could not launch Ollama: ${e}`);
                      }
                    }}
                  />
                </div>
              )}

              <div className="space-y-1">
                <div className="flex items-center justify-between">
                  <label className="text-xs text-[var(--color-muted)]">Model</label>
                  {(draft.llm_provider ?? "openai") === "ollama"
                    && (ollamaStatus?.models.length ?? 0) > 0 && (
                      <button
                        type="button"
                        onClick={() => setUseCustomModel((v) => !v)}
                        className="text-[10px] text-[var(--color-muted)] underline-offset-2 hover:underline"
                      >
                        {useCustomModel ? "Pick from installed" : "Type a custom name"}
                      </button>
                    )}
                </div>
                {(draft.llm_provider ?? "openai") === "ollama"
                  && (ollamaStatus?.models.length ?? 0) > 0
                  && !useCustomModel ? (
                  <select
                    value={draft.llm_model ?? DEFAULT_MODELS[draft.llm_provider ?? "openai"]}
                    onChange={(e) => update({ llm_model: e.target.value || null })}
                    className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)] px-3 py-1.5 text-sm font-mono"
                  >
                    {ollamaStatus!.models.map((m) => (
                      <option key={m} value={m}>{m}</option>
                    ))}
                  </select>
                ) : (
                  <input
                    type="text"
                    value={draft.llm_model ?? DEFAULT_MODELS[draft.llm_provider ?? "openai"]}
                    onChange={(e) => update({ llm_model: e.target.value || null })}
                    className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)] px-3 py-1.5 text-sm font-mono"
                  />
                )}
                {(draft.llm_provider ?? "openai") === "ollama"
                  && ollamaStatus?.reachable
                  && ollamaStatus.models.length === 0 && (
                    <p className="text-[10px] text-amber-400">
                      Ollama is running but no models are installed. Open a terminal and run
                      {" "}<code className="font-mono">ollama pull {draft.llm_model ?? "llama3"}</code>.
                    </p>
                  )}
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
      {installOpen && (
        <OllamaInstallModal
          progress={installProgress}
          running={installRunning}
          onClose={() => {
            if (installRunning) return;
            setInstallOpen(false);
            void refreshOllamaStatus();
          }}
          onStart={async () => {
            setInstallRunning(true);
            const channel = new Channel<InstallProgress>();
            channel.onmessage = (msg) => setInstallProgress(msg);
            try {
              await invoke("install_ollama", { progress: channel });
              // Successful path: re-poll status, leave modal open so user
              // sees the success state before they close it themselves.
              await refreshOllamaStatus();
            } catch (e) {
              setInstallProgress({ kind: "failed", message: String(e) });
            } finally {
              setInstallRunning(false);
            }
          }}
        />
      )}
    </div>
  );
}

/** Status row rendered under the Ollama base-URL input. Three states:
 *  reachable (green), installed-but-not-running (amber + Launch), or
 *  not-installed (amber + Install). */
function OllamaStatusRow({
  status, checking, onRefresh, onInstall, onLaunch,
}: {
  status: OllamaStatus | null;
  checking: boolean;
  onRefresh: () => void;
  onInstall: () => void;
  onLaunch: () => void;
}) {
  if (checking && !status) {
    return <p className="text-[10px] text-[var(--color-muted)]">Checking Ollama…</p>;
  }
  if (!status) {
    return (
      <p className="text-[10px] text-[var(--color-muted)]">
        Couldn't probe Ollama.
        {" "}<button onClick={onRefresh} className="underline">Retry</button>
      </p>
    );
  }
  if (status.reachable) {
    return (
      <p className="flex items-center gap-2 text-[10px] text-emerald-400">
        <span>✓ Ollama running</span>
        {status.version && <span className="text-[var(--color-muted)]">v{status.version}</span>}
        <span className="text-[var(--color-muted)]">
          — {status.models.length} model{status.models.length === 1 ? "" : "s"}
        </span>
        <button onClick={onRefresh} className="ml-auto text-[var(--color-muted)] underline">Refresh</button>
      </p>
    );
  }
  if (status.app_installed) {
    return (
      <div className="flex items-center gap-2 text-[10px] text-amber-400">
        <span>⚠ Ollama installed but not running</span>
        <button
          onClick={onLaunch}
          className="ml-auto rounded-md border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-amber-300 hover:bg-amber-500/20"
        >
          Launch Ollama
        </button>
      </div>
    );
  }
  return (
    <div className="flex items-center gap-2 text-[10px] text-amber-400">
      <span>Ollama not detected on this machine.</span>
      <button
        onClick={onInstall}
        className="ml-auto rounded-md border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-amber-300 hover:bg-amber-500/20"
      >
        Install Ollama
      </button>
    </div>
  );
}

/** Modal that drives the `install_ollama` Tauri command. Shows the
 *  upstream URL (so the user can verify it before clicking Download),
 *  the SHA256 sidecar is fetched + checked behind the scenes, and a
 *  live progress bar streams from the Tauri channel. */
function OllamaInstallModal({
  progress, running, onClose, onStart,
}: {
  progress: InstallProgress | null;
  running: boolean;
  onClose: () => void;
  onStart: () => void;
}) {
  // We can't know exact size before the Starting event arrives, so we
  // pre-show "~177 MB (macOS)" / "~1.4 GB (Windows)" hints. The actual
  // total comes from the server's Content-Length once the download begins.
  const isMac = typeof navigator !== "undefined" && /Mac/i.test(navigator.platform);
  const sizeHint = isMac ? "~177 MB" : "~1.4 GB";
  const sourceUrl = isMac
    ? "https://ollama.com/download/Ollama-darwin.zip"
    : "https://ollama.com/download/OllamaSetup.exe";

  const downloaded = progress?.kind === "progress" ? progress.downloaded_bytes : 0;
  const total = progress?.kind === "progress" || progress?.kind === "starting"
    ? progress.total_bytes
    : 0;
  const pct = total > 0 ? Math.min(100, Math.round((downloaded / total) * 100)) : 0;
  const fmtMB = (n: number) => `${(n / 1024 / 1024).toFixed(1)} MB`;
  const done = progress?.kind === "done";
  const failed = progress?.kind === "failed";

  let statusLine = "";
  if (failed) statusLine = progress.message;
  else if (done) statusLine = "Ollama installed and launched. The daemon is starting up…";
  else if (progress?.kind === "installing") statusLine = progress.step;
  else if (progress?.kind === "verifying") statusLine = "Verifying SHA256…";
  else if (progress?.kind === "progress")
    statusLine = total > 0
      ? `Downloading… ${fmtMB(downloaded)} / ${fmtMB(total)} (${pct}%)`
      : `Downloading… ${fmtMB(downloaded)}`;
  else if (progress?.kind === "starting") statusLine = "Starting download…";
  else if (running) statusLine = "Fetching SHA256 sidecar from ollama.com…";

  return (
    <div
      className="fixed inset-0 z-[60] flex items-center justify-center bg-black/70 backdrop-blur-sm"
      onClick={(e) => { if (!running && e.target === e.currentTarget) onClose(); }}
    >
      <div className="w-full max-w-md rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-6 shadow-2xl">
        <h3 className="mb-3 text-sm font-semibold">Install Ollama</h3>
        <p className="mb-3 text-xs text-[var(--color-muted)]">
          Atlas will download Ollama directly from the publisher and verify the SHA256
          against the official sidecar at the same URL. {sizeHint} on this platform.
          {!isMac && " Windows will prompt for elevation to complete the install."}
        </p>
        <div className="mb-3 rounded-md border border-[var(--color-border)] bg-[var(--color-panel-2)] px-3 py-2 text-[10px] font-mono break-all text-[var(--color-muted)]">
          {sourceUrl}
        </div>
        {(running || progress) && (
          <div className="space-y-2">
            <div className="h-2 w-full overflow-hidden rounded-full bg-[var(--color-panel-2)]">
              <div
                className={`h-full transition-all ${failed ? "bg-rose-500" : done ? "bg-emerald-500" : "bg-[var(--color-accent)]"}`}
                style={{ width: `${done ? 100 : pct}%` }}
              />
            </div>
            <p className={`text-[11px] ${failed ? "text-rose-400" : done ? "text-emerald-400" : "text-[var(--color-muted)]"}`}>
              {statusLine}
            </p>
          </div>
        )}
        <div className="mt-5 flex justify-end gap-2">
          <button
            onClick={onClose}
            disabled={running}
            className="rounded-lg px-3 py-1.5 text-xs text-[var(--color-muted)] hover:text-[var(--color-fg)] disabled:opacity-40"
          >
            {done || failed ? "Close" : "Cancel"}
          </button>
          {!progress && !running && (
            <button
              onClick={onStart}
              className="rounded-lg bg-[var(--color-accent)] px-3 py-1.5 text-xs font-medium text-white hover:opacity-90"
            >
              Download &amp; install
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
