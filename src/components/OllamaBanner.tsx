import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { AlertTriangle, Download } from "lucide-react";
import { useApp } from "../store";
import type { OllamaStatus } from "../types";

/**
 * Top-of-window reminder shown when the app is configured for local AI
 * (Ollama — the default) but the daemon isn't reachable. Links into Settings
 * where the one-click installer + qwen auto-pull live. Renders nothing once
 * Ollama is up, or when the user has switched to a cloud provider.
 */
export function OllamaBanner({
  onOpenSettings,
}: {
  onOpenSettings: () => void;
}) {
  const settings = useApp((s) => s.settings);
  const [status, setStatus] = useState<OllamaStatus | null>(null);

  const provider = settings?.llm_provider ?? "ollama";
  const baseUrl = settings?.llm_base_url ?? null;

  useEffect(() => {
    if (provider !== "ollama") return;
    let cancelled = false;
    const check = async () => {
      try {
        const s = await invoke<OllamaStatus>("check_ollama_status", {
          baseUrl,
        });
        if (!cancelled) setStatus(s);
      } catch {
        if (!cancelled) setStatus(null);
      }
    };
    void check();
    const id = setInterval(check, 30_000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [provider, baseUrl]);

  // Only nag when on local Ollama and the daemon isn't answering.
  if (provider !== "ollama" || !status || status.reachable) return null;

  const message = status.app_installed
    ? "Ollama is installed but not running — start it so Atlas can use local AI for insights and the assistant."
    : "Local AI isn't installed yet. Atlas uses Ollama + qwen for on-device insights and the assistant — no API key or cloud needed.";

  return (
    <div className="flex items-center justify-center gap-3 border-b border-amber-500/30 bg-amber-500/10 px-4 py-2 text-sm text-amber-200">
      <AlertTriangle className="h-4 w-4 shrink-0" />
      <span className="min-w-0 text-center">{message}</span>
      <button
        type="button"
        onClick={onOpenSettings}
        className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-amber-400/40 bg-amber-400/15 px-2.5 py-1 text-xs font-semibold text-amber-100 transition-colors hover:bg-amber-400/25"
      >
        <Download className="h-3.5 w-3.5" />
        {status.app_installed ? "Open settings" : "Install Ollama"}
      </button>
    </div>
  );
}
