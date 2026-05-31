/**
 * UpdateBanner — shows a dismissible banner when a new version is available.
 *
 * Checks for updates once on mount (fire-and-forget, silently ignores errors).
 * The "Update" button opens the GitHub releases page via the opener plugin.
 */
import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";
import { ArrowUpCircle, X } from "lucide-react";

interface UpdateInfo {
  available: boolean;
  version?: string;
  body?: string;
  error?: string;
}

export default function UpdateBanner() {
  const [update, setUpdate] = useState<UpdateInfo | null>(null);
  const [dismissed, setDismissed] = useState(false);

  useEffect(() => {
    invoke<UpdateInfo>("check_for_update")
      .then((info) => {
        if (info.available) setUpdate(info);
      })
      .catch(() => {
        // Silently ignore — offline or endpoint not set up yet.
      });
  }, []);

  if (!update?.available || dismissed) return null;

  return (
    <div className="flex items-center gap-3 px-4 py-2 bg-indigo-50 dark:bg-indigo-900/30 border-b border-indigo-100 dark:border-indigo-800 text-sm">
      <ArrowUpCircle className="w-4 h-4 text-indigo-500 flex-shrink-0" />
      <span className="flex-1 text-indigo-700 dark:text-indigo-300">
        Version <strong>{update.version}</strong> is available.
      </span>
      <button
        onClick={() =>
          openUrl(
            "https://github.com/andreboyer/wifi-troubleshooter/releases/latest"
          )
        }
        className="px-3 py-1 rounded-lg bg-indigo-500 hover:bg-indigo-600 text-white text-xs font-medium transition-colors"
      >
        Download
      </button>
      <button
        onClick={() => setDismissed(true)}
        className="p-0.5 rounded text-indigo-400 hover:text-indigo-600 dark:hover:text-indigo-200 transition-colors"
        aria-label="Dismiss"
      >
        <X className="w-3.5 h-3.5" />
      </button>
    </div>
  );
}
