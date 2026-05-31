import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { DeviceEvent, ScanResult, ScanSummary, Settings, UserMode } from "./types";

const DEFAULT_SETTINGS: Settings = {
  scan_interval_secs: 120,
  monitoring_enabled: false,
  notifications_enabled: true,
  notification_min_severity: "medium",
  llm_provider: null,
  llm_api_key: null,
  llm_model: null,
  llm_base_url: null,
  industry_profile: "home",
  watchlist: [],
  pos_targets: [],
  onboarding_complete: false,
};

interface AppState {
  mode: UserMode;
  setMode: (m: UserMode) => void;

  scanning: boolean;
  lastScan: ScanResult | null;
  error: string | null;

  recentScans: ScanSummary[];
  recentEvents: DeviceEvent[];

  settings: Settings;
  settingsLoaded: boolean;
  loadSettings: () => Promise<void>;
  saveSettings: (s: Settings) => Promise<void>;

  monitoring: boolean;
  startMonitoring: () => Promise<void>;
  stopMonitoring: () => Promise<void>;

  explanation: string | null;
  explaining: boolean;
  explainFindings: () => Promise<void>;

  runQuickScan: () => Promise<void>;
  refreshHistory: () => Promise<void>;
  subscribeToScanEvents: () => Promise<() => void>;
}

export const useApp = create<AppState>((set, get) => ({
  mode: "simple",
  setMode: (mode) => set({ mode }),

  scanning: false,
  lastScan: null,
  error: null,

  recentScans: [],
  recentEvents: [],

  settings: DEFAULT_SETTINGS,
  settingsLoaded: false,
  loadSettings: async () => {
    try {
      const s = await invoke<Settings>("get_settings");
      set({ settings: s, settingsLoaded: true, monitoring: s.monitoring_enabled });
    } catch (e) {
      console.warn("failed to load settings:", e);
      set({ settingsLoaded: true });
    }
  },
  saveSettings: async (s: Settings) => {
    await invoke("update_settings", { settings: s });
    set({ settings: s });
  },

  monitoring: false,
  startMonitoring: async () => {
    await invoke("start_monitoring");
    set({ monitoring: true });
    // Persist the monitoring flag.
    const s = get().settings;
    await get().saveSettings({ ...s, monitoring_enabled: true });
  },
  stopMonitoring: async () => {
    await invoke("stop_monitoring");
    set({ monitoring: false });
    const s = get().settings;
    await get().saveSettings({ ...s, monitoring_enabled: false });
  },

  explanation: null,
  explaining: false,
  explainFindings: async () => {
    const scan = get().lastScan;
    if (!scan) return;
    set({ explaining: true, explanation: null });
    try {
      const text = await invoke<string>("explain_findings", { scanResult: scan });
      set({ explanation: text, explaining: false });
    } catch (e) {
      set({ explanation: `Error: ${String(e)}`, explaining: false });
    }
  },

  runQuickScan: async () => {
    set({ scanning: true, error: null });
    try {
      const result = await invoke<ScanResult>("run_quick_scan");
      set({ lastScan: result, scanning: false });
      await get().refreshHistory();
    } catch (e) {
      set({ error: String(e), scanning: false });
    }
  },

  refreshHistory: async () => {
    try {
      const [recentScans, recentEvents] = await Promise.all([
        invoke<ScanSummary[]>("get_recent_scans", { limit: 20 }),
        invoke<DeviceEvent[]>("get_recent_device_events", { limit: 50 }),
      ]);
      set({ recentScans, recentEvents });
    } catch (e) {
      console.warn("history refresh failed:", e);
    }
  },

  subscribeToScanEvents: async () => {
    const unlisten = await listen<ScanResult>("scan:completed", (event) => {
      set({ lastScan: event.payload });
      get().refreshHistory();
    });
    return unlisten;
  },
}));
