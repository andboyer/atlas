import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";
import type { DeviceEvent, ScanResult, ScanSummary, UserMode } from "./types";

interface AppState {
  mode: UserMode;
  setMode: (m: UserMode) => void;

  scanning: boolean;
  lastScan: ScanResult | null;
  error: string | null;

  recentScans: ScanSummary[];
  recentEvents: DeviceEvent[];

  runQuickScan: () => Promise<void>;
  refreshHistory: () => Promise<void>;
}

export const useApp = create<AppState>((set, get) => ({
  mode: "simple",
  setMode: (mode) => set({ mode }),

  scanning: false,
  lastScan: null,
  error: null,

  recentScans: [],
  recentEvents: [],

  runQuickScan: async () => {
    set({ scanning: true, error: null });
    try {
      const result = await invoke<ScanResult>("run_quick_scan");
      set({ lastScan: result, scanning: false });
      // History changes whenever a new scan is recorded.
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
      // History is non-critical; just log.
      console.warn("history refresh failed:", e);
    }
  },
}));
