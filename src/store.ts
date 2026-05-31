import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";
import type { ScanResult, UserMode } from "./types";

interface AppState {
  mode: UserMode;
  setMode: (m: UserMode) => void;

  scanning: boolean;
  lastScan: ScanResult | null;
  error: string | null;

  runQuickScan: () => Promise<void>;
}

export const useApp = create<AppState>((set) => ({
  mode: "simple",
  setMode: (mode) => set({ mode }),

  scanning: false,
  lastScan: null,
  error: null,

  runQuickScan: async () => {
    set({ scanning: true, error: null });
    try {
      const result = await invoke<ScanResult>("run_quick_scan");
      set({ lastScan: result, scanning: false });
    } catch (e) {
      set({ error: String(e), scanning: false });
    }
  },
}));
