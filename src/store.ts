import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type {
  AvDiagnosticsResult,
  AvInsight,
  DeviceEvent,
  LiveSample,
  Narrative,
  RadioInsight,
  ScanResult,
  ScanSummary,
  Settings,
  StressSample,
  StressTestDescriptor,
  StressTestResult,
  WifiEvent,
} from "./types";

const LIVE_RING_CAPACITY = 3600; // 60 min @ 1 Hz, matches backend.
const WIFI_EVENTS_CAPACITY = 500; // matches backend ring.
const NARRATIVES_CAPACITY = 50; // matches backend ring.

/**
 * Parse the JSON envelope the `radio_insights` backend returns. Models
 * occasionally wrap the JSON in ```json fences despite our "strict JSON"
 * prompt, so we strip common fences and try to recover the first/last brace
 * pair before giving up.
 */
function parseRadioInsights(raw: string): RadioInsight[] | null {
  if (!raw) return null;
  let text = raw.trim();
  // Strip ```json … ``` or ``` … ``` fences if present.
  if (text.startsWith("```")) {
    text = text.replace(/^```(?:json)?\s*/i, "").replace(/```\s*$/i, "").trim();
  }
  // Fall back to the outermost {...} block if there's surrounding prose.
  const first = text.indexOf("{");
  const last = text.lastIndexOf("}");
  if (first === -1 || last === -1 || last <= first) return null;
  const slice = text.slice(first, last + 1);
  try {
    const obj = JSON.parse(slice);
    if (!obj || !Array.isArray(obj.items)) return null;
    const items: RadioInsight[] = [];
    for (const it of obj.items) {
      if (!it || typeof it !== "object") continue;
      const sev = String(it.severity ?? "info").toLowerCase();
      const severity =
        sev === "critical" || sev === "warn" || sev === "info" ? sev : "info";
      items.push({
        severity: severity as RadioInsight["severity"],
        title: String(it.title ?? "").trim() || "Untitled",
        detail: String(it.detail ?? "").trim(),
        suggestion: String(it.suggestion ?? "").trim(),
      });
    }
    return items;
  } catch {
    return null;
  }
}

/**
 * Parse the JSON envelope the `av_insights` backend returns. Same shape as
 * `parseRadioInsights` plus a `category` field; unrecognised category values
 * are coerced to "general".
 */
function parseAvInsights(raw: string): AvInsight[] | null {
  if (!raw) return null;
  let text = raw.trim();
  if (text.startsWith("```")) {
    text = text.replace(/^```(?:json)?\s*/i, "").replace(/```\s*$/i, "").trim();
  }
  const first = text.indexOf("{");
  const last = text.lastIndexOf("}");
  if (first === -1 || last === -1 || last <= first) return null;
  const slice = text.slice(first, last + 1);
  try {
    const obj = JSON.parse(slice);
    if (!obj || !Array.isArray(obj.items)) return null;
    const items: AvInsight[] = [];
    const allowedCat = new Set(["dante", "multicast", "ptp", "wifi", "qos", "general"]);
    for (const it of obj.items) {
      if (!it || typeof it !== "object") continue;
      const sev = String(it.severity ?? "info").toLowerCase();
      const severity =
        sev === "critical" || sev === "warn" || sev === "info" ? sev : "info";
      const catRaw = String(it.category ?? "general").toLowerCase();
      const category = allowedCat.has(catRaw) ? catRaw : "general";
      items.push({
        severity: severity as AvInsight["severity"],
        category: category as AvInsight["category"],
        title: String(it.title ?? "").trim() || "Untitled",
        detail: String(it.detail ?? "").trim(),
        suggestion: String(it.suggestion ?? "").trim(),
      });
    }
    return items;
  } catch {
    return null;
  }
}

const DEFAULT_SETTINGS: Settings = {
  scan_interval_secs: 15,
  monitoring_enabled: true,
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
  preferred_av_interface: "",
};

interface MonitorStatus {
  running: boolean;
  interval_secs: number;
}

interface AppState {
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
  intervalSecs: number;
  bootstrapMonitor: () => Promise<void>;
  startMonitoring: () => Promise<void>;
  stopMonitoring: () => Promise<void>;
  refreshMonitorStatus: () => Promise<void>;

  explanation: string | null;
  explaining: boolean;
  explainFindings: () => Promise<void>;

  /** Structured radio-only suggestions from the LLM (parsed from the
   *  `radio_insights` command's JSON response). */
  radioInsights: RadioInsight[] | null;
  radioInsightsLoading: boolean;
  radioInsightsError: string | null;
  loadRadioInsights: () => Promise<void>;

  /** Snapshot of unprivileged AV-over-IP diagnostics: Dante mDNS browse,
   *  per-interface multicast joins, TCP reachability, heuristic warnings. */
  avDiagnostics: AvDiagnosticsResult | null;
  avDiagnosticsLoading: boolean;
  avDiagnosticsError: string | null;
  loadAvDiagnostics: () => Promise<void>;
  /** Privileged IGMP querier listen (re-execs current binary via osascript). */
  runDeepProbe: (kind: string) => Promise<void>;
  deepProbeRunning: boolean;
  deepProbeError: string | null;

  /** LLM-generated structured AV suggestions parsed from `av_insights`. */
  avInsights: AvInsight[] | null;
  avInsightsLoading: boolean;
  avInsightsError: string | null;
  loadAvInsights: () => Promise<void>;

  /** Rolling 60-min ring of 1 Hz live samples (newest at the end). */
  liveSamples: LiveSample[];
  loadInitialLiveMetrics: () => Promise<void>;
  subscribeToLiveMetrics: () => Promise<() => void>;

  // ── Wi-Fi system events (Play C) ──
  wifiEvents: WifiEvent[];
  loadInitialWifiEvents: () => Promise<void>;
  subscribeToWifiEvents: () => Promise<() => void>;

  // ── Causal narratives (Play D) ──
  narratives: Narrative[];
  loadInitialNarratives: () => Promise<void>;
  subscribeToNarratives: () => Promise<() => void>;

  // ── Active stress tests (Play B) ──
  availableStressTests: StressTestDescriptor[];
  loadStressTestList: () => Promise<void>;
  stressResults: StressTestResult[];
  runningStressKind: string | null;
  liveStressSamples: StressSample[];
  runStressTest: (kind: string) => Promise<void>;
  subscribeToStressEvents: () => Promise<() => void>;

  runQuickScan: () => Promise<void>;
  refreshHistory: () => Promise<void>;
  subscribeToScanEvents: () => Promise<() => void>;
}

export const useApp = create<AppState>((set, get) => ({
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
  intervalSecs: 15,
  refreshMonitorStatus: async () => {
    try {
      const s = await invoke<MonitorStatus>("get_monitor_status");
      set({ monitoring: s.running, intervalSecs: s.interval_secs });
    } catch (e) {
      console.warn("failed to read monitor status:", e);
    }
  },
  bootstrapMonitor: async () => {
    // Sync the in-memory monitoring flag with what the backend is actually
    // doing. The backend auto-starts monitoring at launch when
    // settings.monitoring_enabled is true (the live-scan default), so this
    // typically returns running=true on first read.
    await get().refreshMonitorStatus();
    if (!get().monitoring && get().settings.monitoring_enabled) {
      // Settings say monitoring should be on but the backend isn't running it
      // — start it now. Happens after a fresh install hits the live-scan
      // default, or after the user toggled monitoring in settings and the
      // backend didn't autostart.
      try {
        await get().startMonitoring();
      } catch (e) {
        console.warn("failed to auto-start monitoring:", e);
      }
    }
  },
  startMonitoring: async () => {
    await invoke("start_monitoring");
    set({ monitoring: true });
    // Persist the monitoring flag.
    const s = get().settings;
    await get().saveSettings({ ...s, monitoring_enabled: true });
    await get().refreshMonitorStatus();
  },
  stopMonitoring: async () => {
    await invoke("stop_monitoring");
    set({ monitoring: false });
    const s = get().settings;
    await get().saveSettings({ ...s, monitoring_enabled: false });
    await get().refreshMonitorStatus();
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

  radioInsights: null,
  radioInsightsLoading: false,
  radioInsightsError: null,
  loadRadioInsights: async () => {
    const scan = get().lastScan;
    if (!scan) return;
    set({ radioInsightsLoading: true, radioInsightsError: null });
    try {
      const raw = await invoke<string>("radio_insights", { scanResult: scan });
      const parsed = parseRadioInsights(raw);
      if (parsed) {
        set({ radioInsights: parsed, radioInsightsLoading: false });
      } else {
        set({
          radioInsightsLoading: false,
          radioInsightsError:
            "The model returned a response we couldn't parse. Try again.",
        });
      }
    } catch (e) {
      set({
        radioInsightsLoading: false,
        radioInsightsError: String(e),
      });
    }
  },

  avDiagnostics: null,
  avDiagnosticsLoading: false,
  avDiagnosticsError: null,
  loadAvDiagnostics: async () => {
    set({ avDiagnosticsLoading: true, avDiagnosticsError: null });
    try {
      const iface = (get().settings.preferred_av_interface || "").trim();
      const result = await invoke<AvDiagnosticsResult>("run_av_diagnostics", {
        lastScan: get().lastScan,
        iface: iface || null,
      });
      set({ avDiagnostics: result, avDiagnosticsLoading: false });
    } catch (e) {
      set({ avDiagnosticsLoading: false, avDiagnosticsError: String(e) });
    }
  },
  deepProbeRunning: false,
  deepProbeError: null,
  runDeepProbe: async (kind: string) => {
    set({ deepProbeRunning: true, deepProbeError: null });
    try {
      const iface = (get().settings.preferred_av_interface || "").trim();
      const deep = await invoke<import("./types").DeepProbeResult>(
        "run_deep_probes",
        { kind, iface: iface || null },
      );
      const current = get().avDiagnostics;
      if (current) {
        const prior = current.deep_probe ?? {
          ran_at: deep.ran_at,
          igmp: null,
          ptp: null,
          dscp: null,
          lldp: null,
          link_audit: null,
          sap: null,
        };
        // Merge: keep prior fields, overlay any populated fields from
        // this probe, always bump ran_at. The backend ships
        // DeepProbeResult instances with one populated field per probe
        // kind (or several when kind is "all"); merging lets us
        // accumulate results across separate probe runs.
        const merged: import("./types").DeepProbeResult = {
          ran_at: deep.ran_at,
          igmp: deep.igmp ?? prior.igmp,
          ptp: deep.ptp ?? prior.ptp,
          dscp: deep.dscp ?? prior.dscp,
          lldp: deep.lldp ?? prior.lldp,
          link_audit: deep.link_audit ?? prior.link_audit,
          sap: deep.sap ?? prior.sap,
        };
        set({ avDiagnostics: { ...current, deep_probe: merged } });
      }
      set({ deepProbeRunning: false });
    } catch (e) {
      set({ deepProbeRunning: false, deepProbeError: String(e) });
    }
  },

  avInsights: null,
  avInsightsLoading: false,
  avInsightsError: null,
  loadAvInsights: async () => {
    const av = get().avDiagnostics;
    if (!av) return;
    set({ avInsightsLoading: true, avInsightsError: null });
    try {
      const raw = await invoke<string>("av_insights", {
        av,
        scanResult: get().lastScan,
      });
      const parsed = parseAvInsights(raw);
      if (parsed) {
        set({ avInsights: parsed, avInsightsLoading: false });
      } else {
        set({
          avInsightsLoading: false,
          avInsightsError:
            "The model returned a response we couldn't parse. Try again.",
        });
      }
    } catch (e) {
      set({ avInsightsLoading: false, avInsightsError: String(e) });
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

  liveSamples: [],
  loadInitialLiveMetrics: async () => {
    try {
      const samples = await invoke<LiveSample[]>("get_live_metrics");
      // Keep the trailing LIVE_RING_CAPACITY in case the backend ever grows
      // its ring without us noticing.
      const trimmed =
        samples.length > LIVE_RING_CAPACITY
          ? samples.slice(samples.length - LIVE_RING_CAPACITY)
          : samples;
      set({ liveSamples: trimmed });
    } catch (e) {
      console.warn("live metrics hydrate failed:", e);
    }
  },
  subscribeToLiveMetrics: async () => {
    const unlisten = await listen<LiveSample>("metric:tick", (event) => {
      const next = [...get().liveSamples, event.payload];
      if (next.length > LIVE_RING_CAPACITY) {
        next.splice(0, next.length - LIVE_RING_CAPACITY);
      }
      set({ liveSamples: next });
    });
    return unlisten;
  },

  // ── Wi-Fi system events ──────────────────────────────────────────────
  wifiEvents: [],
  loadInitialWifiEvents: async () => {
    try {
      const events = await invoke<WifiEvent[]>("get_wifi_events");
      const trimmed =
        events.length > WIFI_EVENTS_CAPACITY
          ? events.slice(events.length - WIFI_EVENTS_CAPACITY)
          : events;
      set({ wifiEvents: trimmed });
    } catch (e) {
      console.warn("wifi events hydrate failed:", e);
    }
  },
  subscribeToWifiEvents: async () => {
    const unlisten = await listen<WifiEvent>("wifi:event", (event) => {
      const next = [...get().wifiEvents, event.payload];
      if (next.length > WIFI_EVENTS_CAPACITY) {
        next.splice(0, next.length - WIFI_EVENTS_CAPACITY);
      }
      set({ wifiEvents: next });
    });
    return unlisten;
  },

  // ── Causal narratives ────────────────────────────────────────────────
  narratives: [],
  loadInitialNarratives: async () => {
    try {
      const items = await invoke<Narrative[]>("get_narratives");
      const trimmed =
        items.length > NARRATIVES_CAPACITY
          ? items.slice(items.length - NARRATIVES_CAPACITY)
          : items;
      set({ narratives: trimmed });
    } catch (e) {
      console.warn("narratives hydrate failed:", e);
    }
  },
  subscribeToNarratives: async () => {
    const unNew = await listen<Narrative>("narrative:new", (event) => {
      const next = [...get().narratives, event.payload];
      if (next.length > NARRATIVES_CAPACITY) {
        next.splice(0, next.length - NARRATIVES_CAPACITY);
      }
      set({ narratives: next });
    });
    const unUpd = await listen<Narrative>("narrative:update", (event) => {
      const incoming = event.payload;
      const next = get().narratives.map((n) =>
        n.id === incoming.id ? incoming : n
      );
      set({ narratives: next });
    });
    return () => {
      unNew();
      unUpd();
    };
  },

  // ── Active stress tests ──────────────────────────────────────────────
  availableStressTests: [],
  loadStressTestList: async () => {
    try {
      const items = await invoke<StressTestDescriptor[]>("list_stress_tests");
      set({ availableStressTests: items });
    } catch (e) {
      console.warn("stress test list failed:", e);
    }
  },
  stressResults: [],
  runningStressKind: null,
  liveStressSamples: [],
  runStressTest: async (kind: string) => {
    if (get().runningStressKind) return;
    set({ runningStressKind: kind, liveStressSamples: [] });
    try {
      const result = await invoke<StressTestResult>("run_stress_test", { kind });
      set({
        stressResults: [...get().stressResults, result].slice(-20),
        runningStressKind: null,
        liveStressSamples: [],
      });
    } catch (e) {
      console.warn("stress test failed:", e);
      set({ runningStressKind: null, liveStressSamples: [] });
    }
  },
  subscribeToStressEvents: async () => {
    const unTick = await listen<[string, StressSample]>("stress:tick", (event) => {
      const [, sample] = event.payload;
      set({ liveStressSamples: [...get().liveStressSamples, sample] });
    });
    const unDone = await listen<StressTestResult>("stress:complete", () => {
      // The runStressTest() awaiter already commits the final result; this
      // listener is here so other parts of the UI can react if needed.
    });
    return () => {
      unTick();
      unDone();
    };
  },
}));
