import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type {
  AvDiagnosticsResult,
  AvInsight,
  DeviceEvent,
  IpScanResult,
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

/** A single turn in the assistant (chat) session. `isError` marks a failed
 *  LLM call so the UI can style it distinctly. */
export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
  isError?: boolean;
  /** Transient progress line emitted by the agent while it runs a device
   *  tool call (e.g. "Ran show_interfaces on core-sw-1"). Rendered muted and
   *  excluded from the history sent back to the model. */
  step?: boolean;
}

/**
 * Recover the JSON object from an LLM reply. Reasoning models (qwen3, QwQ,
 * deepseek-r1) emit a `<think>…</think>` block before the answer — and that
 * block routinely contains its own braces, which broke the naive first-`{` /
 * last-`}` slice and made suggestion generation fail. We strip reasoning
 * blocks and markdown fences first, then take the outermost brace pair.
 */
function extractJsonSlice(raw: string): string | null {
  if (!raw) return null;
  let text = raw.trim();
  // Drop <think>…</think> / <thinking>…</thinking> reasoning blocks.
  text = text
    .replace(/<think>[\s\S]*?<\/think>/gi, "")
    .replace(/<thinking>[\s\S]*?<\/thinking>/gi, "")
    .trim();
  // Strip ```json … ``` or ``` … ``` fences if present.
  if (text.startsWith("```")) {
    text = text
      .replace(/^```(?:json)?\s*/i, "")
      .replace(/```\s*$/i, "")
      .trim();
  }
  // Take the outermost {...} block, ignoring any surrounding prose.
  const first = text.indexOf("{");
  const last = text.lastIndexOf("}");
  if (first === -1 || last === -1 || last <= first) return null;
  return text.slice(first, last + 1);
}

/**
 * Parse the JSON envelope the `radio_insights` backend returns. Tolerates
 * markdown fences and reasoning-model `<think>` preambles via
 * `extractJsonSlice`.
 */
function parseRadioInsights(raw: string): RadioInsight[] | null {
  const slice = extractJsonSlice(raw);
  if (slice === null) return null;
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
  const slice = extractJsonSlice(raw);
  if (slice === null) return null;
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
  preferred_interface: "",
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

  /** Assistant (chat) session — persisted in the store so it survives
   *  navigating away from the panel and lasts until the app is closed. */
  chatMessages: ChatMessage[];
  chatInput: string;
  chatOpen: boolean;
  /** Whether the persistent right-side assistant dock is collapsed. */
  assistantDockCollapsed: boolean;
  setAssistantDockCollapsed: (collapsed: boolean) => void;
  /** True while a chat_query is in flight. Lives in the store so the request
   *  keeps running (and the result still lands) when the panel unmounts. */
  chatLoading: boolean;
  setChatMessages: (updater: ChatMessage[] | ((prev: ChatMessage[]) => ChatMessage[])) => void;
  setChatInput: (value: string) => void;
  setChatOpen: (open: boolean) => void;
  clearChat: () => void;
  /** Append a transient agent progress step while a turn is in flight. */
  appendChatStep: (content: string) => void;
  /** Send a question to the LLM. Runs to completion independent of the panel
   *  being mounted, so tabbing away never aborts an in-flight request. */
  sendChat: (scanResult: ScanResult, question: string) => Promise<void>;

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

  // ── Cross-tab navigation ──
  /** When set, App switches to this tab on the next render, then clears it. */
  requestedTab: string | null;
  /** Runbook id the Runbooks panel should pre-select when it mounts/updates. */
  pendingRunbookId: string | null;
  /** Jump to the Runbooks tab with `id` pre-selected (one-click "Diagnose"). */
  openRunbook: (id: string) => void;
  clearRequestedTab: () => void;
  clearPendingRunbook: () => void;
  /** Host fields to pre-fill the Fleet "Add host" form (from the IP Scanner). */
  prefillHost: { hostname: string; alias?: string } | null;
  /** Jump to the Fleet tab with the add-host form pre-filled. */
  addHostToFleet: (host: { hostname: string; alias?: string }) => void;
  clearPrefillHost: () => void;

  // ── IP Scanner (persisted across tab switches) ──
  /** Last subnet sweep result, kept in the store so it survives unmounts. */
  ipScanResult: IpScanResult | null;
  /** CIDR currently shown in the IP Scanner input. */
  ipScanCidr: string;
  /** True while a sweep is in flight. */
  ipScanLoading: boolean;
  /** Last sweep error, if any. */
  ipScanError: string | null;
  setIpScanCidr: (cidr: string) => void;
  runSubnetScan: (cidr?: string | null) => Promise<void>;
}

export const useApp = create<AppState>((set, get) => ({
  scanning: false,
  lastScan: null,
  error: null,

  requestedTab: null,
  pendingRunbookId: null,
  openRunbook: (id: string) =>
    set({ pendingRunbookId: id, requestedTab: "runbooks" }),
  clearRequestedTab: () => set({ requestedTab: null }),
  clearPendingRunbook: () => set({ pendingRunbookId: null }),
  prefillHost: null,
  addHostToFleet: (host) => set({ prefillHost: host, requestedTab: "fleet" }),
  clearPrefillHost: () => set({ prefillHost: null }),

  ipScanResult: null,
  ipScanCidr: "",
  ipScanLoading: false,
  ipScanError: null,
  setIpScanCidr: (cidr: string) => set({ ipScanCidr: cidr }),
  runSubnetScan: async (cidr?: string | null) => {
    if (get().ipScanLoading) return;
    set({ ipScanLoading: true, ipScanError: null });
    try {
      const res = await invoke<IpScanResult>("scan_subnet", {
        cidr: (cidr ?? get().ipScanCidr).trim() || null,
      });
      set({ ipScanResult: res, ipScanCidr: res.cidr });
    } catch (e) {
      set({ ipScanError: String(e) });
    } finally {
      set({ ipScanLoading: false });
    }
  },

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

  chatMessages: [],
  chatInput: "",
  chatOpen: false,
  assistantDockCollapsed: false,
  setAssistantDockCollapsed: (collapsed) =>
    set({ assistantDockCollapsed: collapsed }),
  chatLoading: false,
  setChatMessages: (updater) =>
    set((s) => ({
      chatMessages:
        typeof updater === "function" ? updater(s.chatMessages) : updater,
    })),
  setChatInput: (value) => set({ chatInput: value }),
  setChatOpen: (open) => set({ chatOpen: open }),
  clearChat: () => set({ chatMessages: [], chatInput: "" }),
  appendChatStep: (content) =>
    set((s) =>
      s.chatLoading
        ? {
            chatMessages: [
              ...s.chatMessages,
              { role: "assistant", content, step: true },
            ],
          }
        : {},
    ),
  sendChat: async (scanResult, question) => {
    if (get().chatLoading) return;
    const history = get().chatMessages;
    // Strip transient agent step lines — only real user/assistant turns are
    // sent back to the model as conversation history.
    const cleanHistory = history.filter((m) => !m.step);
    const withQuestion: ChatMessage[] = [
      ...history,
      { role: "user", content: question },
    ];
    set({ chatMessages: withQuestion, chatInput: "", chatLoading: true });
    try {
      const answer = await invoke<string>("chat_agent", {
        scanResult,
        history: cleanHistory, // history before the new question
        question,
      });
      set((s) => ({
        chatMessages: [...s.chatMessages, { role: "assistant", content: answer }],
        chatLoading: false,
      }));
    } catch (e) {
      set((s) => ({
        chatMessages: [
          ...s.chatMessages,
          { role: "assistant", content: String(e), isError: true },
        ],
        chatLoading: false,
      }));
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
      const iface = (get().settings.preferred_interface || "").trim();
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
      const iface = (get().settings.preferred_interface || "").trim();
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
          stp: null,
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
          stp: deep.stp ?? prior.stp,
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
