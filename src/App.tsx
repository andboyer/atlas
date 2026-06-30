import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  LayoutDashboard,
  Network,
  Radio,
  History,
  Download,
  Settings as SettingsIcon,
  Wrench,
  Bell,
  Waves,
  Stethoscope,
  Server,
  ScanSearch,
} from "lucide-react";
import { StatusCard } from "./components/StatusCard";
import { KpiRow } from "./components/KpiRow";
import { Tabs } from "./components/Tabs";
import { NicPicker } from "./components/NicPicker";
import { FindingsList } from "./components/FindingsList";
import { HistoryPanel } from "./components/HistoryPanel";
import { IncidentTimeline } from "./components/IncidentTimeline";
import { ServiceStatus } from "./components/ServiceStatus";
import { SettingsPanel } from "./components/SettingsPanel";
import ChannelMap from "./components/ChannelMap";
import { NearbyApTable } from "./components/NearbyApTable";
import AssistantDock from "./components/AssistantDock";
import { AiExplanation } from "./components/AiExplanation";
import { RadioInsights } from "./components/RadioInsights";
import { AvDiagnostics } from "./components/AvDiagnostics";
import { OllamaBanner } from "./components/OllamaBanner";
import UpdateBanner from "./components/UpdateBanner";
import QualityPanel from "./components/QualityPanel";
import PhyEfficiencyBadge from "./components/PhyEfficiencyBadge";
import RoamingPanel from "./components/RoamingPanel";
import RogueApPanel from "./components/RogueApPanel";
import { WanPanel } from "./components/WanPanel";
import { TrendsPanel } from "./components/TrendsPanel";
import { AlternateApBanner } from "./components/AlternateApBanner";
import { LinkDetailsPanel } from "./components/LinkDetailsPanel";
import { NetworkPathPanel } from "./components/NetworkPathPanel";
import { ScanMetaFooter } from "./components/ScanMetaFooter";
import { PermissionsCard } from "./components/PermissionsCard";
import { LiveMetricsChart } from "./components/LiveMetricsChart";
import { NarrativePanel } from "./components/NarrativePanel";
import { StressTestPanel } from "./components/StressTestPanel";
import { WifiEventsTimeline } from "./components/WifiEventsTimeline";
import { RunbooksPanel } from "./components/RunbooksPanel";
import HostInventoryPanel from "./components/HostInventoryPanel";
import AuditLogPanel from "./components/AuditLogPanel";
import SkillPackBrowser from "./components/SkillPackBrowser";
import RunbookEditor from "./components/RunbookEditor";
import ApprovalModal from "./components/ApprovalModal";
import IpScannerPanel from "./components/IpScannerPanel";
import { useApp } from "./store";

/** Top-level workspace groups. Each bundles related panels under a sub-nav so
 *  the surface is ~5 destinations instead of a 12-tab strip. */
type GroupId = "home" | "wifi" | "network" | "avfleet" | "activity";

/** Legacy single-tab ids still used by cross-panel navigation requests
 *  (store.requestedTab). Mapped onto the new (group, sub) structure. */
const LEGACY_TAB_MAP: Record<string, { group: GroupId; sub: string }> = {
  overview: { group: "home", sub: "summary" },
  alerts: { group: "home", sub: "findings" },
  network: { group: "network", sub: "health" },
  airspace: { group: "wifi", sub: "airspace" },
  av: { group: "avfleet", sub: "av" },
  runbooks: { group: "avfleet", sub: "runbooks" },
  fleet: { group: "avfleet", sub: "fleet" },
  devices: { group: "network", sub: "devices" },
  scanner: { group: "network", sub: "devices" },
  activity: { group: "activity", sub: "timeline" },
  tools: { group: "activity", sub: "tools" },
  assistant: { group: "home", sub: "summary" },
};

/** Default sub-tab for each group, used when first entering it. */
const DEFAULT_SUB: Record<GroupId, string> = {
  home: "summary",
  wifi: "airspace",
  network: "health",
  avfleet: "av",
  activity: "timeline",
};

function SubNav({
  items,
  active,
  onChange,
}: {
  items: { id: string; label: string; badge?: number }[];
  active: string;
  onChange: (id: string) => void;
}) {
  return (
    <div className="mb-5 flex flex-wrap items-center gap-1">
      {items.map((it) => {
        const on = it.id === active;
        return (
          <button
            key={it.id}
            onClick={() => onChange(it.id)}
            className={[
              "rounded-lg px-3 py-1.5 text-xs font-medium transition-colors",
              on
                ? "bg-[var(--color-panel-2)] text-[var(--color-text)]"
                : "text-[var(--color-muted)] hover:text-[var(--color-text)]",
            ].join(" ")}
          >
            {it.label}
            {typeof it.badge === "number" && it.badge > 0 && (
              <span className="ml-1.5 rounded-full bg-[var(--color-accent)]/20 px-1.5 py-0.5 text-[10px] font-semibold text-[var(--color-accent)]">
                {it.badge}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}

function SectionHeading({
  children,
  icon,
}: {
  children: React.ReactNode;
  icon?: React.ReactNode;
}) {
  return (
    <div className="mb-3 flex items-center gap-3">
      <h2 className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.18em] text-[var(--color-muted)]">
        {icon && (
          <span className="text-[var(--color-accent)]" aria-hidden>
            {icon}
          </span>
        )}
        {children}
      </h2>
      <span className="atlas-section-rule" />
    </div>
  );
}

function App() {
  const monitoring = useApp((s) => s.monitoring);
  const lastScan = useApp((s) => s.lastScan);
  const loadSettings = useApp((s) => s.loadSettings);
  const subscribeToScanEvents = useApp((s) => s.subscribeToScanEvents);
  const subscribeToLiveMetrics = useApp((s) => s.subscribeToLiveMetrics);
  const loadInitialLiveMetrics = useApp((s) => s.loadInitialLiveMetrics);
  const subscribeToWifiEvents = useApp((s) => s.subscribeToWifiEvents);
  const loadInitialWifiEvents = useApp((s) => s.loadInitialWifiEvents);
  const subscribeToNarratives = useApp((s) => s.subscribeToNarratives);
  const loadInitialNarratives = useApp((s) => s.loadInitialNarratives);
  const subscribeToStressEvents = useApp((s) => s.subscribeToStressEvents);
  const loadStressTestList = useApp((s) => s.loadStressTestList);
  const bootstrapMonitor = useApp((s) => s.bootstrapMonitor);
  const findingsCount = useApp((s) => s.lastScan?.findings?.length ?? 0);
  const devicesCount = useApp((s) => s.lastScan?.devices?.length ?? 0);

  const [showSettings, setShowSettings] = useState(false);
  const [activeGroup, setActiveGroup] = useState<GroupId>("home");
  // Remember the last sub-tab visited within each group so switching groups
  // and coming back restores where you were.
  const [subByGroup, setSubByGroup] = useState<Record<GroupId, string>>(DEFAULT_SUB);
  const activeSub = subByGroup[activeGroup];
  const dockCollapsed = useApp((s) => s.assistantDockCollapsed);
  const [exporting, setExporting] = useState(false);

  const navigate = (group: GroupId, sub?: string) => {
    setActiveGroup(group);
    if (sub) setSubByGroup((prev) => ({ ...prev, [group]: sub }));
  };
  const setActiveSub = (sub: string) =>
    setSubByGroup((prev) => ({ ...prev, [activeGroup]: sub }));

  // Cross-tab navigation: other panels (e.g. AV "Diagnose with…") request a
  // tab switch via the store. Apply it here, then clear the request.
  const requestedTab = useApp((s) => s.requestedTab);
  const clearRequestedTab = useApp((s) => s.clearRequestedTab);
  useEffect(() => {
    if (requestedTab) {
      const mapped = LEGACY_TAB_MAP[requestedTab];
      if (mapped) navigate(mapped.group, mapped.sub);
      clearRequestedTab();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [requestedTab, clearRequestedTab]);

  // Surface chat-agent device tool calls as transient transcript steps.
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    listen<{
      tool?: string;
      host?: string | null;
      cmd?: string | null;
      result?: { error?: string; verdict?: string } | null;
    }>("chat-agent-step", (ev) => {
      const { host, cmd, result } = ev.payload ?? {};
      let line: string;
      if (result?.error) {
        line = `device ${cmd ?? "exec"} on ${host ?? "?"} failed: ${result.error}`;
      } else if (result?.verdict && result.verdict !== "ok") {
        line = `device ${cmd ?? "exec"} on ${host ?? "?"} → ${result.verdict}`;
      } else {
        line = `Ran ${cmd ?? "command"} on ${host ?? "device"}`;
      }
      useApp.getState().appendChatStep(line);
    }).then((fn) => {
      unlisten = fn;
    });
    return () => unlisten?.();
  }, []);

  useEffect(() => {
    loadSettings();
    let unsub: (() => void) | undefined;
    let unsubTicks: (() => void) | undefined;
    let unsubWifi: (() => void) | undefined;
    let unsubNarr: (() => void) | undefined;
    let unsubStress: (() => void) | undefined;
    subscribeToScanEvents().then((fn) => {
      unsub = fn;
    });
    subscribeToLiveMetrics().then((fn) => {
      unsubTicks = fn;
    });
    subscribeToWifiEvents().then((fn) => {
      unsubWifi = fn;
    });
    subscribeToNarratives().then((fn) => {
      unsubNarr = fn;
    });
    subscribeToStressEvents().then((fn) => {
      unsubStress = fn;
    });
    // Auto-start live scanning (default is on) and run an immediate first
    // scan so the dashboard has data within ~seconds of launch instead of
    // waiting for the first interval tick.
    (async () => {
      try {
        await bootstrapMonitor();
        // Seed the live chart from whatever the backend ring already holds
        // (typically empty on cold start, but populated after a soft reload).
        loadInitialLiveMetrics().catch(() => {});
        loadInitialWifiEvents().catch(() => {});
        loadInitialNarratives().catch(() => {});
        loadStressTestList().catch(() => {});
        const st = useApp.getState();
        if (!st.lastScan && !st.scanning) {
          st.runQuickScan().catch(() => {});
        }
      } catch (e) {
        console.warn("bootstrap monitor failed:", e);
      }
    })();
    return () => {
      unsub?.();
      unsubTicks?.();
      unsubWifi?.();
      unsubNarr?.();
      unsubStress?.();
    };
  }, []);

  const handleExport = async () => {
    if (!lastScan) return;
    setExporting(true);
    try {
      const html = await invoke<string>("export_report", {
        runId: lastScan.run_id,
      });
      const blob = new Blob([html], { type: "text/html" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `wifi-report-${lastScan.run_id.slice(0, 8)}.html`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      console.error("export failed", e);
    } finally {
      setExporting(false);
    }
  };

  // Primary navigation: five groups, each with its own sub-tabs. Badges
  // surface live counts on the group and the relevant sub.
  const NAV: {
    id: GroupId;
    label: string;
    icon: React.ReactNode;
    badge?: number;
    subs: { id: string; label: string; badge?: number }[];
  }[] = [
    {
      id: "home",
      label: "Overview",
      icon: <LayoutDashboard className="h-4 w-4" />,
      badge: findingsCount,
      subs: [
        { id: "summary", label: "Summary" },
        { id: "findings", label: "Findings", badge: findingsCount },
      ],
    },
    {
      id: "wifi",
      label: "Wi-Fi",
      icon: <Radio className="h-4 w-4" />,
      subs: [
        { id: "airspace", label: "Airspace" },
        { id: "link", label: "Link & radio" },
      ],
    },
    {
      id: "network",
      label: "Network",
      icon: <Network className="h-4 w-4" />,
      badge: devicesCount,
      subs: [
        { id: "health", label: "Path & WAN" },
        { id: "devices", label: "Devices", badge: devicesCount },
      ],
    },
    {
      id: "avfleet",
      label: "AV & Fleet",
      icon: <Waves className="h-4 w-4" />,
      subs: [
        { id: "av", label: "AV / Multicast" },
        { id: "runbooks", label: "Runbooks" },
        { id: "fleet", label: "Fleet" },
      ],
    },
    {
      id: "activity",
      label: "Activity",
      icon: <History className="h-4 w-4" />,
      subs: [
        { id: "timeline", label: "Timeline" },
        { id: "history", label: "History" },
        { id: "tools", label: "Stress tests" },
      ],
    },
  ];

  const currentGroup = NAV.find((g) => g.id === activeGroup) ?? NAV[0];

  return (
    <div className="min-h-screen">
      <UpdateBanner />
      <OllamaBanner onOpenSettings={() => setShowSettings(true)} />
      <header className="sticky top-0 z-30 border-b border-[var(--color-border)] bg-[var(--color-bg)]/85 backdrop-blur">
        <div className="mx-auto flex max-w-[1600px] items-center justify-between gap-3 px-8 py-4">
          <div className="flex items-center gap-3">
            <div className="atlas-brand-chip flex h-11 w-11 items-center justify-center rounded-xl">
              <img
                src="/atlas-mark.svg"
                alt=""
                className="h-9 w-9 select-none"
                draggable={false}
              />
            </div>
            <div className="leading-tight">
              <h1 className="text-base font-semibold tracking-[0.32em] text-[var(--color-accent)]">
                ATLAS
              </h1>
              <p className="text-[10px] uppercase tracking-[0.22em] text-[var(--color-muted)]">
                Map your network
              </p>
            </div>
            {monitoring && (
              <span className="ml-3 inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-1 text-[11px] font-medium text-emerald-300">
                <span className="atlas-pulse h-1.5 w-1.5 rounded-full bg-emerald-400 text-emerald-400" />
                Live
              </span>
            )}
          </div>
          <div className="flex items-center gap-3">
            <NicPicker />
            {lastScan && (
              <button
                onClick={handleExport}
                disabled={exporting}
                className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)]/80 px-3 py-1.5 text-xs font-medium text-[var(--color-muted)] transition-colors hover:border-[var(--color-accent)]/40 hover:text-[var(--color-text)] disabled:opacity-50"
                title="Export HTML report"
              >
                <Download className="h-3.5 w-3.5" />
                {exporting ? "Exporting…" : "Export"}
              </button>
            )}
            <button
              onClick={() => setShowSettings(true)}
              className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)]/80 px-3 py-1.5 text-xs font-medium text-[var(--color-muted)] transition-colors hover:border-[var(--color-accent)]/40 hover:text-[var(--color-text)]"
              title="Settings"
            >
              <SettingsIcon className="h-3.5 w-3.5" />
              Settings
            </button>
          </div>
        </div>
        <div className="atlas-hairline" aria-hidden />
      </header>

      <main className="mx-auto max-w-[1600px] px-6 py-6">
        <div className="flex gap-6">
          {/* Left: workspace content */}
          <div className="min-w-0 flex-1">
            {/* === Above-fold: alerts → identity → KPIs. Keep this short. === */}
            <div className="space-y-4">
              {lastScan?.captive_portal && (
                <div className="flex items-center gap-3 rounded-xl border border-yellow-500/40 bg-yellow-500/10 px-5 py-3 text-sm text-yellow-200">
                  <span className="text-lg">⚠</span>
                  <div>
                    <strong>Captive portal detected.</strong> Your traffic is
                    being intercepted by a login page (hotel, café, or corporate
                    network). Browse to any http:// page to authenticate.
                  </div>
                </div>
              )}

              <AlternateApBanner />
              <PermissionsCard />
              <StatusCard />
              <KpiRow />
            </div>

            {/* === Primary group nav === */}
            <div className="mt-6">
              <Tabs
                tabs={NAV.map((g) => ({
                  id: g.id,
                  label: g.label,
                  icon: g.icon,
                  badge: g.badge,
                }))}
                active={activeGroup}
                onChange={(id) => navigate(id as GroupId)}
              />

              {/* === Secondary sub-nav for the active group === */}
              <div className="mt-5">
                <SubNav
                  items={currentGroup.subs}
                  active={activeSub}
                  onChange={setActiveSub}
                />
              </div>

              <div className="space-y-6">
                {/* ── Overview ─────────────────────────────────────────── */}
                {activeGroup === "home" && activeSub === "summary" && (
                  <>
                    <LiveMetricsChart />
                    <AiExplanation />
                    {lastScan && <QualityPanel quality={lastScan.quality} />}
                    <TrendsPanel />
                  </>
                )}
                {activeGroup === "home" && activeSub === "findings" && (
                  <>
                    <section>
                      <SectionHeading icon={<Bell className="h-3.5 w-3.5" />}>
                        Findings &amp; recommendations
                      </SectionHeading>
                      <FindingsList />
                    </section>
                    <NarrativePanel />
                  </>
                )}

                {/* ── Wi-Fi ────────────────────────────────────────────── */}
                {activeGroup === "wifi" && activeSub === "airspace" && (
                  <>
                    <section>
                      <ChannelMap
                        nearbyAps={lastScan?.nearby_aps ?? []}
                        ownChannel={lastScan?.link.channel ?? null}
                        ownBssid={lastScan?.link.bssid ?? null}
                        interference={lastScan?.interference ?? null}
                      />
                    </section>
                    <section>
                      <NearbyApTable
                        aps={lastScan?.nearby_aps ?? []}
                        ownBssid={lastScan?.link.bssid ?? null}
                        ownSsid={lastScan?.link.ssid ?? null}
                      />
                    </section>
                    {lastScan && <RoamingPanel roaming={lastScan.roaming} />}
                    {lastScan && <RogueApPanel findings={lastScan.rogue_aps} />}
                  </>
                )}
                {activeGroup === "wifi" && activeSub === "link" && (
                  <>
                    {lastScan && <LinkDetailsPanel link={lastScan.link} />}
                    {lastScan && (
                      <PhyEfficiencyBadge phy={lastScan.phy_efficiency} />
                    )}
                    <RadioInsights />
                  </>
                )}

                {/* ── Network ──────────────────────────────────────────── */}
                {activeGroup === "network" && activeSub === "health" && (
                  <>
                    {lastScan && (
                      <NetworkPathPanel
                        reachability={lastScan.reachability}
                        mtuBytes={lastScan.mtu_bytes}
                        dnsLeak={lastScan.dns_leak}
                        captivePortal={lastScan.captive_portal}
                      />
                    )}
                    <WanPanel />
                    <section>
                      <SectionHeading icon={<Network className="h-3.5 w-3.5" />}>
                        Service reachability
                      </SectionHeading>
                      <ServiceStatus />
                    </section>
                  </>
                )}
                {activeGroup === "network" && activeSub === "devices" && (
                  <section>
                    <SectionHeading icon={<ScanSearch className="h-3.5 w-3.5" />}>
                      Devices on this network
                    </SectionHeading>
                    <IpScannerPanel />
                  </section>
                )}

                {/* ── AV & Fleet ───────────────────────────────────────── */}
                {activeGroup === "avfleet" && activeSub === "av" && (
                  <AvDiagnostics />
                )}
                {activeGroup === "avfleet" && activeSub === "runbooks" && (
                  <section>
                    <SectionHeading
                      icon={<Stethoscope className="h-3.5 w-3.5" />}
                    >
                      Runbooks
                    </SectionHeading>
                    <RunbooksPanel />
                  </section>
                )}
                {activeGroup === "avfleet" && activeSub === "fleet" && (
                  <div className="space-y-8">
                    <section>
                      <SectionHeading icon={<Server className="h-3.5 w-3.5" />}>
                        Host inventory
                      </SectionHeading>
                      <HostInventoryPanel />
                    </section>
                    <SkillPackBrowser />
                    <RunbookEditor />
                    <AuditLogPanel />
                  </div>
                )}

                {/* ── Activity ─────────────────────────────────────────── */}
                {activeGroup === "activity" && activeSub === "timeline" && (
                  <>
                    <section>
                      <SectionHeading icon={<History className="h-3.5 w-3.5" />}>
                        Incident timeline
                      </SectionHeading>
                      <IncidentTimeline />
                    </section>
                    <WifiEventsTimeline />
                  </>
                )}
                {activeGroup === "activity" && activeSub === "history" && (
                  <section>
                    <SectionHeading icon={<History className="h-3.5 w-3.5" />}>
                      Past scans
                    </SectionHeading>
                    <HistoryPanel />
                  </section>
                )}
                {activeGroup === "activity" && activeSub === "tools" && (
                  <section>
                    <SectionHeading icon={<Wrench className="h-3.5 w-3.5" />}>
                      Stress tests
                    </SectionHeading>
                    <StressTestPanel />
                  </section>
                )}
              </div>
            </div>

            <ScanMetaFooter />
          </div>

          {/* Right: persistent AI dock */}
          <aside
            className={`shrink-0 transition-[width] ${
              dockCollapsed ? "w-12" : "w-[380px]"
            }`}
          >
            <div className="sticky top-[88px] h-[calc(100vh-7rem)]">
              <AssistantDock />
            </div>
          </aside>
        </div>
      </main>

      {showSettings && <SettingsPanel onClose={() => setShowSettings(false)} />}

      <ApprovalModal />
    </div>
  );
}

export default App;
