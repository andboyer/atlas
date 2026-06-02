import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  LayoutDashboard,
  Network,
  Radio,
  Cpu,
  History,
  MessageSquare,
  Download,
  Settings as SettingsIcon,
  Wrench,
  Bell,
  Waves,
} from "lucide-react";
import { StatusCard } from "./components/StatusCard";
import { KpiRow } from "./components/KpiRow";
import { Tabs } from "./components/Tabs";
import { FindingsList } from "./components/FindingsList";
import { DeviceList } from "./components/DeviceList";
import { HistoryPanel } from "./components/HistoryPanel";
import { IncidentTimeline } from "./components/IncidentTimeline";
import { ServiceStatus } from "./components/ServiceStatus";
import { SettingsPanel } from "./components/SettingsPanel";
import { AvInterfacePicker } from "./components/AvInterfacePicker";
import ChannelMap from "./components/ChannelMap";
import { NearbyApTable } from "./components/NearbyApTable";
import ChatPanel from "./components/ChatPanel";
import { AiExplanation } from "./components/AiExplanation";
import { RadioInsights } from "./components/RadioInsights";
import { AvDiagnostics } from "./components/AvDiagnostics";
import OnboardingWizard from "./components/OnboardingWizard";
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
import { useApp } from "./store";

type TabId =
  | "overview"
  | "alerts"
  | "network"
  | "airspace"
  | "av"
  | "devices"
  | "activity"
  | "tools"
  | "assistant";

function SectionHeading({ children }: { children: React.ReactNode }) {
  return (
    <h2 className="mb-3 text-xs font-semibold uppercase tracking-wider text-[var(--color-muted)]">
      {children}
    </h2>
  );
}

function App() {
  const monitoring = useApp((s) => s.monitoring);
  const lastScan = useApp((s) => s.lastScan);
  const settings = useApp((s) => s.settings);
  const settingsLoaded = useApp((s) => s.settingsLoaded);
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
  const [activeTab, setActiveTab] = useState<TabId>("overview");
  const [exporting, setExporting] = useState(false);

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

  const tabs = [
    {
      id: "overview",
      label: "Overview",
      icon: <LayoutDashboard className="h-4 w-4" />,
    },
    {
      id: "alerts",
      label: "Alerts",
      icon: <Bell className="h-4 w-4" />,
      badge: findingsCount,
    },
    {
      id: "network",
      label: "Network",
      icon: <Network className="h-4 w-4" />,
    },
    {
      id: "airspace",
      label: "Airspace",
      icon: <Radio className="h-4 w-4" />,
    },
    {
      id: "av",
      label: "AV / Multicast",
      icon: <Waves className="h-4 w-4" />,
    },
    {
      id: "devices",
      label: "Devices",
      icon: <Cpu className="h-4 w-4" />,
      badge: devicesCount,
    },
    {
      id: "activity",
      label: "Activity",
      icon: <History className="h-4 w-4" />,
    },
    {
      id: "tools",
      label: "Tools",
      icon: <Wrench className="h-4 w-4" />,
    },
    {
      id: "assistant",
      label: "Assistant",
      icon: <MessageSquare className="h-4 w-4" />,
    },
  ];

  return (
    <div className="min-h-screen">
      <UpdateBanner />
      <header className="sticky top-0 z-30 border-b border-[var(--color-border)] bg-[var(--color-bg)]/85 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between gap-3 px-6 py-3">
          <div className="flex items-center gap-3">
            <img
              src="/atlas-mark.svg"
              alt=""
              className="h-9 w-9 select-none"
              draggable={false}
            />
            <div>
              <h1 className="text-sm font-semibold leading-tight tracking-[0.28em] text-[var(--color-accent)]">
                ATLAS
              </h1>
              <p className="text-[10px] uppercase tracking-[0.18em] text-[var(--color-muted)]">
                Map your network
              </p>
            </div>
            {monitoring && (
              <span className="ml-2 flex items-center gap-1.5 rounded-full bg-emerald-500/15 px-2.5 py-1 text-xs text-emerald-300">
                <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
                monitoring
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            <AvInterfacePicker />
            {lastScan && (
              <button
                onClick={handleExport}
                disabled={exporting}
                className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)] px-3 py-1.5 text-xs text-[var(--color-muted)] transition-colors hover:text-[var(--color-text)] disabled:opacity-50"
                title="Export HTML report"
              >
                <Download className="h-3.5 w-3.5" />
                {exporting ? "Exporting…" : "Export"}
              </button>
            )}
            <button
              onClick={() => setShowSettings(true)}
              className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)] px-3 py-1.5 text-xs text-[var(--color-muted)] transition-colors hover:text-[var(--color-text)]"
              title="Settings"
            >
              <SettingsIcon className="h-3.5 w-3.5" />
              Settings
            </button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-6 py-6">
        {/* === Above-fold: alerts → identity → KPIs → tabs. Keep this short. === */}
        <div className="space-y-4">
          {lastScan?.captive_portal && (
            <div className="flex items-center gap-3 rounded-xl border border-yellow-500/40 bg-yellow-500/10 px-5 py-3 text-sm text-yellow-200">
              <span className="text-lg">⚠</span>
              <div>
                <strong>Captive portal detected.</strong> Your traffic is being
                intercepted by a login page (hotel, café, or corporate
                network). Browse to any http:// page to authenticate.
              </div>
            </div>
          )}

          <AlternateApBanner />
          <PermissionsCard />
          <StatusCard />
          <KpiRow />
        </div>

        {/* === Tabs === */}
        <div className="mt-6">
          <Tabs
            tabs={tabs}
            active={activeTab}
            onChange={(id) => setActiveTab(id as TabId)}
          />

          <div className="mt-6 space-y-6">
            {activeTab === "overview" && (
              <>
                <LiveMetricsChart />
                <AiExplanation />
                <RadioInsights />
                {lastScan && <QualityPanel quality={lastScan.quality} />}
                <TrendsPanel />
              </>
            )}

            {activeTab === "alerts" && (
              <>
                <section>
                  <SectionHeading>Findings &amp; recommendations</SectionHeading>
                  <FindingsList />
                </section>
                <NarrativePanel />
              </>
            )}

            {activeTab === "network" && (
              <>
                {lastScan && <LinkDetailsPanel link={lastScan.link} />}
                {lastScan && (
                  <NetworkPathPanel
                    reachability={lastScan.reachability}
                    mtuBytes={lastScan.mtu_bytes}
                    dnsLeak={lastScan.dns_leak}
                    captivePortal={lastScan.captive_portal}
                  />
                )}
                {lastScan && (
                  <PhyEfficiencyBadge phy={lastScan.phy_efficiency} />
                )}
                <WanPanel />
                <section>
                  <SectionHeading>Service reachability</SectionHeading>
                  <ServiceStatus />
                </section>
              </>
            )}

            {activeTab === "airspace" && (
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

            {activeTab === "av" && <AvDiagnostics />}

            {activeTab === "devices" && (
              <section>
                <SectionHeading>Devices on this network</SectionHeading>
                <DeviceList />
              </section>
            )}

            {activeTab === "activity" && (
              <>
                <section>
                  <SectionHeading>Scan history</SectionHeading>
                  <IncidentTimeline />
                </section>
                <WifiEventsTimeline />
                <section>
                  <SectionHeading>Past scans</SectionHeading>
                  <HistoryPanel />
                </section>
              </>
            )}

            {activeTab === "tools" && (
              <>
                <StressTestPanel />
              </>
            )}

            {activeTab === "assistant" && (
              <section>
                {lastScan ? (
                  <ChatPanel scanResult={lastScan} />
                ) : (
                  <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-6 text-sm text-[var(--color-muted)]">
                    Run a scan to chat with the AI assistant about your network.
                  </div>
                )}
              </section>
            )}
          </div>
        </div>

        <ScanMetaFooter />
      </main>

      {showSettings && <SettingsPanel onClose={() => setShowSettings(false)} />}

      {settingsLoaded && !settings?.onboarding_complete && (
        <OnboardingWizard onComplete={() => loadSettings()} />
      )}
    </div>
  );
}

export default App;
