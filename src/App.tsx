import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ModeToggle } from "./components/ModeToggle";
import { StatusCard } from "./components/StatusCard";
import { FindingsList } from "./components/FindingsList";
import { DeviceList } from "./components/DeviceList";
import { HistoryPanel } from "./components/HistoryPanel";
import { MetricCharts } from "./components/MetricCharts";
import { IncidentTimeline } from "./components/IncidentTimeline";
import { ServiceStatus } from "./components/ServiceStatus";
import { SettingsPanel } from "./components/SettingsPanel";
import ChannelMap from "./components/ChannelMap";
import ChatPanel from "./components/ChatPanel";
import { useApp } from "./store";

function App() {
  const mode = useApp((s) => s.mode);
  const monitoring = useApp((s) => s.monitoring);
  const lastScan = useApp((s) => s.lastScan);
  const loadSettings = useApp((s) => s.loadSettings);
  const subscribeToScanEvents = useApp((s) => s.subscribeToScanEvents);
  const [showSettings, setShowSettings] = useState(false);
  const [exporting, setExporting] = useState(false);

  useEffect(() => {
    loadSettings();
    let unsub: (() => void) | undefined;
    subscribeToScanEvents().then((fn) => { unsub = fn; });
    return () => { unsub?.(); };
  }, []);

  const handleExport = async () => {
    if (!lastScan) return;
    setExporting(true);
    try {
      const html = await invoke<string>("export_report", { runId: lastScan.run_id });
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

  return (
    <div className="min-h-screen">
      <header className="border-b border-[var(--color-border)] bg-[var(--color-panel)]/80 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="h-8 w-8 rounded-lg bg-[var(--color-accent)]" />
            <div>
              <h1 className="text-base font-semibold">WiFi Troubleshooter</h1>
              <p className="text-xs text-[var(--color-muted)]">
                AI-assisted network diagnostics
              </p>
            </div>
            {monitoring && (
              <span className="flex items-center gap-1.5 rounded-full bg-emerald-500/15 px-2.5 py-1 text-xs text-emerald-300">
                <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
                monitoring
              </span>
            )}
          </div>
          <div className="flex items-center gap-3">
            <ModeToggle />
            {mode === "admin" && lastScan && (
              <button
                onClick={handleExport}
                disabled={exporting}
                className="rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)] px-3 py-1.5 text-sm text-[var(--color-muted)] hover:text-[var(--color-fg)] transition-colors disabled:opacity-50"
                title="Export HTML report"
              >
                {exporting ? "Exporting…" : "⬇ Export"}
              </button>
            )}
            <button
              onClick={() => setShowSettings(true)}
              className="rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)] px-3 py-1.5 text-sm text-[var(--color-muted)] hover:text-[var(--color-fg)] transition-colors"
              title="Settings"
            >
              ⚙ Settings
            </button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl space-y-6 px-6 py-8">
        {lastScan?.captive_portal && (
          <div className="flex items-center gap-3 rounded-xl border border-yellow-500/40 bg-yellow-500/10 px-5 py-3 text-sm text-yellow-200">
            <span className="text-lg">⚠</span>
            <div>
              <strong>Captive portal detected.</strong> Your traffic is being intercepted by a login
              page (hotel, café, or corporate network). Browse to any http:// page to authenticate.
            </div>
          </div>
        )}

        <StatusCard />

        <section>
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-[var(--color-muted)]">
            Findings & recommendations
          </h2>
          <FindingsList />
        </section>

        {(mode === "pro" || mode === "admin") && lastScan && (
          <section>
            <ChatPanel scanResult={lastScan} />
          </section>
        )}

        {(mode === "pro" || mode === "admin") && (
          <section>
            <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-[var(--color-muted)]">
              Live metrics
            </h2>
            <MetricCharts />
          </section>
        )}

        {mode === "admin" && (
          <section>
            <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-[var(--color-muted)]">
              Incident timeline
            </h2>
            <IncidentTimeline />
          </section>
        )}

        {mode === "admin" && (
          <section>
            <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-[var(--color-muted)]">
              Channel map
            </h2>
            <ChannelMap
              nearbyAps={lastScan?.nearby_aps ?? []}
              ownChannel={lastScan?.link.channel ?? null}
            />
          </section>
        )}

        {(mode === "pro" || mode === "admin") && (
          <section>
            <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-[var(--color-muted)]">
              Service reachability
            </h2>
            <ServiceStatus />
          </section>
        )}

        {(mode === "pro" || mode === "admin") && (
          <section>
            <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-[var(--color-muted)]">
              Devices on this network
            </h2>
            <DeviceList />
          </section>
        )}

        {mode === "admin" && (
          <section>
            <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-[var(--color-muted)]">
              History
            </h2>
            <HistoryPanel />
          </section>
        )}
      </main>

      {showSettings && <SettingsPanel onClose={() => setShowSettings(false)} />}
    </div>
  );
}

export default App;

