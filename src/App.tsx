import { useEffect, useState } from "react";
import { ModeToggle } from "./components/ModeToggle";
import { StatusCard } from "./components/StatusCard";
import { FindingsList } from "./components/FindingsList";
import { DeviceList } from "./components/DeviceList";
import { HistoryPanel } from "./components/HistoryPanel";
import { ServiceStatus } from "./components/ServiceStatus";
import { SettingsPanel } from "./components/SettingsPanel";
import { useApp } from "./store";

function App() {
  const mode = useApp((s) => s.mode);
  const monitoring = useApp((s) => s.monitoring);
  const loadSettings = useApp((s) => s.loadSettings);
  const subscribeToScanEvents = useApp((s) => s.subscribeToScanEvents);
  const [showSettings, setShowSettings] = useState(false);

  useEffect(() => {
    loadSettings();
    let unsub: (() => void) | undefined;
    subscribeToScanEvents().then((fn) => { unsub = fn; });
    return () => { unsub?.(); };
  }, []);

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
        <StatusCard />

        <section>
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-[var(--color-muted)]">
            Findings & recommendations
          </h2>
          <FindingsList />
        </section>

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

