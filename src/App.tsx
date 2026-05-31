import { ModeToggle } from "./components/ModeToggle";
import { StatusCard } from "./components/StatusCard";
import { FindingsList } from "./components/FindingsList";
import { DeviceList } from "./components/DeviceList";
import { useApp } from "./store";

function App() {
  const mode = useApp((s) => s.mode);
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
          </div>
          <ModeToggle />
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
              Devices on this network
            </h2>
            <DeviceList />
          </section>
        )}
      </main>
    </div>
  );
}

export default App;

