import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useShallow } from "zustand/react/shallow";
import { Cable } from "lucide-react";
import { useApp } from "../store";
import type { NetworkInterfaceInfo } from "../types";

/** Compact header-bar dropdown that pins AV-over-IP probes to a specific
 *  physical NIC. Mirrors the Settings panel field but lives in the toolbar
 *  so it's reachable without opening the modal. Only physical, up,
 *  IPv4-bearing interfaces appear (utun / awdl / bridge / docker / etc.
 *  are filtered server-side via `NetworkInterfaceInfo.is_physical` and
 *  client-side via `ipv4 != null`). */
export function AvInterfacePicker() {
  const { settings, saveSettings, settingsLoaded } = useApp(
    useShallow((s) => ({
      settings: s.settings,
      saveSettings: s.saveSettings,
      settingsLoaded: s.settingsLoaded,
    })),
  );

  const [ifaces, setIfaces] = useState<NetworkInterfaceInfo[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Refresh on mount and every 30s so unplugged USB-Ethernet adapters
  // disappear from the picker without needing a full app restart.
  useEffect(() => {
    let cancelled = false;
    const refresh = () => {
      invoke<NetworkInterfaceInfo[]>("list_network_interfaces")
        .then((list) => {
          if (!cancelled) {
            setIfaces(list);
            setError(null);
          }
        })
        .catch((e) => {
          if (!cancelled) setError(String(e));
        });
    };
    refresh();
    const id = window.setInterval(refresh, 30_000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, []);

  // Don't render until settings load so we don't briefly show "Auto"
  // and then snap to the persisted selection.
  if (!settingsLoaded) return null;

  const usable = ifaces.filter(
    (i) => i.is_physical && i.is_up && !i.is_loopback && !!i.ipv4,
  );
  const current = settings.preferred_av_interface ?? "";
  const currentMissing =
    current && !ifaces.some((i) => i.name === current);

  const handleChange = async (value: string) => {
    setBusy(true);
    try {
      await saveSettings({ ...settings, preferred_av_interface: value });
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)] px-2 py-1 text-xs text-[var(--color-muted)]"
      title={
        error
          ? `AV NIC error: ${error}`
          : "Pin AV-over-IP probes (Dante / AES67 / IGMP) to a specific physical NIC. Auto lets the kernel pick (usually Wi-Fi)."
      }
    >
      <Cable className="h-3.5 w-3.5 shrink-0" aria-hidden />
      <span className="hidden sm:inline">AV NIC</span>
      <select
        value={current}
        onChange={(e) => handleChange(e.target.value)}
        disabled={busy}
        className="cursor-pointer rounded bg-transparent pr-1 text-xs font-mono text-[var(--color-text)] focus:outline-none focus:ring-1 focus:ring-[var(--color-accent)] disabled:opacity-50"
        aria-label="AV-over-IP network interface"
      >
        <option value="">Auto</option>
        {usable.map((i) => (
          <option key={i.name} value={i.name}>
            {i.name}
            {i.ipv4 ? ` — ${i.ipv4}` : ""}
          </option>
        ))}
        {currentMissing && (
          <option value={current}>{current} — not present</option>
        )}
      </select>
    </div>
  );
}
