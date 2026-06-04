import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useShallow } from "zustand/react/shallow";
import { Cable, HelpCircle, Wifi } from "lucide-react";
import { useApp } from "../store";
import type { NetworkInterfaceInfo } from "../types";

/** Render the wired / wireless / unclassified icon-and-label badge for
 *  one interface. The colour is deliberately bold for Wi-Fi because
 *  Dante-over-Wi-Fi isn't a supported topology and we want the user to
 *  notice the second they pin the AV probes to a wireless radio. */
function MediumBadge({ iface }: { iface: NetworkInterfaceInfo | undefined }) {
  if (!iface) return null;
  if (iface.is_wireless === true) {
    return (
      <span
        className="inline-flex items-center gap-1 rounded-full border border-rose-500/40 bg-rose-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-rose-300"
        title="Pinned to a Wi-Fi radio — Dante/AES67 are designed for wired networks."
      >
        <Wifi className="h-3 w-3" /> Wi-Fi
      </span>
    );
  }
  if (iface.is_wireless === false) {
    return (
      <span
        className="inline-flex items-center gap-1 rounded-full border border-emerald-500/40 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-emerald-300"
        title="Wired adapter — Wi-Fi inferences will be suppressed."
      >
        <Cable className="h-3 w-3" /> Wired
      </span>
    );
  }
  return (
    <span
      className="inline-flex items-center gap-1 rounded-full border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-amber-300"
      title="Medium not detected (virtual or unclassified adapter)."
    >
      <HelpCircle className="h-3 w-3" /> Unknown
    </span>
  );
}

/** Suffix appended to each <option>'s text so the user sees whether
 *  the NIC is wired, wireless, or unclassified inline in the dropdown. */
function mediumSuffix(iface: NetworkInterfaceInfo): string {
  if (iface.is_wireless === true) return "Wi-Fi";
  if (iface.is_wireless === false) return "Wired";
  return "Unknown";
}

/** AV-tab NIC picker. Lives at the top of the AV-over-IP diagnostics
 *  tab (previously in the global header). Surfaces the medium of every
 *  candidate NIC and the medium of the currently-pinned NIC, so the
 *  user can immediately tell whether the diagnostics are about to
 *  inherit a Wi-Fi posture or a wired one. */
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

  const current = settings.preferred_av_interface ?? "";

  const usable = useMemo(
    () => ifaces.filter((i) => i.is_physical && i.is_up && !i.is_loopback && !!i.ipv4),
    [ifaces],
  );

  const selected = useMemo(
    () => ifaces.find((i) => i.name === current),
    [ifaces, current],
  );
  const currentMissing = !!current && !selected;

  const handleChange = async (value: string) => {
    if (!settingsLoaded) return;
    setBusy(true);
    try {
      await saveSettings({ ...settings, preferred_av_interface: value });
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  // Friendly hint that surfaces directly below the picker so the user
  // understands what their current pick means for the rest of the tab.
  const hint = (() => {
    if (currentMissing) {
      return `"${current}" isn't present on this host right now. Reconnect the adapter or pick another.`;
    }
    if (!current) {
      return "Auto lets the kernel pick the NIC — usually Wi-Fi on laptops. Pin a wired adapter for Dante / AES67.";
    }
    if (selected?.is_wireless === true) {
      return "Wi-Fi pin: diagnostics will assume the audio network is Wi-Fi. Dante/AES67 aren't supported on Wi-Fi.";
    }
    if (selected?.is_wireless === false) {
      return "Wired pin: Wi-Fi-only warnings are suppressed; the audio VLAN won't be flagged as Wi-Fi.";
    }
    return "Pinned NIC medium isn't classifiable; Wi-Fi inferences default to the host's last Wi-Fi scan.";
  })();

  return (
    <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)]/70 p-3">
      <div className="flex flex-wrap items-center gap-3">
        <label
          htmlFor="av-iface"
          className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.18em] text-[var(--color-muted)]"
        >
          <Cable className="h-3.5 w-3.5" /> Diagnostics NIC
        </label>
        <select
          id="av-iface"
          value={current}
          onChange={(e) => handleChange(e.target.value)}
          disabled={busy || !settingsLoaded}
          className="min-w-[18rem] flex-1 cursor-pointer rounded border border-[var(--color-border)] bg-[var(--color-bg)]/60 px-2 py-1.5 text-sm font-mono text-[var(--color-text)] focus:outline-none focus:ring-1 focus:ring-[var(--color-accent)] disabled:opacity-50"
          aria-label="AV-over-IP network interface"
        >
          <option value="">Auto (kernel default)</option>
          {usable.map((i) => (
            <option key={i.name} value={i.name}>
              {i.name}
              {i.ipv4 ? ` — ${i.ipv4}` : ""} — {mediumSuffix(i)}
            </option>
          ))}
          {currentMissing && (
            <option value={current}>{current} — not present</option>
          )}
        </select>
        <MediumBadge iface={selected} />
      </div>
      <p className="mt-2 text-xs leading-snug text-[var(--color-muted)]">
        {hint}
      </p>
      {error && (
        <p className="mt-1 text-xs text-rose-300">AV NIC error: {error}</p>
      )}
    </div>
  );
}
