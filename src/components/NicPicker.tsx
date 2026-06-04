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

/** Global NIC picker. Lives in the top header (right of the brand,
 *  before Export / Settings). The selected NIC is the iface every
 *  iface-pinned probe in Atlas uses — AV-over-IP diagnostics, the
 *  privileged deep probes (IGMP, PTP, LLDP, SAP, DSCP), and traceroute
 *  all read `settings.preferred_interface`. Wi-Fi-radio-bound probes
 *  (channel map, RSSI sampler) always use the Wi-Fi adapter regardless
 *  of this pin because that's the only NIC they can physically read.
 *
 *  The picker exposes:
 *    - the NIC + IPv4 + medium suffix inline in each <option>;
 *    - a wired / Wi-Fi / unknown medium badge next to the selected
 *      value, deliberately bold for Wi-Fi so the user notices the
 *      moment they pin diagnostics to a wireless radio;
 *    - a one-line footnote that explains what the current pick means
 *      for downstream probes.
 */
export function NicPicker() {
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

  const current = settings.preferred_interface ?? "";

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
      await saveSettings({ ...settings, preferred_interface: value });
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  // One-line footnote rendered under the picker so the user always
  // knows what the current pick means for downstream probes.
  const hint = (() => {
    if (currentMissing) {
      return `"${current}" isn't present on this host right now. Reconnect the adapter or pick another.`;
    }
    if (!current) {
      return "Auto: the kernel picks per its routing table — usually Wi-Fi on laptops. Pin a wired adapter for Dante / AES67.";
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
    <div className="flex flex-col items-end gap-1">
      <div className="flex items-center gap-2">
        <label
          htmlFor="atlas-iface"
          className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.18em] text-[var(--color-muted)]"
        >
          <Cable className="h-3.5 w-3.5" /> Atlas NIC
        </label>
        <select
          id="atlas-iface"
          value={current}
          onChange={(e) => handleChange(e.target.value)}
          disabled={busy || !settingsLoaded}
          className="min-w-[14rem] max-w-[22rem] cursor-pointer rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)]/80 px-2.5 py-1.5 text-xs font-mono text-[var(--color-text)] transition-colors hover:border-[var(--color-accent)]/40 focus:outline-none focus:ring-1 focus:ring-[var(--color-accent)] disabled:opacity-50"
          aria-label="Atlas network interface (used by every iface-pinned probe)"
          title="NIC every iface-pinned probe binds to (AV diagnostics, deep probes, traceroute). Wi-Fi scans always use the Wi-Fi radio."
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
      <p className="max-w-[28rem] text-right text-[10px] leading-snug text-[var(--color-muted)]">
        {hint}
      </p>
      {error && (
        <p className="text-[10px] text-rose-300">NIC error: {error}</p>
      )}
    </div>
  );
}
