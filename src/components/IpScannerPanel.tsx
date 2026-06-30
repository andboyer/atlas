import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";
import {
  Loader2,
  ScanSearch,
  AlertTriangle,
  ServerCog,
  Globe,
  TerminalSquare,
} from "lucide-react";
import type { IpScanHost } from "../types";
import { useApp } from "../store";

/** Friendly labels for the curated TCP ports the backend probes. */
const PORT_LABELS: Record<number, string> = {
  22: "SSH",
  23: "Telnet",
  53: "DNS",
  80: "HTTP",
  139: "NetBIOS",
  443: "HTTPS",
  445: "SMB",
  515: "LPD",
  631: "IPP",
  3389: "RDP",
  5000: "UPnP",
  5900: "VNC",
  8006: "Proxmox",
  8080: "HTTP-alt",
  8443: "HTTPS-alt",
  9100: "RAW print",
};

/** Numeric-aware IPv4 sort so 192.168.1.2 sorts before 192.168.1.10. */
function compareIps(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 4; i++) {
    const da = pa[i] ?? 0;
    const db = pb[i] ?? 0;
    if (da !== db) return da - db;
  }
  return a.localeCompare(b);
}

export function IpScannerPanel() {
  const cidr = useApp((s) => s.ipScanCidr);
  const setCidr = useApp((s) => s.setIpScanCidr);
  const result = useApp((s) => s.ipScanResult);
  const loading = useApp((s) => s.ipScanLoading);
  const error = useApp((s) => s.ipScanError);
  const runSubnetScan = useApp((s) => s.runSubnetScan);
  const addHostToFleet = useApp((s) => s.addHostToFleet);
  const discovered = useApp((s) => s.lastScan?.devices) ?? [];
  const [menu, setMenu] = useState<{ x: number; y: number; host: IpScanHost } | null>(
    null,
  );
  // Transient errors from row actions (browser / SSH launch).
  const [actionError, setActionError] = useState<string | null>(null);

  // Devices found passively during the normal scan (mDNS + ARP). Shown by
  // default so the table isn't empty before an active sweep is run. Mapped
  // onto the IpScanHost shape used by the table + context menu. A full
  // "Scan" replaces these with the active-sweep results.
  const discoveredHosts: IpScanHost[] = discovered
    .filter((d) => d.ip)
    .map((d) => ({
      ip: d.ip as string,
      mac: d.mac || null,
      vendor: d.vendor,
      hostname: d.hostname,
      latency_ms: d.latency_ms,
      online: d.online,
      open_ports: [],
    }))
    .sort((a, b) => compareIps(a.ip, b.ip));

  // The active sweep result wins once it exists; otherwise fall back to the
  // passively-discovered devices.
  const showingDiscovered = !result;
  const rows = result ? result.hosts : discoveredHosts;

  // Pre-fill the CIDR from the active interface on first mount (only if the
  // store doesn't already hold one from a previous visit).
  useEffect(() => {
    if (cidr) return;
    invoke<string>("default_scan_cidr")
      .then((c) => setCidr(c))
      .catch(() => setCidr("192.168.1.0/24"));
  }, [cidr, setCidr]);

  // Dismiss the context menu on any outside click, scroll, or Escape.
  useEffect(() => {
    if (!menu) return;
    const close = () => setMenu(null);
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setMenu(null);
    };
    window.addEventListener("click", close);
    window.addEventListener("scroll", close, true);
    window.addEventListener("resize", close);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("click", close);
      window.removeEventListener("scroll", close, true);
      window.removeEventListener("resize", close);
      window.removeEventListener("keydown", onKey);
    };
  }, [menu]);

  const runScan = () => {
    void runSubnetScan();
  };

  const openRow = (host: IpScanHost, e: React.MouseEvent) => {
    e.preventDefault();
    setMenu({ x: e.clientX, y: e.clientY, host });
  };

  /** Best-guess admin URL from the host's open ports (HTTPS wins over HTTP). */
  const browserUrlFor = (host: IpScanHost): string => {
    const p = host.open_ports;
    if (p.includes(443)) return `https://${host.ip}`;
    if (p.includes(8443)) return `https://${host.ip}:8443`;
    if (p.includes(8006)) return `https://${host.ip}:8006`;
    if (p.includes(80)) return `http://${host.ip}`;
    if (p.includes(8080)) return `http://${host.ip}:8080`;
    return `http://${host.ip}`;
  };

  const handleAddToFleet = (host: IpScanHost) => {
    setMenu(null);
    addHostToFleet({ hostname: host.ip, alias: host.hostname || host.ip });
  };

  const handleOpenBrowser = async (host: IpScanHost) => {
    setMenu(null);
    setActionError(null);
    try {
      await openUrl(browserUrlFor(host));
    } catch (e) {
      setActionError(`Couldn't open browser: ${String(e)}`);
    }
  };

  const handleOpenSsh = async (host: IpScanHost) => {
    setMenu(null);
    setActionError(null);
    try {
      await invoke("open_ssh_terminal", { host: host.ip, port: 22 });
    } catch (e) {
      setActionError(`Couldn't open SSH window: ${String(e)}`);
    }
  };

  return (
    <div className="space-y-4">
      {/* Controls */}
      <div className="atlas-card p-4">
        <div className="flex flex-wrap items-end gap-3">
          <label className="flex flex-col gap-1">
            <span className="text-[11px] font-semibold uppercase tracking-[0.12em] text-[var(--color-muted)]">
              Subnet (CIDR)
            </span>
            <input
              value={cidr}
              onChange={(e) => setCidr(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") runScan();
              }}
              placeholder="192.168.1.0/24"
              spellCheck={false}
              className="w-56 rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)]/60 px-3 py-2 font-mono text-sm text-[var(--color-text)] outline-none focus:border-indigo-400/60"
            />
          </label>
          <button
            onClick={runScan}
            disabled={loading}
            className="inline-flex items-center gap-2 rounded-lg bg-indigo-500 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-400 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {loading ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <ScanSearch className="h-4 w-4" />
            )}
            {loading ? "Scanning…" : "Scan"}
          </button>
          {result && !loading && (
            <span className="text-xs text-[var(--color-muted)]">
              {result.online_count} live of {result.host_count} scanned ·{" "}
              {(result.duration_ms / 1000).toFixed(1)}s
            </span>
          )}
          {showingDiscovered && !loading && discoveredHosts.length > 0 && (
            <span className="text-xs text-[var(--color-muted)]">
              {discoveredHosts.length} auto-discovered · Scan to sweep the full
              subnet
            </span>
          )}
        </div>
        <p className="mt-2 text-[11px] text-[var(--color-muted)]">
          Auto-discovered devices (passive mDNS + ARP from the latest scan) are
          listed below. Run an active <strong>Scan</strong> to ping every
          address, read ARP for MACs, browse mDNS for names, and probe common
          TCP ports — this replaces the discovered list with the full sweep.
          Ranges are capped at 1024 hosts (use /22 or smaller). Right-click a
          row to add it to the Fleet, open it in a browser, or launch an SSH
          window.
        </p>
      </div>

      {(error || actionError) && (
        <div className="atlas-card flex items-start gap-2 border-rose-500/30 bg-rose-500/5 p-4 text-sm text-rose-300">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>{error ?? actionError}</span>
        </div>
      )}

      {/* Results */}
      {rows.length > 0 ? (
        <div className="atlas-card overflow-hidden">
          {showingDiscovered && (
            <div className="border-b border-[var(--color-border)]/60 bg-[var(--color-panel-2)]/40 px-4 py-2 text-[11px] text-[var(--color-muted)]">
              Showing auto-discovered devices. Open ports are only probed during
              an active scan.
            </div>
          )}
          <table className="w-full text-sm">
            <thead className="bg-[var(--color-panel-2)]/60 text-left text-[11px] font-semibold uppercase tracking-[0.12em] text-[var(--color-muted)]">
              <tr>
                <th className="px-4 py-3">IP</th>
                <th className="px-4 py-3">Host</th>
                <th className="px-4 py-3">Vendor</th>
                <th className="px-4 py-3">MAC</th>
                <th className="px-4 py-3">Latency</th>
                <th className="px-4 py-3">Open ports</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((h) => (
                <tr
                  key={h.ip}
                  onContextMenu={(e) => openRow(h, e)}
                  className="cursor-context-menu border-t border-[var(--color-border)]/60 transition-colors hover:bg-[var(--color-panel-2)]/40"
                >
                  <td className="px-4 py-3 font-mono text-xs tabular-nums text-[var(--color-text)]">
                    {h.ip}
                  </td>
                  <td className="px-4 py-3 text-[var(--color-text)]">
                    {h.hostname ?? (
                      <span className="text-[var(--color-muted)]">—</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-[var(--color-muted)]">
                    {h.vendor ?? "—"}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-[var(--color-muted)] tabular-nums">
                    {h.mac ?? "—"}
                  </td>
                  <td className="px-4 py-3 tabular-nums">
                    {typeof h.latency_ms === "number"
                      ? `${h.latency_ms.toFixed(1)} ms`
                      : "—"}
                  </td>
                  <td className="px-4 py-3">
                    {h.open_ports.length > 0 ? (
                      <div className="flex flex-wrap gap-1">
                        {h.open_ports.map((p) => (
                          <span
                            key={p}
                            title={PORT_LABELS[p] ? `${p} · ${PORT_LABELS[p]}` : `${p}`}
                            className="rounded border border-[var(--color-border)] bg-[var(--color-panel-2)]/70 px-1.5 py-0.5 font-mono text-[10px] text-[var(--color-muted)]"
                          >
                            {p}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <span className="text-[var(--color-muted)]">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : result && !loading ? (
        <div className="atlas-card p-6 text-sm text-[var(--color-muted)]">
          No live hosts found in {result.cidr}.
        </div>
      ) : (
        !loading &&
        !error && (
          <div className="atlas-card p-6 text-sm text-[var(--color-muted)]">
            No devices discovered yet. Enter a subnet and press Scan to actively
            sweep the network.
          </div>
        )
      )}

      {/* Right-click context menu */}
      {menu && (
        <div
          role="menu"
          style={{ top: menu.y, left: menu.x }}
          onClick={(e) => e.stopPropagation()}
          onContextMenu={(e) => e.preventDefault()}
          className="fixed z-50 min-w-[200px] overflow-hidden rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)] py-1 shadow-xl shadow-black/40"
        >
          <div className="px-3 py-1.5 font-mono text-[11px] text-[var(--color-muted)]">
            {menu.host.ip}
          </div>
          <div className="my-1 border-t border-[var(--color-border)]/60" />
          <button
            role="menuitem"
            onClick={() => handleAddToFleet(menu.host)}
            className="flex w-full items-center gap-2.5 px-3 py-2 text-left text-sm text-[var(--color-text)] hover:bg-[var(--color-panel-2)]/70"
          >
            <ServerCog className="h-4 w-4 text-indigo-400" />
            Add to Fleet inventory
          </button>
          <button
            role="menuitem"
            onClick={() => handleOpenBrowser(menu.host)}
            className="flex w-full items-center gap-2.5 px-3 py-2 text-left text-sm text-[var(--color-text)] hover:bg-[var(--color-panel-2)]/70"
          >
            <Globe className="h-4 w-4 text-emerald-400" />
            Open in browser
          </button>
          <button
            role="menuitem"
            onClick={() => handleOpenSsh(menu.host)}
            className="flex w-full items-center gap-2.5 px-3 py-2 text-left text-sm text-[var(--color-text)] hover:bg-[var(--color-panel-2)]/70"
          >
            <TerminalSquare className="h-4 w-4 text-sky-400" />
            Open SSH window
          </button>
        </div>
      )}
    </div>
  );
}

export default IpScannerPanel;
