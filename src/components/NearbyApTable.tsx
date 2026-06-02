/**
 * NearbyApTable — sortable, searchable table of every detected access point.
 *
 * Columns: SSID, BSSID, vendor, channel/band, width, RSSI bar, security, PHY.
 * Default sort is RSSI descending (strongest first). A free-text filter
 * matches against SSID, BSSID, and vendor.
 */
import { useMemo, useState } from "react";
import { Search, ArrowUpDown, ArrowUp, ArrowDown, Lock, ShieldAlert } from "lucide-react";
import { openUrl } from "@tauri-apps/plugin-opener";
import type { NearbyAp } from "../types";

interface Props {
  aps: NearbyAp[];
  ownBssid?: string | null;
  ownSsid?: string | null;
}

type SortKey = "ssid" | "bssid" | "vendor" | "channel" | "rssi" | "security";
type SortDir = "asc" | "desc";

const RSSI_MIN = -100;
const RSSI_MAX = -30;

function rssiPct(rssi: number | null | undefined): number {
  if (rssi == null) return 0;
  const clamped = Math.max(RSSI_MIN, Math.min(RSSI_MAX, rssi));
  return ((clamped - RSSI_MIN) / (RSSI_MAX - RSSI_MIN)) * 100;
}

function rssiTone(rssi: number | null | undefined): string {
  if (rssi == null) return "var(--color-muted)";
  if (rssi >= -60) return "var(--color-good)";
  if (rssi >= -75) return "var(--color-warn)";
  return "var(--color-bad)";
}

function compare<T>(a: T, b: T, dir: SortDir): number {
  if (a == null && b == null) return 0;
  if (a == null) return dir === "asc" ? 1 : -1;
  if (b == null) return dir === "asc" ? -1 : 1;
  if (a < b) return dir === "asc" ? -1 : 1;
  if (a > b) return dir === "asc" ? 1 : -1;
  return 0;
}

export function NearbyApTable({ aps, ownBssid, ownSsid }: Props) {
  const [query, setQuery] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("rssi");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  const redactedCount = useMemo(
    () => aps.filter((a) => a.name_redacted).length,
    [aps]
  );

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return aps;
    return aps.filter((ap) => {
      return (
        (ap.ssid ?? "").toLowerCase().includes(q) ||
        (ap.bssid ?? "").toLowerCase().includes(q) ||
        (ap.vendor ?? "").toLowerCase().includes(q)
      );
    });
  }, [aps, query]);

  const sorted = useMemo(() => {
    const arr = [...filtered];
    arr.sort((a, b) => {
      switch (sortKey) {
        case "ssid":
          return compare(
            (a.ssid ?? "").toLowerCase(),
            (b.ssid ?? "").toLowerCase(),
            sortDir
          );
        case "bssid":
          return compare(a.bssid ?? "", b.bssid ?? "", sortDir);
        case "vendor":
          return compare(
            (a.vendor ?? "").toLowerCase(),
            (b.vendor ?? "").toLowerCase(),
            sortDir
          );
        case "channel":
          return compare(a.channel, b.channel, sortDir);
        case "security":
          return compare(a.security ?? "", b.security ?? "", sortDir);
        case "rssi":
        default:
          return compare(a.rssi_dbm, b.rssi_dbm, sortDir);
      }
    });
    return arr;
  }, [filtered, sortKey, sortDir]);

  const toggleSort = (k: SortKey) => {
    if (k === sortKey) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(k);
      setSortDir(k === "rssi" ? "desc" : "asc");
    }
  };

  return (
    <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5">
      {redactedCount > 0 && (
        <div className="mb-4 flex items-start gap-3 rounded-xl border border-amber-500/30 bg-amber-500/5 p-3">
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
          <div className="flex-1 text-xs leading-relaxed text-[var(--color-text)]">
            <p className="font-semibold text-amber-300">
              macOS hid {redactedCount} SSID{redactedCount === 1 ? "" : "s"} for privacy
            </p>
            <p className="mt-1 text-[var(--color-muted)]">
              Apple redacts nearby network names unless the scanning process has
              <span className="text-[var(--color-text)]"> Location Services </span>
              permission. The signal, channel, and security data below are still accurate &mdash;
              only the names are masked, shown as <span className="font-mono text-[var(--color-text)]">Network&nbsp;N</span>.
            </p>
            <p className="mt-2 text-[var(--color-muted)]">
              In a packaged build, the app will prompt for permission on first launch. While
              running <span className="font-mono text-[var(--color-text)]">pnpm tauri dev</span>,
              grant <span className="font-mono text-[var(--color-text)]">Terminal</span> (or your
              IDE) the Location Services permission instead.
            </p>
            <div className="mt-2 flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => {
                  openUrl(
                    "x-apple.systempreferences:com.apple.preference.security?Privacy_LocationServices"
                  ).catch(() => {
                    /* opener plugin not granted or settings URL unsupported */
                  });
                }}
                className="rounded-md border border-[var(--color-border)] bg-[var(--color-panel-2)] px-2.5 py-1 text-[11px] font-medium text-[var(--color-text)] hover:border-[var(--color-accent)] hover:text-[var(--color-accent)]"
              >
                Open Location Services settings
              </button>
            </div>
          </div>
        </div>
      )}
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold">Detected access points</h3>
          <p className="mt-0.5 text-xs text-[var(--color-muted)]">
            {sorted.length} of {aps.length} visible
            {query && ` matching "${query}"`}
          </p>
        </div>
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--color-muted)]" />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="SSID, BSSID, vendor…"
            className="w-56 rounded-lg border border-[var(--color-border)] bg-[var(--color-panel-2)] py-1.5 pl-8 pr-2 text-xs text-[var(--color-text)] placeholder:text-[var(--color-muted)] focus:border-[var(--color-accent)] focus:outline-none"
          />
        </div>
      </div>

      {aps.length === 0 ? (
        <p className="rounded-lg border border-dashed border-[var(--color-border)] p-6 text-center text-xs text-[var(--color-muted)]">
          No access points reported by the channel scan.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-[var(--color-border)] text-left text-[10px] uppercase tracking-wider text-[var(--color-muted)]">
                <Th label="SSID" k="ssid" sortKey={sortKey} sortDir={sortDir} onSort={toggleSort} />
                <Th label="BSSID" k="bssid" sortKey={sortKey} sortDir={sortDir} onSort={toggleSort} />
                <Th label="Vendor" k="vendor" sortKey={sortKey} sortDir={sortDir} onSort={toggleSort} />
                <Th label="Channel" k="channel" sortKey={sortKey} sortDir={sortDir} onSort={toggleSort} />
                <th className="py-2 pr-3 font-medium">Width</th>
                <Th label="Signal" k="rssi" sortKey={sortKey} sortDir={sortDir} onSort={toggleSort} />
                <Th label="Security" k="security" sortKey={sortKey} sortDir={sortDir} onSort={toggleSort} />
                <th className="py-2 pr-3 font-medium">PHY</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((ap, idx) => {
                const isOwn =
                  (ownBssid != null && ap.bssid === ownBssid) ||
                  (ownSsid != null &&
                    ownBssid == null &&
                    ap.ssid === ownSsid);
                const pct = rssiPct(ap.rssi_dbm);
                const tone = rssiTone(ap.rssi_dbm);
                return (
                  <tr
                    key={(ap.bssid ?? "") + idx}
                    className={`border-b border-[var(--color-border)]/40 transition-colors ${
                      isOwn
                        ? "bg-[var(--color-accent)]/5"
                        : "hover:bg-[var(--color-panel-2)]/50"
                    }`}
                  >
                    <td className="py-2 pr-3">
                      <div className="flex items-center gap-2">
                        {isOwn && (
                          <span
                            className="inline-block h-1.5 w-1.5 rounded-full bg-[var(--color-accent)]"
                            title="Connected AP"
                          />
                        )}
                        {ap.name_redacted && (
                          <span title="SSID hidden by macOS Location Services">
                            <Lock
                              className="h-3 w-3 text-amber-400"
                              aria-label="SSID hidden by macOS Location Services"
                            />
                          </span>
                        )}
                        <span
                          className={
                            ap.name_redacted
                              ? "italic text-[var(--color-muted)]"
                              : ap.ssid
                                ? "font-medium text-[var(--color-text)]"
                                : "italic text-[var(--color-muted)]"
                          }
                          title={
                            ap.name_redacted
                              ? "macOS hid this SSID. Grant Location Services to reveal."
                              : undefined
                          }
                        >
                          {ap.ssid ?? "(hidden)"}
                        </span>
                      </div>
                    </td>
                    <td className="py-2 pr-3 font-mono text-[10px] text-[var(--color-muted)]">
                      {ap.bssid ?? "—"}
                    </td>
                    <td className="py-2 pr-3 text-[var(--color-muted)]">
                      {ap.vendor ?? "—"}
                    </td>
                    <td className="py-2 pr-3 whitespace-nowrap">
                      {ap.channel != null ? (
                        <>
                          <span className="font-semibold">{ap.channel}</span>
                          {ap.band && (
                            <span className="text-[var(--color-muted)]">
                              {" "}
                              · {ap.band} GHz
                            </span>
                          )}
                        </>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td className="py-2 pr-3 text-[var(--color-muted)]">
                      {ap.width_mhz != null ? `${ap.width_mhz} MHz` : "—"}
                    </td>
                    <td className="py-2 pr-3 min-w-[120px]">
                      {ap.rssi_dbm != null ? (
                        <div className="flex items-center gap-2">
                          <div className="h-1.5 w-16 overflow-hidden rounded-full bg-[var(--color-panel-2)]">
                            <div
                              className="h-full rounded-full transition-all"
                              style={{
                                width: `${pct}%`,
                                backgroundColor: tone,
                              }}
                            />
                          </div>
                          <span
                            className="tabular-nums font-medium"
                            style={{ color: tone }}
                          >
                            {ap.rssi_dbm} dBm
                          </span>
                        </div>
                      ) : (
                        <span className="text-[var(--color-muted)]">—</span>
                      )}
                    </td>
                    <td className="py-2 pr-3 text-[var(--color-muted)]">
                      {ap.security ?? "—"}
                    </td>
                    <td className="py-2 pr-3 text-[var(--color-muted)]">
                      {ap.phy_mode ?? "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

interface ThProps {
  label: string;
  k: SortKey;
  sortKey: SortKey;
  sortDir: SortDir;
  onSort: (k: SortKey) => void;
}

function Th({ label, k, sortKey, sortDir, onSort }: ThProps) {
  const active = k === sortKey;
  const Icon = !active ? ArrowUpDown : sortDir === "asc" ? ArrowUp : ArrowDown;
  return (
    <th className="py-2 pr-3 font-medium">
      <button
        onClick={() => onSort(k)}
        className={`flex items-center gap-1 transition-colors ${
          active
            ? "text-[var(--color-text)]"
            : "text-[var(--color-muted)] hover:text-[var(--color-text)]"
        }`}
      >
        <span>{label}</span>
        <Icon className="h-3 w-3" />
      </button>
    </th>
  );
}
