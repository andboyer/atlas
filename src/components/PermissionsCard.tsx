/**
 * PermissionsCard — surfaces missing OS permissions and a one-click jump to
 * the relevant System Settings pane.
 *
 * Inference is heuristic and lives entirely in the renderer:
 *  - Location Services: any `nearby_aps` entry flagged `name_redacted` means
 *    macOS hid SSID names because the calling process lacks Location.
 *  - Local Network: zero discovered devices for a sustained period is a
 *    strong signal mDNS / multicast was blocked.
 *  - Notifications: handled by `@tauri-apps/plugin-notification` — checked
 *    on mount and re-requested on user click.
 *
 * Each row can be dismissed by the user (persisted to localStorage). The
 * card stays hidden when everything is granted, dismissed, or N/A.
 *
 * Dev-build caveat: when running via `pnpm tauri dev`, the binary is the
 * unbundled `target/debug/wifi-troubleshooter` — macOS gates Location
 * Services per-bundle-ID, and the dev binary has no Info.plist registered
 * with TCC, so Location Services CANNOT be granted to it. The card detects
 * this via `import.meta.env.DEV` and shows an explanatory note rather than
 * a pointless "Open Settings" button for the Location row.
 */
import { useEffect, useMemo, useState } from "react";
import {
  ShieldAlert,
  MapPin,
  Network as NetworkIcon,
  Bell,
  ExternalLink,
  CheckCircle2,
  X,
  Info,
} from "lucide-react";
import { openUrl } from "@tauri-apps/plugin-opener";
import {
  isPermissionGranted,
  requestPermission,
} from "@tauri-apps/plugin-notification";
import { useApp } from "../store";

type Status = "granted" | "denied" | "unknown";
type RowId = "location" | "local_network" | "notifications";

interface PermRow {
  id: RowId;
  label: string;
  description: string;
  note?: string;
  icon: React.ReactNode;
  status: Status;
  action?: () => Promise<void>;
  actionLabel?: string;
}

const DISMISSED_KEY = "wifi-troubleshooter:perm-dismissed:v1";

function loadDismissed(): Set<RowId> {
  try {
    const raw = localStorage.getItem(DISMISSED_KEY);
    if (!raw) return new Set();
    const arr = JSON.parse(raw) as RowId[];
    return new Set(arr);
  } catch {
    return new Set();
  }
}

function saveDismissed(set: Set<RowId>) {
  try {
    localStorage.setItem(DISMISSED_KEY, JSON.stringify([...set]));
  } catch {
    /* ignore quota / private mode */
  }
}

function isMac(): boolean {
  if (typeof navigator === "undefined") return false;
  const ua = (navigator.userAgent || "").toLowerCase();
  return ua.includes("mac");
}

/** True when this is a Vite dev build (`pnpm tauri dev`), not a bundled .app. */
const IS_DEV_BUILD: boolean = !!import.meta.env?.DEV;

export function PermissionsCard() {
  const lastScan = useApp((s) => s.lastScan);
  const [notifStatus, setNotifStatus] = useState<Status>("unknown");
  const [refreshNonce, setRefreshNonce] = useState(0);
  const [dismissed, setDismissed] = useState<Set<RowId>>(() => loadDismissed());

  useEffect(() => {
    let cancelled = false;
    isPermissionGranted()
      .then((granted) => {
        if (!cancelled) setNotifStatus(granted ? "granted" : "denied");
      })
      .catch(() => {
        if (!cancelled) setNotifStatus("unknown");
      });
    return () => {
      cancelled = true;
    };
  }, [refreshNonce]);

  const dismiss = (id: RowId) => {
    setDismissed((prev) => {
      const next = new Set(prev);
      next.add(id);
      saveDismissed(next);
      return next;
    });
  };

  const rows = useMemo<PermRow[]>(() => {
    const onMac = isMac();
    const out: PermRow[] = [];

    // Location Services — macOS only signal.
    if (onMac) {
      let locationStatus: Status = "unknown";
      if (lastScan && lastScan.nearby_aps.length > 0) {
        const anyRedacted = lastScan.nearby_aps.some(
          (a) => a.name_redacted === true
        );
        locationStatus = anyRedacted ? "denied" : "granted";
      }
      out.push({
        id: "location",
        label: "Location Services",
        description:
          "Required to read nearby Wi-Fi network names. Without it, SSIDs show as Network 1, Network 2…",
        note: IS_DEV_BUILD
          ? "Dev build limitation: the unbundled binary cannot be granted Location Services by macOS. Run `pnpm tauri build` and launch the bundled .app to grant this permanently."
          : 'Not seeing this app in the Location Services list? Scroll to the bottom of that pane, click "Details…" next to System Services, and enable "Networking & Wireless".',
        icon: <MapPin className="h-4 w-4" />,
        status: locationStatus,
        action: IS_DEV_BUILD
          ? undefined
          : async () => {
              try {
                await openUrl(
                  "x-apple.systempreferences:com.apple.preference.security?Privacy_LocationServices"
                );
              } catch (e) {
                console.warn("openUrl Location Services failed:", e);
              }
            },
        actionLabel: IS_DEV_BUILD ? undefined : "Open Settings",
      });
    }

    // Local Network — macOS only. Zero discovered devices = likely blocked.
    if (onMac) {
      let lanStatus: Status = "unknown";
      if (lastScan) {
        // Heuristic: at least one mDNS-tagged device or any device beyond the
        // gateway implies the multicast prompt was answered "Allow".
        lanStatus = lastScan.devices.length > 1 ? "granted" : "unknown";
      }
      out.push({
        id: "local_network",
        label: "Local Network",
        description:
          "Required to discover devices on your LAN via Bonjour / mDNS. macOS prompts automatically on first scan.",
        icon: <NetworkIcon className="h-4 w-4" />,
        status: lanStatus,
        action: async () => {
          try {
            await openUrl(
              "x-apple.systempreferences:com.apple.preference.security?Privacy_LocalNetwork"
            );
          } catch (e) {
            console.warn("openUrl Local Network failed:", e);
          }
        },
        actionLabel: "Open Settings",
      });
    }

    // Notifications — handled by tauri-plugin-notification on every platform.
    out.push({
      id: "notifications",
      label: "Notifications",
      description:
        "Lets the app alert you when a new high-severity finding appears. Optional but recommended.",
      icon: <Bell className="h-4 w-4" />,
      status: notifStatus,
      action: async () => {
        try {
          const res = await requestPermission();
          setNotifStatus(res === "granted" ? "granted" : "denied");
        } catch {
          setNotifStatus("denied");
        }
        setRefreshNonce((n) => n + 1);
      },
      actionLabel: notifStatus === "denied" ? "Request again" : "Allow",
    });

    return out;
  }, [lastScan, notifStatus]);

  // Hide rows the user explicitly dismissed, then only render the card if
  // something is still flagged as denied.
  const visibleRows = rows.filter((r) => !dismissed.has(r.id));
  const needsAttention = visibleRows.some((r) => r.status === "denied");
  if (!needsAttention) return null;

  return (
    <div className="rounded-2xl border border-amber-500/30 bg-amber-500/5 p-5">
      <div className="mb-4 flex items-start gap-3">
        <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-amber-400" />
        <div>
          <h3 className="text-sm font-semibold text-amber-200">
            Some permissions are missing
          </h3>
          <p className="mt-1 text-xs text-[var(--color-muted)]">
            Grant the permissions below to unlock the full feature set. macOS
            normally prompts on first use; if you dismissed a prompt, you can
            re-enable each one in System Settings. Click the × on any row to
            hide it permanently.
          </p>
        </div>
      </div>
      <ul className="space-y-2">
        {visibleRows.map((row) => {
          const tone =
            row.status === "granted"
              ? "border-emerald-500/30 bg-emerald-500/5"
              : row.status === "denied"
                ? "border-rose-500/30 bg-rose-500/5"
                : "border-[var(--color-border)] bg-[var(--color-panel)]";
          return (
            <li
              key={row.id}
              className={`flex flex-wrap items-start gap-3 rounded-xl border p-3 ${tone}`}
            >
              <span className="mt-0.5 rounded-md bg-[var(--color-panel-2)] p-1.5 text-[var(--color-muted)]">
                {row.icon}
              </span>
              <div className="min-w-[200px] flex-1">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-[var(--color-text)]">
                    {row.label}
                  </span>
                  <StatusPill status={row.status} />
                </div>
                <p className="mt-0.5 text-[11px] text-[var(--color-muted)]">
                  {row.description}
                </p>
                {row.note && (
                  <p className="mt-1.5 flex items-start gap-1.5 rounded-md border border-amber-500/20 bg-amber-500/5 p-2 text-[11px] text-amber-200">
                    <Info className="mt-0.5 h-3 w-3 shrink-0" />
                    <span>{row.note}</span>
                  </p>
                )}
              </div>
              <div className="flex items-center gap-1.5">
                {row.status !== "granted" && row.action && (
                  <button
                    type="button"
                    onClick={() => {
                      row.action?.();
                    }}
                    className="inline-flex items-center gap-1.5 rounded-md border border-[var(--color-border)] bg-[var(--color-panel-2)] px-2.5 py-1 text-[11px] font-medium text-[var(--color-text)] hover:border-[var(--color-accent)] hover:text-[var(--color-accent)]"
                  >
                    {row.actionLabel}
                    <ExternalLink className="h-3 w-3" />
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => dismiss(row.id)}
                  title="I've granted this — stop showing this row"
                  aria-label={`Dismiss ${row.label}`}
                  className="rounded-md p-1 text-[var(--color-muted)] hover:bg-[var(--color-panel-2)] hover:text-[var(--color-text)]"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              </div>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function StatusPill({ status }: { status: Status }) {
  if (status === "granted") {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/15 px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-emerald-300">
        <CheckCircle2 className="h-2.5 w-2.5" />
        Granted
      </span>
    );
  }
  if (status === "denied") {
    return (
      <span className="rounded-full bg-rose-500/15 px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-rose-300">
        Missing
      </span>
    );
  }
  return (
    <span className="rounded-full bg-[var(--color-panel-2)] px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-[var(--color-muted)]">
      Unknown
    </span>
  );
}
