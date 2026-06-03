import type { ReactNode } from "react";

export interface TabDef {
  id: string;
  label: string;
  icon?: ReactNode;
  badge?: number;
}

interface Props {
  tabs: TabDef[];
  active: string;
  onChange: (id: string) => void;
}

/**
 * Pill-bar tab strip. Each tab is a single button; the active one fills with
 * the brand panel surface + brass underline so the eye finds the current
 * section instantly. Overflow wraps to a second row on narrow viewports.
 */
export function Tabs({ tabs, active, onChange }: Props) {
  return (
    <nav
      className="atlas-tabbar flex flex-wrap items-center gap-1"
      aria-label="Primary"
    >
      {tabs.map((t) => {
        const isActive = t.id === active;
        return (
          <button
            key={t.id}
            type="button"
            onClick={() => onChange(t.id)}
            aria-current={isActive ? "page" : undefined}
            className={[
              "group relative inline-flex items-center gap-1.5 whitespace-nowrap rounded-[10px] px-3.5 py-2 text-sm font-medium transition-colors",
              isActive
                ? "bg-[var(--color-panel-2)] text-[var(--color-text)] shadow-[inset_0_1px_0_rgba(245,239,224,0.05),0_1px_0_rgba(0,0,0,0.25)]"
                : "text-[var(--color-muted)] hover:bg-[var(--color-panel)]/40 hover:text-[var(--color-text)]",
            ].join(" ")}
          >
            <span
              className={
                isActive
                  ? "text-[var(--color-accent)]"
                  : "text-[var(--color-muted)] group-hover:text-[var(--color-text)]"
              }
            >
              {t.icon}
            </span>
            <span>{t.label}</span>
            {typeof t.badge === "number" && t.badge > 0 && (
              <span
                className={[
                  "ml-1 inline-flex h-5 min-w-[20px] items-center justify-center rounded-full px-1.5 text-[10px] font-semibold tabular-nums",
                  isActive
                    ? "bg-[var(--color-accent)]/20 text-[var(--color-accent)]"
                    : "bg-[var(--color-bg-elev)] text-[var(--color-muted)] group-hover:text-[var(--color-text)]",
                ].join(" ")}
              >
                {t.badge}
              </span>
            )}
            {isActive && (
              <span
                aria-hidden
                className="absolute inset-x-3 -bottom-px h-[2px] rounded-full bg-[var(--color-accent)]/80"
              />
            )}
          </button>
        );
      })}
    </nav>
  );
}
