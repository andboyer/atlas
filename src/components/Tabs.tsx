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

export function Tabs({ tabs, active, onChange }: Props) {
  return (
    <div className="border-b border-[var(--color-border)]">
      <div className="flex flex-wrap items-center gap-x-1">
        {tabs.map((t) => {
          const isActive = t.id === active;
          return (
            <button
              key={t.id}
              onClick={() => onChange(t.id)}
              className={`relative flex items-center gap-1.5 whitespace-nowrap px-3 py-2.5 text-sm font-medium transition-colors ${
                isActive
                  ? "text-[var(--color-text)]"
                  : "text-[var(--color-muted)] hover:text-[var(--color-text)]"
              }`}
            >
              {t.icon}
              <span>{t.label}</span>
              {typeof t.badge === "number" && t.badge > 0 && (
                <span
                  className={`rounded-full px-1.5 py-0.5 text-[10px] font-semibold ${
                    isActive
                      ? "bg-[var(--color-accent)]/20 text-[var(--color-accent)]"
                      : "bg-[var(--color-panel-2)] text-[var(--color-muted)]"
                  }`}
                >
                  {t.badge}
                </span>
              )}
              {isActive && (
                <span className="absolute -bottom-px left-2 right-2 h-0.5 rounded-full bg-[var(--color-accent)]" />
              )}
            </button>
          );
        })}
      </div>
    </div>
  );
}
