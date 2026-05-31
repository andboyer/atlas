import clsx from "clsx";
import type { UserMode } from "../types";
import { useApp } from "../store";

const modes: { id: UserMode; label: string; hint: string }[] = [
  { id: "simple", label: "Simple", hint: "Plain language, top fixes" },
  { id: "pro", label: "Pro", hint: "Live charts & full details" },
  { id: "admin", label: "Admin", hint: "Network map & reports" },
];

export function ModeToggle() {
  const mode = useApp((s) => s.mode);
  const setMode = useApp((s) => s.setMode);
  return (
    <div className="inline-flex rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)] p-1">
      {modes.map((m) => (
        <button
          key={m.id}
          onClick={() => setMode(m.id)}
          title={m.hint}
          className={clsx(
            "rounded-md px-3 py-1.5 text-sm font-medium transition-colors",
            mode === m.id
              ? "bg-[var(--color-accent)] text-slate-900"
              : "text-[var(--color-muted)] hover:text-[var(--color-text)]",
          )}
        >
          {m.label}
        </button>
      ))}
    </div>
  );
}
