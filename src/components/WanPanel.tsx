import { Globe } from "lucide-react";
import { useApp } from "../store";

export function WanPanel() {
  const wan = useApp((s) => s.lastScan?.wan ?? null);

  if (!wan) return null;

  return (
    <div className="rounded-2xl border border-[var(--color-border)] bg-[var(--color-panel)] p-5">
      <div className="mb-3 flex items-center gap-2">
        <Globe className="h-4 w-4 text-[var(--color-accent)]" />
        <h2 className="text-sm font-semibold uppercase tracking-wide text-[var(--color-muted)]">
          Internet egress
        </h2>
        {wan.dual_stack ? (
          <span className="ml-auto rounded-full bg-emerald-500/15 px-2.5 py-0.5 text-xs text-emerald-300">
            dual-stack
          </span>
        ) : (
          <span className="ml-auto rounded-full bg-amber-500/15 px-2.5 py-0.5 text-xs text-amber-300">
            IPv4-only
          </span>
        )}
      </div>
      <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
        {wan.public_ipv4 && (
          <Row label="Public IPv4" value={<span className="font-mono">{wan.public_ipv4}</span>} />
        )}
        {wan.public_ipv6 && (
          <Row label="Public IPv6" value={<span className="font-mono text-xs">{wan.public_ipv6}</span>} />
        )}
        {wan.isp && (
          <Row
            label="ISP"
            value={
              <>
                {wan.isp}
                {wan.asn != null && (
                  <span className="ml-2 text-xs text-[var(--color-muted)]">AS{wan.asn}</span>
                )}
              </>
            }
          />
        )}
        {(wan.country || wan.region) && (
          <Row
            label="Location"
            value={[wan.region, wan.country].filter(Boolean).join(", ")}
          />
        )}
      </dl>
    </div>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-baseline gap-2">
      <dt className="w-24 shrink-0 text-xs uppercase tracking-wide text-[var(--color-muted)]">
        {label}
      </dt>
      <dd className="text-[var(--color-text)]">{value}</dd>
    </div>
  );
}
