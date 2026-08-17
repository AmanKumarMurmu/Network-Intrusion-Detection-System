import { AlertTriangle } from "lucide-react";
import type { SecurityEvent } from "@/lib/events.functions";
import { RiskBadge } from "./risk-badge";

function ago(iso: string) {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.round(diff / 60000);
  if (mins < 60) return `${Math.max(mins, 0)}m ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

export function AlertsFeed({ events }: { events: SecurityEvent[] }) {
  const alerts = events
    .filter((e) => e.verdict === "attack" && ["critical", "high"].includes(e.risk_level))
    .slice(0, 6);

  return (
    <section className="panel p-4">
      <div className="flex items-center gap-2">
        <AlertTriangle className="size-4 text-critical" aria-hidden />
        <h2 className="font-mono text-sm font-semibold tracking-wide">Active alerts</h2>
      </div>

      <ul className="mt-4 space-y-3">
        {alerts.map((e) => (
          <li key={e.id} className="rounded-lg border border-border/70 bg-background/40 p-3">
            <div className="flex items-center justify-between gap-2">
              <p className="text-sm font-semibold">{e.attack_type}</p>
              <RiskBadge level={e.risk_level} />
            </div>
            <p className="mt-1.5 font-mono text-xs text-muted-foreground">
              {e.src_ip} → {e.dst_ip}:{e.dst_port ?? "—"} / {e.protocol}
            </p>
            <p className="mt-1 text-xs text-muted-foreground">
              {ago(e.occurred_at)} · model confidence {(Number(e.confidence) * 100).toFixed(0)}%
            </p>
          </li>
        ))}
        {alerts.length === 0 && (
          <li className="rounded-lg border border-border/70 bg-background/40 p-4 text-sm text-muted-foreground">
            No high-severity alerts. Traffic looks clean.
          </li>
        )}
      </ul>
    </section>
  );
}
