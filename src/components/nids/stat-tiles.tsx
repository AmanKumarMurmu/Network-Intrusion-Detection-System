import { Activity, ShieldAlert, Siren, Waves } from "lucide-react";
import type { SecurityEvent } from "@/lib/events.functions";

function Tile({
  label,
  value,
  hint,
  icon: Icon,
  tone,
}: {
  label: string;
  value: string;
  hint: string;
  icon: typeof Activity;
  tone: "primary" | "critical" | "high" | "accent";
}) {
  const toneClass = {
    primary: "text-primary",
    critical: "text-critical",
    high: "text-high",
    accent: "text-accent",
  }[tone];

  return (
    <div className="panel p-4">
      <div className="flex items-start justify-between">
        <p className="label-mono">{label}</p>
        <Icon className={`size-4 ${toneClass}`} aria-hidden />
      </div>
      <p className="mt-3 font-mono text-3xl font-bold tracking-tight">{value}</p>
      <p className="mt-1 text-xs text-muted-foreground">{hint}</p>
    </div>
  );
}

export function StatTiles({ events }: { events: SecurityEvent[] }) {
  const attacks = events.filter((e) => e.verdict === "attack");
  const critical = attacks.filter((e) => e.risk_level === "critical").length;
  const packets = events.reduce((sum, e) => sum + e.packet_count, 0);
  const sources = new Set(attacks.map((e) => e.src_ip)).size;

  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      <Tile
        label="Flows analyzed"
        value={events.length.toLocaleString()}
        hint={`${packets.toLocaleString()} packets classified`}
        icon={Activity}
        tone="primary"
      />
      <Tile
        label="Attacks detected"
        value={attacks.length.toLocaleString()}
        hint={`${Math.round((attacks.length / Math.max(events.length, 1)) * 100)}% of analyzed traffic`}
        icon={ShieldAlert}
        tone="high"
      />
      <Tile
        label="Critical alerts"
        value={critical.toLocaleString()}
        hint="Immediate response recommended"
        icon={Siren}
        tone="critical"
      />
      <Tile
        label="Hostile sources"
        value={sources.toLocaleString()}
        hint="Distinct source IPs flagged"
        icon={Waves}
        tone="accent"
      />
    </div>
  );
}
