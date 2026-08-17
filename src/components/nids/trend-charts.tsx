import { useMemo } from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { SecurityEvent } from "@/lib/events.functions";

const attackColors = [
  "var(--chart-1)",
  "var(--chart-2)",
  "var(--chart-3)",
  "var(--chart-4)",
  "var(--chart-5)",
];

const axis = {
  stroke: "var(--muted-foreground)",
  fontSize: 11,
  fontFamily: "var(--font-mono)",
};

const tooltipStyle = {
  background: "var(--popover)",
  border: "1px solid var(--border)",
  borderRadius: 8,
  fontSize: 12,
  fontFamily: "var(--font-mono)",
  color: "var(--popover-foreground)",
};

export function TrendCharts({ events }: { events: SecurityEvent[] }) {
  const timeline = useMemo(() => {
    const buckets = new Map<string, { label: string; attacks: number; normal: number }>();
    for (let i = 23; i >= 0; i--) {
      const d = new Date(Date.now() - i * 3600_000);
      d.setMinutes(0, 0, 0);
      buckets.set(d.toISOString(), {
        label: `${String(d.getHours()).padStart(2, "0")}:00`,
        attacks: 0,
        normal: 0,
      });
    }
    for (const e of events) {
      const d = new Date(e.occurred_at);
      d.setMinutes(0, 0, 0);
      const bucket = buckets.get(d.toISOString());
      if (!bucket) continue;
      if (e.verdict === "attack") bucket.attacks += 1;
      else bucket.normal += 1;
    }
    return [...buckets.values()];
  }, [events]);

  const byType = useMemo(() => {
    const counts = new Map<string, number>();
    for (const e of events) {
      if (e.verdict !== "attack") continue;
      counts.set(e.attack_type, (counts.get(e.attack_type) ?? 0) + 1);
    }
    return [...counts.entries()]
      .map(([type, count]) => ({ type, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 6);
  }, [events]);

  return (
    <div className="grid gap-3 lg:grid-cols-5">
      <section className="panel p-4 lg:col-span-3">
        <h2 className="font-mono text-sm font-semibold tracking-wide">Attack trend · last 24h</h2>
        <p className="mt-1 text-xs text-muted-foreground">
          Classified flows per hour, attack vs. normal
        </p>
        <div className="mt-4 h-64">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={timeline}>
              <defs>
                <linearGradient id="attackFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--critical)" stopOpacity={0.55} />
                  <stop offset="100%" stopColor="var(--critical)" stopOpacity={0.02} />
                </linearGradient>
                <linearGradient id="normalFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--primary)" stopOpacity={0.4} />
                  <stop offset="100%" stopColor="var(--primary)" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="label" tick={axis} tickLine={false} axisLine={false} interval={3} />
              <YAxis tick={axis} tickLine={false} axisLine={false} allowDecimals={false} width={28} />
              <Tooltip contentStyle={tooltipStyle} />
              <Area
                type="monotone"
                dataKey="normal"
                stroke="var(--primary)"
                fill="url(#normalFill)"
                strokeWidth={2}
              />
              <Area
                type="monotone"
                dataKey="attacks"
                stroke="var(--critical)"
                fill="url(#attackFill)"
                strokeWidth={2}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </section>

      <section className="panel p-4 lg:col-span-2">
        <h2 className="font-mono text-sm font-semibold tracking-wide">Attacks by category</h2>
        <p className="mt-1 text-xs text-muted-foreground">Detections grouped by classifier label</p>
        <div className="mt-4 h-64">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={byType} layout="vertical" margin={{ left: 8 }}>
              <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" horizontal={false} />
              <XAxis type="number" tick={axis} tickLine={false} axisLine={false} allowDecimals={false} />
              <YAxis
                type="category"
                dataKey="type"
                tick={axis}
                tickLine={false}
                axisLine={false}
                width={132}
              />
              <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "var(--surface-2)" }} />
              <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                {byType.map((entry, i) => (
                  <Cell key={entry.type} fill={attackColors[i % attackColors.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </section>
    </div>
  );
}
