import { useMemo, useState } from "react";
import type { SecurityEvent } from "@/lib/events.functions";
import { RiskBadge, VerdictBadge } from "./risk-badge";

const filters = ["all", "attack", "normal"] as const;

function formatTime(iso: string) {
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function EventsTable({ events }: { events: SecurityEvent[] }) {
  const [filter, setFilter] = useState<(typeof filters)[number]>("all");
  const [query, setQuery] = useState("");

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return events
      .filter((e) => (filter === "all" ? true : e.verdict === filter))
      .filter(
        (e) =>
          !q ||
          e.src_ip.includes(q) ||
          e.dst_ip.includes(q) ||
          e.attack_type.toLowerCase().includes(q) ||
          e.protocol.toLowerCase().includes(q),
      )
      .slice(0, 60);
  }, [events, filter, query]);

  return (
    <section className="panel overflow-hidden">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-4 py-3">
        <h2 className="font-mono text-sm font-semibold tracking-wide">Security event log</h2>
        <div className="flex flex-wrap items-center gap-2">
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter IP / protocol / attack"
            aria-label="Filter events"
            className="h-8 w-56 rounded-md border border-input bg-background/60 px-3 font-mono text-xs text-foreground outline-none placeholder:text-muted-foreground focus:border-ring"
          />
          <div className="flex rounded-md border border-border p-0.5">
            {filters.map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`rounded px-2.5 py-1 font-mono text-[11px] uppercase tracking-wider transition-colors ${
                  filter === f
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {f}
              </button>
            ))}
          </div>
        </div>
      </header>

      <div className="overflow-x-auto">
        <table className="w-full min-w-[900px] text-left text-sm">
          <thead>
            <tr className="border-b border-border/70 bg-surface-2/60">
              {[
                "Timestamp",
                "Source",
                "Destination",
                "Proto",
                "Verdict",
                "Attack type",
                "Risk",
                "Conf.",
              ].map((h) => (
                <th key={h} className="label-mono px-4 py-2.5 font-medium">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((e) => (
              <tr key={e.id} className="border-b border-border/40 last:border-0 hover:bg-surface-2/50">
                <td className="whitespace-nowrap px-4 py-2.5 font-mono text-xs text-muted-foreground">
                  {formatTime(e.occurred_at)}
                </td>
                <td className="whitespace-nowrap px-4 py-2.5 font-mono text-xs">
                  {e.src_ip}
                  <span className="text-muted-foreground">:{e.src_port ?? "—"}</span>
                </td>
                <td className="whitespace-nowrap px-4 py-2.5 font-mono text-xs">
                  {e.dst_ip}
                  <span className="text-muted-foreground">:{e.dst_port ?? "—"}</span>
                </td>
                <td className="px-4 py-2.5 font-mono text-xs">{e.protocol}</td>
                <td className="px-4 py-2.5">
                  <VerdictBadge verdict={e.verdict} />
                </td>
                <td className="whitespace-nowrap px-4 py-2.5 text-xs">{e.attack_type}</td>
                <td className="px-4 py-2.5">
                  <RiskBadge level={e.risk_level} />
                </td>
                <td className="px-4 py-2.5 font-mono text-xs">
                  {(Number(e.confidence) * 100).toFixed(1)}%
                </td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan={8} className="px-4 py-10 text-center text-sm text-muted-foreground">
                  No events match the current filter.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}
