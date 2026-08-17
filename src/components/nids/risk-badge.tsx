const riskStyles: Record<string, string> = {
  critical: "border-critical/50 bg-critical/15 text-critical",
  high: "border-high/50 bg-high/15 text-high",
  medium: "border-medium/50 bg-medium/15 text-medium",
  low: "border-low/50 bg-low/15 text-low",
};

export function RiskBadge({ level }: { level: string }) {
  const key = level.toLowerCase();
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 font-mono text-[11px] font-medium uppercase tracking-wider ${
        riskStyles[key] ?? riskStyles["low"]
      }`}
    >
      <span className="size-1.5 rounded-full bg-current" />
      {key}
    </span>
  );
}

export function VerdictBadge({ verdict }: { verdict: string }) {
  const attack = verdict.toLowerCase() === "attack";
  return (
    <span
      className={`inline-flex items-center rounded-md border px-2 py-0.5 font-mono text-[11px] font-semibold uppercase tracking-wider ${
        attack
          ? "border-destructive/50 bg-destructive/15 text-destructive"
          : "border-safe/50 bg-safe/15 text-safe"
      }`}
    >
      {attack ? "attack" : "normal"}
    </span>
  );
}
