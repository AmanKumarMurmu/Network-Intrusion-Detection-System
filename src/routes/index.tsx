import { createFileRoute } from "@tanstack/react-router";
import { queryOptions, useSuspenseQuery } from "@tanstack/react-query";
import { Radar, RefreshCw, Terminal } from "lucide-react";
import { listSecurityEvents } from "@/lib/events.functions";
import { StatTiles } from "@/components/nids/stat-tiles";
import { TrendCharts } from "@/components/nids/trend-charts";
import { EventsTable } from "@/components/nids/events-table";
import { AlertsFeed } from "@/components/nids/alerts-feed";

const eventsQuery = queryOptions({
  queryKey: ["security-events"],
  queryFn: () => listSecurityEvents(),
  refetchInterval: 20_000,
});

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Sentinel NIDS — AI Intrusion Detection Console" },
      {
        name: "description",
        content:
          "Live intrusion detection dashboard: ML traffic verdicts, port scan, DoS/DDoS and brute-force alerts with risk levels and 24h attack trends.",
      },
      { property: "og:title", content: "Sentinel NIDS — AI Intrusion Detection Console" },
      {
        property: "og:description",
        content:
          "Machine-learning classified network flows, security alerts and attack trend analytics in one console.",
      },
    ],
  }),
  loader: ({ context }) => context.queryClient.ensureQueryData(eventsQuery),
  component: Dashboard,
  errorComponent: () => (
    <main className="flex min-h-screen items-center justify-center p-6">
      <div className="panel max-w-md p-6 text-center">
        <h1 className="text-lg font-semibold">Sensor feed unavailable</h1>
        <p className="mt-2 text-sm text-muted-foreground">
          The event store could not be reached. Refresh to retry.
        </p>
      </div>
    </main>
  ),
  notFoundComponent: () => (
    <main className="flex min-h-screen items-center justify-center p-6">
      <p className="text-sm text-muted-foreground">Not found.</p>
    </main>
  ),
});

function Dashboard() {
  const { data: events, isFetching, refetch } = useSuspenseQuery(eventsQuery);
  const latest = events[0]?.occurred_at;

  return (
    <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:py-10">
      <header className="panel glow flex flex-wrap items-center justify-between gap-4 p-5">
        <div className="flex items-center gap-3">
          <div className="flex size-11 items-center justify-center rounded-xl border border-primary/40 bg-primary/10">
            <Radar className="size-5 text-primary" aria-hidden />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight sm:text-2xl">
              Sentinel NIDS
              <span className="ml-2 font-mono text-xs font-medium text-primary">v1.0</span>
            </h1>
            <p className="text-sm text-muted-foreground">
              AI-powered network intrusion detection · Scapy sensor + scikit-learn classifier
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="text-right">
            <p className="label-mono">Last event</p>
            <p className="font-mono text-xs">
              {latest ? new Date(latest).toLocaleString() : "awaiting traffic"}
            </p>
          </div>
          <button
            onClick={() => refetch()}
            className="inline-flex items-center gap-2 rounded-md border border-border bg-surface-2 px-3 py-2 font-mono text-xs uppercase tracking-wider text-foreground transition-colors hover:border-ring"
          >
            <RefreshCw className={`size-3.5 ${isFetching ? "animate-spin" : ""}`} aria-hidden />
            Sync
          </button>
        </div>
      </header>

      <div className="mt-4">
        <StatTiles events={events} />
      </div>

      <div className="mt-4">
        <TrendCharts events={events} />
      </div>

      <div className="mt-4 grid gap-3 lg:grid-cols-5">
        <div className="lg:col-span-3">
          <EventsTable events={events} />
        </div>
        <div className="space-y-3 lg:col-span-2">
          <AlertsFeed events={events} />
          <section className="panel p-4">
            <div className="flex items-center gap-2">
              <Terminal className="size-4 text-primary" aria-hidden />
              <h2 className="font-mono text-sm font-semibold tracking-wide">Connect a live sensor</h2>
            </div>
            <p className="mt-2 text-xs text-muted-foreground">
              Run the Python capture agent on your Linux host. It sniffs packets with Scapy, builds
              flow features with Pandas/NumPy, classifies them with the scikit-learn model, stores
              them locally in SQLite and streams detections to this dashboard.
            </p>
            <pre className="mt-3 overflow-x-auto rounded-lg border border-border bg-background/60 p-3 font-mono text-[11px] leading-relaxed text-muted-foreground">
              {`cd agent
pip install -r requirements.txt
python train_model.py
sudo NIDS_INGEST_URL=<dashboard>/api/public/ingest \\
     NIDS_INGEST_TOKEN=<your token> \\
     python nids_agent.py -i eth0`}
            </pre>
          </section>
        </div>
      </div>

      <footer className="mt-6 text-center font-mono text-[11px] uppercase tracking-widest text-muted-foreground">
        Events persisted in the cloud database · trends computed over the last 24 hours
      </footer>
    </main>
  );
}
