import { createFileRoute } from "@tanstack/react-router";
import { z } from "zod";

const eventSchema = z.object({
  occurred_at: z.string().datetime().default(() => new Date().toISOString()),
  src_ip: z.string().min(3).max(64),
  dst_ip: z.string().min(3).max(64),
  src_port: z.number().int().min(0).max(65535).nullable().default(null),
  dst_port: z.number().int().min(0).max(65535).nullable().default(null),
  protocol: z.string().min(1).max(16).default("TCP"),
  verdict: z.enum(["normal", "attack"]).default("attack"),
  attack_type: z.string().min(1).max(64).default("Unknown"),
  risk_level: z.enum(["low", "medium", "high", "critical"]).default("low"),
  confidence: z.number().min(0).max(1).default(0),
  packet_count: z.number().int().min(0).max(100_000_000).default(0),
  byte_count: z.number().int().min(0).max(1_000_000_000_000).default(0),
  sensor: z.string().min(1).max(64).default("sensor-01"),
  features: z.record(z.unknown()).default({}),
});

const bodySchema = z.object({ events: z.array(eventSchema).min(1).max(200) });

function timingSafeEqual(a: string, b: string) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export const Route = createFileRoute("/api/public/ingest")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const expected = process.env["NIDS_INGEST_TOKEN"];
        if (!expected) {
          return Response.json({ error: "Ingest endpoint not configured" }, { status: 503 });
        }
        const provided = request.headers.get("x-ingest-token") ?? "";
        if (!timingSafeEqual(provided, expected)) {
          return Response.json({ error: "Invalid ingest token" }, { status: 401 });
        }

        let json: unknown;
        try {
          json = await request.json();
        } catch {
          return Response.json({ error: "Invalid JSON body" }, { status: 400 });
        }

        const parsed = bodySchema.safeParse(json);
        if (!parsed.success) {
          return Response.json({ error: "Invalid payload" }, { status: 400 });
        }

        const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
        const { error } = await supabaseAdmin.from("security_events").insert(
          parsed.data.events.map((e) => ({
            ...e,
            features: e.features as never,
          })),
        );

        if (error) {
          console.error("ingest insert failed", error.message);
          return Response.json({ error: "Could not store events" }, { status: 500 });
        }

        return Response.json({ ok: true, stored: parsed.data.events.length });
      },
    },
  },
});
