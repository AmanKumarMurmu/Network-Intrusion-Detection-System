import { createServerFn } from "@tanstack/react-start";
import { createClient } from "@supabase/supabase-js";
import type { Database } from "@/integrations/supabase/types";

export type SecurityEvent = {
  id: string;
  occurred_at: string;
  src_ip: string;
  dst_ip: string;
  src_port: number | null;
  dst_port: number | null;
  protocol: string;
  verdict: string;
  attack_type: string;
  risk_level: string;
  confidence: number;
  packet_count: number;
  byte_count: number;
  sensor: string;
};

export const listSecurityEvents = createServerFn({ method: "GET" }).handler(
  async (): Promise<SecurityEvent[]> => {
    const key = process.env["SUPABASE_PUBLISHABLE_KEY"]!;
    const supabasePublic = createClient<Database>(process.env["SUPABASE_URL"]!, key, {
      auth: { persistSession: false, autoRefreshToken: false },
      global: {
        fetch: (input, init) => {
          const h = new Headers(init?.headers);
          if (key.startsWith("sb_") && h.get("Authorization") === `Bearer ${key}`) {
            h.delete("Authorization");
          }
          h.set("apikey", key);
          return fetch(input, { ...init, headers: h });
        },
      },
    });

    const { data, error } = await supabasePublic
      .from("security_events")
      .select(
        "id, occurred_at, src_ip, dst_ip, src_port, dst_port, protocol, verdict, attack_type, risk_level, confidence, packet_count, byte_count, sensor",
      )
      .order("occurred_at", { ascending: false })
      .limit(300);

    if (error) throw new Error(error.message);
    return (data ?? []) as SecurityEvent[];
  },
);
