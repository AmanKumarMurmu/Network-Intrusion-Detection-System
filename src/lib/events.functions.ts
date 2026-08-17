import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";

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

export const listSecurityEvents = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }): Promise<SecurityEvent[]> => {
    const { data, error } = await context.supabase
      .from("security_events")
      .select(
        "id, occurred_at, src_ip, dst_ip, src_port, dst_port, protocol, verdict, attack_type, risk_level, confidence, packet_count, byte_count, sensor",
      )
      .order("occurred_at", { ascending: false })
      .limit(300);

    if (error) throw new Error(error.message);
    return (data ?? []) as SecurityEvent[];
  });
