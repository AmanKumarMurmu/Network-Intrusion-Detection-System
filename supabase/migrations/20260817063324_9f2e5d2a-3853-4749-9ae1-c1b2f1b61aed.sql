CREATE TABLE public.security_events (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  occurred_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  src_ip TEXT NOT NULL,
  dst_ip TEXT NOT NULL,
  src_port INTEGER,
  dst_port INTEGER,
  protocol TEXT NOT NULL DEFAULT 'TCP',
  verdict TEXT NOT NULL DEFAULT 'attack',
  attack_type TEXT NOT NULL DEFAULT 'Unknown',
  risk_level TEXT NOT NULL DEFAULT 'low',
  confidence NUMERIC(5,4) NOT NULL DEFAULT 0,
  packet_count INTEGER NOT NULL DEFAULT 0,
  byte_count BIGINT NOT NULL DEFAULT 0,
  sensor TEXT NOT NULL DEFAULT 'sensor-01',
  features JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE INDEX security_events_occurred_at_idx ON public.security_events (occurred_at DESC);
CREATE INDEX security_events_attack_type_idx ON public.security_events (attack_type);

GRANT SELECT ON public.security_events TO anon;
GRANT SELECT ON public.security_events TO authenticated;
GRANT ALL ON public.security_events TO service_role;

ALTER TABLE public.security_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Anyone can view security events"
  ON public.security_events FOR SELECT
  TO anon, authenticated
  USING (true);

INSERT INTO public.security_events (occurred_at, src_ip, dst_ip, src_port, dst_port, protocol, verdict, attack_type, risk_level, confidence, packet_count, byte_count, sensor, features) VALUES
  (now() - interval '9 minutes',  '203.0.113.45', '192.168.1.10', 51244, 22,   'TCP',  'attack', 'Brute Force',  'critical', 0.9720, 842,  61240,  'sensor-01', '{"failed_logins": 118, "avg_iat_ms": 42}'),
  (now() - interval '27 minutes', '198.51.100.7', '192.168.1.10', 40921, 3389, 'TCP',  'attack', 'Port Scan',    'high',     0.9310, 1204, 74300,  'sensor-01', '{"unique_ports": 964, "syn_ratio": 0.98}'),
  (now() - interval '52 minutes', '45.155.205.12','192.168.1.20', 0,     80,   'TCP',  'attack', 'DDoS',         'critical', 0.9880, 48210,3120400,'sensor-01', '{"pps": 8400, "syn_ratio": 0.99}'),
  (now() - interval '1 hour 18 minutes', '192.168.1.34','8.8.8.8', 53311, 53,  'UDP',  'normal', 'None',         'low',      0.1200, 12,   1420,   'sensor-01', '{"pps": 3}'),
  (now() - interval '2 hours 5 minutes', '10.0.0.88', '192.168.1.10', 33122, 21, 'TCP','attack', 'Brute Force',  'medium',   0.7640, 320,  21100,  'sensor-01', '{"failed_logins": 41}'),
  (now() - interval '3 hours 12 minutes','185.220.101.9','192.168.1.15',44120,445,'TCP','attack','Suspicious Connection','high',0.8450, 96, 8800, 'sensor-01', '{"tor_exit": true}'),
  (now() - interval '4 hours 40 minutes','172.16.4.21','192.168.1.10', 51999, 8080,'TCP','normal','None',        'low',      0.0900, 58,   40200,  'sensor-01', '{"pps": 6}'),
  (now() - interval '6 hours 15 minutes','91.219.236.4','192.168.1.20', 0,    443, 'TCP', 'attack','DoS',        'high',     0.9110, 18400,921000, 'sensor-01', '{"pps": 3100}'),
  (now() - interval '9 hours 30 minutes','203.0.113.77','192.168.1.12', 39877, 23, 'TCP', 'attack','Port Scan',  'medium',   0.6890, 410,  25600,  'sensor-01', '{"unique_ports": 212}'),
  (now() - interval '20 hours',          '192.168.1.55','1.1.1.1',      50122, 53, 'UDP', 'normal','None',       'low',      0.0400, 9,    980,    'sensor-01', '{"pps": 2}'),
  (now() - interval '1 day 4 hours',     '141.98.10.60','192.168.1.10', 42001, 22, 'TCP', 'attack','Brute Force','critical', 0.9640, 1520, 98400,  'sensor-01', '{"failed_logins": 260}'),
  (now() - interval '2 days 3 hours',    '196.19.10.3', '192.168.1.18', 43122, 3306,'TCP', 'attack','Suspicious Connection','medium',0.5920, 74, 6100,'sensor-01', '{"geo": "unknown"}');