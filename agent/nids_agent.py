"""Sentinel NIDS capture agent.

Sniffs live traffic with Scapy, aggregates packets into flows, extracts
features, classifies each flow with the trained scikit-learn model, stores the
event in SQLite and forwards detections to the web dashboard.

Usage:
    sudo NIDS_INGEST_URL=https://<app>/api/public/ingest \
         NIDS_INGEST_TOKEN=<token> \
         python nids_agent.py -i eth0

Offline replay of a Wireshark capture:
    python nids_agent.py --pcap capture.pcap
"""

from __future__ import annotations

import argparse
import datetime as dt
import os

from joblib import load
from scapy.all import IP, TCP, UDP, ICMP, sniff, rdpcap

from detectors import classify_attack_type, risk_level
from features import FlowTable
from storage import connect, push_remote, save_local

SENSOR = os.environ.get("NIDS_SENSOR_NAME", "sensor-01")
MODEL_PATH = os.environ.get("NIDS_MODEL_PATH", "model.joblib")


def load_model():
    if not os.path.exists(MODEL_PATH):
        raise SystemExit(f"model not found: {MODEL_PATH} — run `python train_model.py` first")
    bundle = load(MODEL_PATH)
    return bundle["model"]


def protocol_of(pkt) -> str:
    if TCP in pkt:
        return "TCP"
    if UDP in pkt:
        return "UDP"
    if ICMP in pkt:
        return "ICMP"
    return "IP"


def handle_packet(pkt, table: FlowTable) -> None:
    if IP not in pkt:
        return
    proto = protocol_of(pkt)
    layer = pkt[TCP] if TCP in pkt else pkt[UDP] if UDP in pkt else None
    flags = str(pkt[TCP].flags) if TCP in pkt else ""
    table.observe(
        src_ip=pkt[IP].src,
        dst_ip=pkt[IP].dst,
        protocol=proto,
        size=len(pkt),
        src_port=getattr(layer, "sport", None),
        dst_port=getattr(layer, "dport", None),
        flags=flags,
    )


def flush(table: FlowTable, model, conn, quiet: bool = False) -> None:
    batch: list[dict] = []
    for flow in table.expire():
        vector = flow.vector()
        proba = float(model.predict_proba(vector)[0][1])
        is_attack = proba >= 0.5
        attack_type = classify_attack_type(flow) if is_attack else "None"
        event = {
            "occurred_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "verdict": "attack" if is_attack else "normal",
            "attack_type": attack_type,
            "risk_level": risk_level(attack_type, proba, flow) if is_attack else "low",
            "confidence": round(proba, 4),
            "packet_count": flow.packet_count,
            "byte_count": flow.byte_count,
            "sensor": SENSOR,
            "features": {k: round(v, 4) for k, v in flow.features().items()},
        }
        save_local(conn, event)
        batch.append(event)

        if is_attack and not quiet:
            print(
                f"[ALERT {event['risk_level'].upper():8}] {attack_type:22} "
                f"{flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} "
                f"({flow.protocol}) conf={proba:.2f}"
            )

    if batch:
        push_remote(batch)


def main() -> None:
    parser = argparse.ArgumentParser(description="Sentinel NIDS capture agent")
    parser.add_argument("-i", "--iface", help="interface to sniff (e.g. eth0)")
    parser.add_argument("--pcap", help="analyze a pcap file instead of live capture")
    parser.add_argument("--window", type=float, default=10.0, help="flow window in seconds")
    parser.add_argument("--bpf", default="ip", help="BPF capture filter")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    model = load_model()
    conn = connect()
    table = FlowTable(window_seconds=args.window)

    if args.pcap:
        for pkt in rdpcap(args.pcap):
            handle_packet(pkt, table)
        table.window = 0.0
        flush(table, model, conn, args.quiet)
        print("pcap analysis complete")
        return

    print(f"sniffing on {args.iface or 'default iface'} (Ctrl+C to stop)")
    try:
        sniff(
            iface=args.iface,
            filter=args.bpf,
            store=False,
            prn=lambda pkt: (handle_packet(pkt, table), flush(table, model, conn, args.quiet)),
        )
    except KeyboardInterrupt:
        pass
    finally:
        table.window = 0.0
        flush(table, model, conn, args.quiet)
        conn.close()
        print("sensor stopped")


if __name__ == "__main__":
    main()
