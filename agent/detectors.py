"""Rule-based attack labelling and risk scoring.

The scikit-learn model answers "normal vs attack". These heuristics name the
attack class (port scan, DoS/DDoS, brute force, suspicious connection) and
convert the model confidence into a risk level for the dashboard.
"""

from __future__ import annotations

from features import AUTH_PORTS, Flow

RISK_ORDER = ["low", "medium", "high", "critical"]


def classify_attack_type(flow: Flow) -> str:
    f = flow.features()

    if f["unique_dst_ports"] >= 15 and f["syn_ratio"] >= 0.6:
        return "Port Scan"

    if f["packets_per_sec"] >= 400 and f["mean_pkt_size"] < 400:
        return "DDoS" if f["unique_dst_ports"] <= 3 and f["packet_count"] > 5000 else "DoS"

    if flow.dst_port in AUTH_PORTS and f["packets_per_sec"] >= 8 and f["packet_count"] >= 40:
        return "Brute Force"

    if f["rst_ratio"] >= 0.4 or f["auth_port_hits"] >= 1:
        return "Suspicious Connection"

    return "Anomalous Traffic"


def risk_level(attack_type: str, confidence: float, flow: Flow) -> str:
    base = {
        "DDoS": 3,
        "DoS": 2,
        "Brute Force": 2,
        "Port Scan": 1,
        "Suspicious Connection": 1,
        "Anomalous Traffic": 0,
    }.get(attack_type, 0)

    if confidence >= 0.9:
        base += 1
    elif confidence < 0.6:
        base -= 1

    if flow.features()["packets_per_sec"] > 2000:
        base += 1

    return RISK_ORDER[max(0, min(base, len(RISK_ORDER) - 1))]
