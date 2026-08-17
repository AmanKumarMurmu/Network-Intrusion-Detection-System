"""Flow aggregation and feature extraction for the NIDS sensor.

Packets captured by Scapy are grouped into short time-window "flows" keyed by
(src_ip, dst_ip, protocol). Each flow is reduced to a numeric feature vector
that both the rule engine and the scikit-learn classifier consume.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import numpy as np

FEATURE_NAMES = [
    "packet_count",
    "byte_count",
    "mean_pkt_size",
    "duration",
    "packets_per_sec",
    "unique_dst_ports",
    "syn_ratio",
    "rst_ratio",
    "fin_ratio",
    "mean_iat_ms",
    "auth_port_hits",
    "is_udp",
]

AUTH_PORTS = {21, 22, 23, 25, 110, 143, 389, 445, 1433, 3306, 3389, 5432, 5900}


@dataclass
class Flow:
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int | None = None
    dst_port: int | None = None
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    packet_count: int = 0
    byte_count: int = 0
    syn: int = 0
    rst: int = 0
    fin: int = 0
    dst_ports: set[int] = field(default_factory=set)
    timestamps: list[float] = field(default_factory=list)

    def add(self, size: int, src_port, dst_port, flags: str, now: float) -> None:
        self.packet_count += 1
        self.byte_count += size
        self.last_seen = now
        self.timestamps.append(now)
        if src_port is not None:
            self.src_port = int(src_port)
        if dst_port is not None:
            self.dst_port = int(dst_port)
            self.dst_ports.add(int(dst_port))
        if "S" in flags and "A" not in flags:
            self.syn += 1
        if "R" in flags:
            self.rst += 1
        if "F" in flags:
            self.fin += 1

    def features(self) -> dict[str, float]:
        duration = max(self.last_seen - self.first_seen, 1e-3)
        iats = np.diff(np.array(self.timestamps)) if len(self.timestamps) > 1 else np.array([0.0])
        return {
            "packet_count": float(self.packet_count),
            "byte_count": float(self.byte_count),
            "mean_pkt_size": self.byte_count / max(self.packet_count, 1),
            "duration": duration,
            "packets_per_sec": self.packet_count / duration,
            "unique_dst_ports": float(len(self.dst_ports)),
            "syn_ratio": self.syn / max(self.packet_count, 1),
            "rst_ratio": self.rst / max(self.packet_count, 1),
            "fin_ratio": self.fin / max(self.packet_count, 1),
            "mean_iat_ms": float(np.mean(iats) * 1000.0),
            "auth_port_hits": float(len(self.dst_ports & AUTH_PORTS)),
            "is_udp": 1.0 if self.protocol == "UDP" else 0.0,
        }

    def vector(self) -> np.ndarray:
        f = self.features()
        return np.array([[f[name] for name in FEATURE_NAMES]], dtype=float)


class FlowTable:
    """Keeps flows for a rolling window and yields the expired ones."""

    def __init__(self, window_seconds: float = 10.0) -> None:
        self.window = window_seconds
        self.flows: dict[tuple[str, str, str], Flow] = {}

    def observe(self, src_ip, dst_ip, protocol, size, src_port, dst_port, flags) -> None:
        now = time.time()
        key = (src_ip, dst_ip, protocol)
        flow = self.flows.get(key)
        if flow is None:
            flow = Flow(src_ip=src_ip, dst_ip=dst_ip, protocol=protocol)
            self.flows[key] = flow
        flow.add(size, src_port, dst_port, flags, now)

    def expire(self) -> list[Flow]:
        now = time.time()
        done = [k for k, f in self.flows.items() if now - f.first_seen >= self.window]
        return [self.flows.pop(k) for k in done]
