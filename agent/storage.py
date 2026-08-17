"""Local SQLite event store plus dashboard forwarding."""

from __future__ import annotations

import json
import os
import sqlite3
from typing import Any

import requests

DB_PATH = os.environ.get("NIDS_DB_PATH", "nids_events.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT NOT NULL,
    verdict TEXT NOT NULL,
    attack_type TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    confidence REAL NOT NULL,
    packet_count INTEGER NOT NULL,
    byte_count INTEGER NOT NULL,
    sensor TEXT NOT NULL,
    features TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_time ON security_events(occurred_at DESC);
"""


def connect(path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def save_local(conn: sqlite3.Connection, event: dict[str, Any]) -> None:
    conn.execute(
        """INSERT INTO security_events (occurred_at, src_ip, dst_ip, src_port, dst_port,
               protocol, verdict, attack_type, risk_level, confidence, packet_count,
               byte_count, sensor, features)
           VALUES (:occurred_at, :src_ip, :dst_ip, :src_port, :dst_port, :protocol,
               :verdict, :attack_type, :risk_level, :confidence, :packet_count,
               :byte_count, :sensor, :features_json)""",
        {**event, "features_json": json.dumps(event.get("features", {}))},
    )
    conn.commit()


def push_remote(events: list[dict[str, Any]]) -> bool:
    """Send events to the web dashboard ingest endpoint."""
    url = os.environ.get("NIDS_INGEST_URL")
    token = os.environ.get("NIDS_INGEST_TOKEN")
    if not url or not token or not events:
        return False
    try:
        res = requests.post(
            url,
            json={"events": events},
            headers={"x-ingest-token": token, "Content-Type": "application/json"},
            timeout=8,
        )
        if res.status_code >= 300:
            print(f"[warn] ingest failed: {res.status_code} {res.text[:200]}")
            return False
        return True
    except requests.RequestException as exc:  # network hiccup: keep sniffing
        print(f"[warn] ingest error: {exc}")
        return False
