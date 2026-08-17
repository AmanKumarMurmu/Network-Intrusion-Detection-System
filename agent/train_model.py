"""Train the Normal/Attack traffic classifier.

Builds a labelled dataset of flow feature vectors (synthetic profiles for
normal traffic, port scans, DoS/DDoS floods and brute-force bursts), fits a
RandomForest inside a scaling pipeline and writes model.joblib.

Swap `build_dataset()` for a real capture export (e.g. CIC-IDS2017 /
NSL-KDD columns mapped onto FEATURE_NAMES) when you have labelled data.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from joblib import dump
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from features import FEATURE_NAMES

RNG = np.random.default_rng(42)
MODEL_PATH = "model.joblib"


def _rows(n: int, spec: dict[str, tuple[float, float]], label: int) -> pd.DataFrame:
    data = {
        name: RNG.uniform(*spec.get(name, (0.0, 1.0)), size=n) for name in FEATURE_NAMES
    }
    frame = pd.DataFrame(data)
    frame["label"] = label
    return frame


def build_dataset(n: int = 4000) -> pd.DataFrame:
    normal = _rows(
        n,
        {
            "packet_count": (5, 300),
            "byte_count": (400, 200_000),
            "mean_pkt_size": (80, 1400),
            "duration": (1, 10),
            "packets_per_sec": (0.5, 40),
            "unique_dst_ports": (1, 4),
            "syn_ratio": (0.0, 0.2),
            "rst_ratio": (0.0, 0.1),
            "fin_ratio": (0.0, 0.3),
            "mean_iat_ms": (20, 3000),
            "auth_port_hits": (0, 1),
            "is_udp": (0, 1),
        },
        0,
    )
    port_scan = _rows(
        n // 3,
        {
            "packet_count": (200, 3000),
            "byte_count": (8_000, 200_000),
            "mean_pkt_size": (40, 90),
            "duration": (1, 12),
            "packets_per_sec": (40, 900),
            "unique_dst_ports": (20, 1000),
            "syn_ratio": (0.7, 1.0),
            "rst_ratio": (0.2, 0.9),
            "fin_ratio": (0.0, 0.1),
            "mean_iat_ms": (0.2, 20),
            "auth_port_hits": (1, 8),
            "is_udp": (0, 0.2),
        },
        1,
    )
    flood = _rows(
        n // 3,
        {
            "packet_count": (3000, 60_000),
            "byte_count": (150_000, 4_000_000),
            "mean_pkt_size": (40, 300),
            "duration": (1, 12),
            "packets_per_sec": (400, 12_000),
            "unique_dst_ports": (1, 3),
            "syn_ratio": (0.6, 1.0),
            "rst_ratio": (0.0, 0.3),
            "fin_ratio": (0.0, 0.1),
            "mean_iat_ms": (0.01, 2),
            "auth_port_hits": (0, 2),
            "is_udp": (0, 1),
        },
        1,
    )
    brute = _rows(
        n // 3,
        {
            "packet_count": (60, 2500),
            "byte_count": (6_000, 300_000),
            "mean_pkt_size": (100, 600),
            "duration": (2, 12),
            "packets_per_sec": (8, 300),
            "unique_dst_ports": (1, 2),
            "syn_ratio": (0.2, 0.7),
            "rst_ratio": (0.1, 0.6),
            "fin_ratio": (0.1, 0.6),
            "mean_iat_ms": (3, 120),
            "auth_port_hits": (1, 2),
            "is_udp": (0, 0.1),
        },
        1,
    )
    return pd.concat([normal, port_scan, flood, brute], ignore_index=True)


def main() -> None:
    df = build_dataset()
    X = df[FEATURE_NAMES].to_numpy()
    y = df["label"].to_numpy()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    model = Pipeline(
        [
            ("scaler", StandardScaler()),
            (
                "clf",
                RandomForestClassifier(
                    n_estimators=250, max_depth=14, class_weight="balanced", random_state=42
                ),
            ),
        ]
    )
    model.fit(X_train, y_train)

    print(classification_report(y_test, model.predict(X_test), target_names=["normal", "attack"]))
    dump({"model": model, "features": FEATURE_NAMES}, MODEL_PATH)
    print(f"saved -> {MODEL_PATH}")


if __name__ == "__main__":
    main()
