"""Client throughput fairness: Calculate per-client transmit/receive throughput and Jain fairness from byte deltas over a measured interval."""
from __future__ import annotations
import math
import re
import statistics
from datetime import datetime, timezone

def run(p: dict) -> dict:
    clients = p.get("clients", [])
    try:
        interval = float(p["interval_seconds"])
    except (KeyError, TypeError, ValueError):
        raise ValueError("interval_seconds is required")
    if not math.isfinite(interval) or interval <= 0 or interval > 86400:
        raise ValueError("interval_seconds must be greater than 0 and at most one day")
    if not isinstance(clients, list):
        raise ValueError("'clients' must be a list")
    rows = []
    for client in clients:
        if not isinstance(client, dict) or not client.get("client_mac"):
            raise ValueError("Each record needs client_mac")
        try:
            tx = float(client["tx_bytes"])
            rx = float(client["rx_bytes"])
        except (KeyError, TypeError, ValueError):
            raise ValueError("Each record needs numeric tx_bytes and rx_bytes")
        if not math.isfinite(tx) or not math.isfinite(rx) or tx < 0 or rx < 0:
            raise ValueError("Byte counters must be finite and non-negative")
        rows.append({"client_mac": str(client["client_mac"]).upper(),
                     "tx_mbps": tx * 8 / interval / 1_000_000,
                     "rx_mbps": rx * 8 / interval / 1_000_000})
    def fairness(values):
        total = sum(values)
        return (total * total / (len(values) * sum(value * value for value in values))) if values and any(values) else None
    return {"interval_seconds": interval, "clients": rows,
            "tx_jain_fairness": round(fairness([row["tx_mbps"] for row in rows]), 4) if fairness([row["tx_mbps"] for row in rows]) is not None else None,
            "rx_jain_fairness": round(fairness([row["rx_mbps"] for row in rows]), 4) if fairness([row["rx_mbps"] for row in rows]) is not None else None}

FEATURE = {
    "id": "F124",
    "slug": "client_throughput_fairness",
    "name": "Client throughput fairness",
    "category": "Client QoS",
    "description": "Calculate per-client transmit/receive throughput and Jain fairness from byte deltas over a measured interval.",
    "parameters": {"clients":"client[]","interval_seconds":"number"},
    "run": run,
}
