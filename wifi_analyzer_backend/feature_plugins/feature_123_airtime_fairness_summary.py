"""Airtime fairness summary: Calculate measured per-client airtime allocation and Jain fairness from AP/controller counters."""
from __future__ import annotations
import math
import re
import statistics
from datetime import datetime, timezone

def run(p: dict) -> dict:
    clients = p.get("clients", [])
    if not isinstance(clients, list):
        raise ValueError("'clients' must be a list")
    rows = []
    for client in clients:
        if not isinstance(client, dict) or not client.get("client_mac"):
            raise ValueError("Each record needs client_mac")
        tx = float(client.get("tx_airtime_ms", 0))
        rx = float(client.get("rx_airtime_ms", 0))
        if not math.isfinite(tx) or not math.isfinite(rx) or tx < 0 or rx < 0:
            raise ValueError("Airtime counters must be finite and non-negative")
        rows.append({"client_mac": str(client["client_mac"]).upper(), "tx_airtime_ms": tx,
                     "rx_airtime_ms": rx, "total_airtime_ms": tx + rx})
    total = sum(row["total_airtime_ms"] for row in rows)
    fairness = (total * total) / (len(rows) * sum(row["total_airtime_ms"] ** 2 for row in rows)) if rows and any(row["total_airtime_ms"] for row in rows) else None
    for row in rows:
        row["airtime_share_pct"] = round(row["total_airtime_ms"] / total * 100, 2) if total else None
    return {"clients": rows, "total_airtime_ms": total, "jain_fairness_index": round(fairness, 4) if fairness is not None else None,
            "note": "Uses supplied AP/controller airtime counters; scan RSSI cannot provide airtime fairness."}

FEATURE = {
    "id": "F123",
    "slug": "airtime_fairness_summary",
    "name": "Airtime fairness summary",
    "category": "Client QoS",
    "description": "Calculate measured per-client airtime allocation and Jain fairness from AP/controller counters.",
    "parameters": {"clients":"client[]"},
    "run": run,
}
