"""Client retry rate: Calculate per-client retransmission ratios from AP-reported transmit and retry counters."""
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
        try:
            packets, retries = int(client["tx_packets"]), int(client["tx_retries"])
        except (KeyError, TypeError, ValueError):
            raise ValueError("tx_packets and tx_retries must be integers")
        if packets < 0 or retries < 0:
            raise ValueError("Packet counters must be non-negative")
        denominator = packets + retries
        rate = retries / denominator * 100 if denominator else None
        rows.append({"client_mac": str(client["client_mac"]).upper(), "tx_packets": packets,
                     "tx_retries": retries, "retry_rate_pct": round(rate, 2) if rate is not None else None})
    return {"clients": rows, "measured_clients": sum(row["retry_rate_pct"] is not None for row in rows),
            "note": "Retry rate is computed from AP-provided tx_packets and tx_retries counters."}

FEATURE = {
    "id": "F127",
    "slug": "client_retry_rate",
    "name": "Client retry rate",
    "category": "Client QoS",
    "description": "Calculate per-client retransmission ratios from AP-reported transmit and retry counters.",
    "parameters": {"clients":"client[]"},
    "run": run,
}
