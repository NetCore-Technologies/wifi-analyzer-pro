"""PHY rate asymmetry: Compare measured uplink and downlink PHY rates for associated clients."""
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
            tx, rx = float(client["tx_rate_mbps"]), float(client["rx_rate_mbps"])
        except (KeyError, TypeError, ValueError):
            raise ValueError("tx_rate_mbps and rx_rate_mbps are required")
        if not math.isfinite(tx) or not math.isfinite(rx) or tx < 0 or rx < 0:
            raise ValueError("PHY rates must be finite and non-negative")
        difference = round(tx - rx, 2)
        rows.append({"client_mac": str(client["client_mac"]).upper(), "tx_rate_mbps": tx,
                     "rx_rate_mbps": rx, "tx_minus_rx_mbps": difference,
                     "faster_direction": "uplink" if difference > 0 else "downlink" if difference < 0 else "equal"})
    return {"clients": rows, "client_count": len(rows),
            "note": "Negotiated PHY rates are not application throughput measurements."}

FEATURE = {
    "id": "F128",
    "slug": "phy_rate_asymmetry",
    "name": "PHY rate asymmetry",
    "category": "Client QoS",
    "description": "Compare measured uplink and downlink PHY rates for associated clients.",
    "parameters": {"clients":"client[]"},
    "run": run,
}
