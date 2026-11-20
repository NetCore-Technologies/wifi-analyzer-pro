"""Target Wake Time summary: Summarise explicitly advertised and active 802.11ax Target Wake Time sessions."""
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
            raise ValueError("Each client needs client_mac")
        supported = client.get("twt_supported")
        active = client.get("twt_active")
        interval = client.get("twt_interval_ms")
        duration = client.get("twt_duration_ms")
        if interval is not None and (not math.isfinite(float(interval)) or float(interval) <= 0):
            raise ValueError("twt_interval_ms must be positive")
        if duration is not None and (not math.isfinite(float(duration)) or float(duration) < 0):
            raise ValueError("twt_duration_ms must be non-negative")
        rows.append({"client_mac": str(client["client_mac"]).upper(),
                     "twt_supported": supported if isinstance(supported, bool) else None,
                     "twt_active": active if isinstance(active, bool) else None,
                     "twt_interval_ms": interval, "twt_duration_ms": duration})
    return {"clients": rows, "supported_count": sum(row["twt_supported"] is True for row in rows),
            "active_count": sum(row["twt_active"] is True for row in rows),
            "unknown_support_count": sum(row["twt_supported"] is None for row in rows)}

FEATURE = {
    "id": "F131",
    "slug": "twt_power_save_summary",
    "name": "Target Wake Time summary",
    "category": "PHY analysis",
    "description": "Summarise explicitly advertised and active 802.11ax Target Wake Time sessions.",
    "parameters": {"clients":"client[]"},
    "run": run,
}
