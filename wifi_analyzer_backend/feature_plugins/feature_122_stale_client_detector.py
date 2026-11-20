"""Stale client detector: Identify client records whose supplied last-seen timestamps exceed a configurable age threshold."""
from __future__ import annotations
import math
import re
import statistics
from datetime import datetime, timezone

def _time(value):
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        raise ValueError("Timestamps must use ISO-8601")
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed

def run(p: dict) -> dict:
    clients = p.get("clients", [])
    if not isinstance(clients, list):
        raise ValueError("'clients' must be a list")
    threshold = float(p.get("stale_after_seconds", 300))
    if not math.isfinite(threshold) or threshold < 1 or threshold > 2592000:
        raise ValueError("stale_after_seconds must be between 1 and 2592000")
    now = _time(p["now"]) if p.get("now") else datetime.now(timezone.utc)
    records = []
    for client in clients:
        if not isinstance(client, dict) or not (client.get("client_mac") or client.get("mac")):
            raise ValueError("Each client needs client_mac or mac")
        seen = _time(client.get("last_seen"))
        age = (now - seen).total_seconds()
        records.append({"client_mac": str(client.get("client_mac") or client.get("mac")).upper(),
                        "age_seconds": round(age, 2), "stale": age > threshold,
                        "last_seen": seen.isoformat()})
    return {"threshold_seconds": threshold, "stale_clients": [item for item in records if item["stale"]],
            "client_count": len(records), "stale_count": sum(item["stale"] for item in records),
            "future_timestamps": [item["client_mac"] for item in records if item["age_seconds"] < 0]}

FEATURE = {
    "id": "F122",
    "slug": "stale_client_detector",
    "name": "Stale client detector",
    "category": "Client operations",
    "description": "Identify client records whose supplied last-seen timestamps exceed a configurable age threshold.",
    "parameters": {"clients":"client[]","now":"ISO-8601","stale_after_seconds":"number"},
    "run": run,
}
