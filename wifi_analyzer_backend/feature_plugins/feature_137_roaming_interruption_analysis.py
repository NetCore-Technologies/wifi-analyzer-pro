"""Roaming interruption analysis: Measure disconnect-to-reconnect interruption duration for client handover event pairs."""
from __future__ import annotations
import math
import re
import statistics
from datetime import datetime, timezone

def _time(value):
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        raise ValueError("Event timestamps must be ISO-8601")
    return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result

def run(p: dict) -> dict:
    events = p.get("events", [])
    if not isinstance(events, list):
        raise ValueError("'events' must be a list")
    rows = []
    for event in events:
        if not isinstance(event, dict) or not event.get("client_mac"):
            raise ValueError("Each event needs client_mac")
        down, up = _time(event.get("disconnected_at")), _time(event.get("reconnected_at"))
        gap = (up - down).total_seconds() * 1000
        if gap < 0:
            raise ValueError("reconnected_at must not precede disconnected_at")
        rows.append({"client_mac": str(event["client_mac"]).upper(), "downtime_ms": round(gap, 2),
                     "from_bssid": event.get("from_bssid"), "to_bssid": event.get("to_bssid")})
    durations = [row["downtime_ms"] for row in rows]
    return {"interruptions": rows, "count": len(rows),
            "median_downtime_ms": statistics.median(durations) if durations else None,
            "max_downtime_ms": max(durations) if durations else None}

FEATURE = {
    "id": "F137",
    "slug": "roaming_interruption_analysis",
    "name": "Roaming interruption analysis",
    "category": "Roaming",
    "description": "Measure disconnect-to-reconnect interruption duration for client handover event pairs.",
    "parameters": {"events":"event[]"},
    "run": run,
}
