"""Roaming stability score: Calculate a transparent heuristic from observed roam events per client and a chosen time window."""
from __future__ import annotations
import math
import statistics
from datetime import datetime
from .common import number

FEATURE = None

def run(p: dict) -> dict:
    events = p.get("events", [])
    if not isinstance(events, list):
        raise ValueError("'events' must be a list")
    hours = number(p.get("window_hours", 24), 24)
    if not math.isfinite(hours) or hours <= 0 or hours > 24 * 365:
        raise ValueError("'window_hours' must be greater than 0 and no more than one year")
    counts = {}
    for event in events:
        if not isinstance(event, dict) or event.get("event") != "roamed":
            continue
        mac = str(event.get("client_mac") or "unknown").upper()
        counts[mac] = counts.get(mac, 0) + 1
    output = []
    for mac, count in sorted(counts.items()):
        rate = count / hours
        score = max(0, min(100, round(100 - rate * 20)))
        output.append({"client_mac": mac, "roam_events": count, "window_hours": hours,
                       "roams_per_hour": round(rate, 3), "stability_score": score,
                       "score_type": "heuristic"})
    return {"clients": output, "window_hours": hours,
            "note": "Heuristic only; interpret with connection duration, signal and application telemetry."}

FEATURE = {
    "id": "F109",
    "slug": "roaming_stability_score",
    "name": "Roaming stability score",
    "category": "Roaming",
    "description": "Calculate a transparent heuristic from observed roam events per client and a chosen time window.",
    "parameters": {"events":"event[]","window_hours":"number"},
    "run": run,
}
