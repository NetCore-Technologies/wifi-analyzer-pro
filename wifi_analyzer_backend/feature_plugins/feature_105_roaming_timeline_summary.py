"""Roaming timeline summary: Summarise observed roaming and network-change events per client from association diffs."""
from __future__ import annotations
import math
import statistics
from datetime import datetime

FEATURE = None

def run(p: dict) -> dict:
    events = p.get("events", [])
    if not isinstance(events, list):
        raise ValueError("'events' must be a list")
    clients = {}
    for event in events:
        if not isinstance(event, dict) or not event.get("client_mac"):
            raise ValueError("Each event needs client_mac")
        mac = str(event["client_mac"]).upper()
        summary = clients.setdefault(mac, {"client_mac": mac, "roams": 0, "network_changes": 0, "connects": 0, "disconnects": 0})
        kind = event.get("event")
        if kind == "roamed":
            summary["roams"] += 1
        elif kind == "network_changed":
            summary["network_changes"] += 1
        elif kind == "connected":
            summary["connects"] += 1
        elif kind == "disconnected":
            summary["disconnects"] += 1
    output = sorted(clients.values(), key=lambda item: item["client_mac"])
    return {"clients": output, "client_count": len(output), "event_count": len(events)}

FEATURE = {
    "id": "F105",
    "slug": "roaming_timeline_summary",
    "name": "Roaming timeline summary",
    "category": "Roaming",
    "description": "Summarise observed roaming and network-change events per client from association diffs.",
    "parameters": {"events":"event[]"},
    "run": run,
}
