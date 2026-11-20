"""Association roam events: Diff client association snapshots and classify roam, network-change, connect and disconnect events."""
from __future__ import annotations
import math
import statistics
from datetime import datetime

FEATURE = None

def _index(items):
    if not isinstance(items, list):
        raise ValueError("Snapshots must be lists")
    result = {}
    for item in items:
        if not isinstance(item, dict) or not item.get("client_mac"):
            raise ValueError("Each snapshot record needs client_mac")
        key = str(item["client_mac"]).replace("-", ":").upper()
        if key in result:
            raise ValueError("A client may appear only once per snapshot")
        result[key] = item
    return result

def run(p: dict) -> dict:
    previous = _index(p.get("previous", []))
    current = _index(p.get("current", []))
    events = []
    for mac in sorted(previous.keys() | current.keys()):
        before, after = previous.get(mac), current.get(mac)
        if before is None:
            event = "connected"
        elif after is None:
            event = "disconnected"
        elif str(before.get("bssid") or "").upper() != str(after.get("bssid") or "").upper():
            event = "roamed" if str(before.get("ssid") or "") == str(after.get("ssid") or "") else "network_changed"
        else:
            continue
        events.append({
            "client_mac": mac, "event": event,
            "previous_bssid": before.get("bssid") if before else None,
            "current_bssid": after.get("bssid") if after else None,
            "previous_ssid": before.get("ssid") if before else None,
            "current_ssid": after.get("ssid") if after else None,
            "timestamp": (after or before).get("timestamp"),
        })
    return {"events": events, "event_count": len(events)}

FEATURE = {
    "id": "F104",
    "slug": "association_roam_events",
    "name": "Association roam events",
    "category": "Roaming",
    "description": "Diff client association snapshots and classify roam, network-change, connect and disconnect events.",
    "parameters": {"previous":"client[]","current":"client[]"},
    "run": run,
}
