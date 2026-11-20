"""Same-SSID band presence: Group visible SSIDs by advertised band and count their BSSID observations."""
from __future__ import annotations
import math
import statistics
from datetime import datetime

FEATURE = None

def run(p: dict) -> dict:
    items = p.get("networks", [])
    if not isinstance(items, list):
        raise ValueError("'networks' must be a list")
    groups = {}
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("Each network must be an object")
        ssid = str(item.get("ssid") or "").strip()
        if not ssid:
            continue
        band = str(item.get("band") or "unknown")
        entry = groups.setdefault(ssid, {})
        entry.setdefault(band, set()).add(str(item.get("bssid") or "").upper())
    result = []
    for ssid, bands in sorted(groups.items()):
        result.append({"ssid": ssid, "bands": [
            {"band": band, "bssid_count": len(addresses)}
            for band, addresses in sorted(bands.items())
        ]})
    return {"ssids": result, "ssid_count": len(result)}

FEATURE = {
    "id": "F101",
    "slug": "same_ssid_band_presence",
    "name": "Same-SSID band presence",
    "category": "Roaming",
    "description": "Group visible SSIDs by advertised band and count their BSSID observations.",
    "parameters": {"networks":"network[]"},
    "run": run,
}
