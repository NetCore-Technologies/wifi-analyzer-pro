"""Regulatory channel allowlist check: Compare observed channels against an OS/controller-supplied regional allowlist."""
from __future__ import annotations
import math
import statistics
from datetime import datetime

FEATURE = None

def run(p: dict) -> dict:
    band = str(p.get("band") or "")
    allowed = p.get("allowed_channels")
    networks = p.get("networks", [])
    if band not in ("2.4GHz", "5GHz", "6GHz"):
        raise ValueError("'band' must be 2.4GHz, 5GHz or 6GHz")
    if not isinstance(allowed, list) or not isinstance(networks, list):
        raise ValueError("allowed_channels and networks must be lists")
    try:
        allowed_set = {int(value) for value in allowed}
    except (TypeError, ValueError):
        raise ValueError("allowed_channels must contain integers")
    observed = []
    for item in networks:
        if not isinstance(item, dict):
            raise ValueError("Each network must be an object")
        if item.get("band") != band:
            continue
        try:
            channel = int(item.get("channel", item.get("ch")))
        except (TypeError, ValueError):
            continue
        if channel > 0:
            observed.append({"ssid": item.get("ssid") or "", "bssid": item.get("bssid"), "channel": channel})
    outside = [item for item in observed if item["channel"] not in allowed_set]
    return {"band": band, "allowed_channels": sorted(allowed_set), "observed_count": len(observed),
            "outside_allowlist": outside, "outside_count": len(outside),
            "note": "The allowlist must come from the correct country code/regulatory database for this device."}

FEATURE = {
    "id": "F120",
    "slug": "regulatory_channel_allowlist_check",
    "name": "Regulatory channel allowlist check",
    "category": "RF planning",
    "description": "Compare observed channels against an OS/controller-supplied regional allowlist.",
    "parameters": {"band":"string","allowed_channels":"integer[]","networks":"network[]"},
    "run": run,
}
