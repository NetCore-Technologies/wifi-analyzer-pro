"""Band-steering evidence: Compare measured RSSI for the same SSID across bands without inferring AP steering decisions."""
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
        band = str(item.get("band") or "unknown")
        try:
            rssi = float(item["rssi"])
        except (KeyError, TypeError, ValueError):
            continue
        if not math.isfinite(rssi):
            continue
        if ssid:
            groups.setdefault(ssid, {}).setdefault(band, []).append(rssi)
    comparisons = []
    for ssid, bands in sorted(groups.items()):
        if len(bands) < 2:
            continue
        measurements = [
            {"band": band, "strongest_rssi_dbm": max(values), "observations": len(values)}
            for band, values in sorted(bands.items())
        ]
        strongest = max(measurements, key=lambda value: value["strongest_rssi_dbm"])
        weakest = min(measurements, key=lambda value: value["strongest_rssi_dbm"])
        comparisons.append({
            "ssid": ssid, "bands": measurements,
            "strongest_observed_band": strongest["band"],
            "rssi_spread_db": round(strongest["strongest_rssi_dbm"] - weakest["strongest_rssi_dbm"], 1),
        })
    return {"comparisons": comparisons, "note": "Scanner RSSI comparisons do not prove client band-steering decisions."}

FEATURE = {
    "id": "F102",
    "slug": "band_steering_evidence",
    "name": "Band-steering evidence",
    "category": "Roaming",
    "description": "Compare measured RSSI for the same SSID across bands without inferring AP steering decisions.",
    "parameters": {"networks":"network[]"},
    "run": run,
}
