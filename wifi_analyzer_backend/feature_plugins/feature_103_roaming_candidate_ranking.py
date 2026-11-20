"""Roaming candidate ranking: Rank same-SSID BSSIDs by measured signal improvement over the connected BSSID."""
from __future__ import annotations
import math
import statistics
from datetime import datetime

FEATURE = None

def run(p: dict) -> dict:
    items = p.get("networks", [])
    current = str(p.get("current_bssid") or "").replace("-", ":").upper()
    if not isinstance(items, list) or not current:
        raise ValueError("'networks' list and 'current_bssid' are required")
    minimum = number(p.get("min_improvement_db", 8), 8)
    if minimum < 0 or minimum > 60:
        raise ValueError("'min_improvement_db' must be between 0 and 60")
    records = [item for item in items if isinstance(item, dict)]
    active = next((item for item in records if str(item.get("bssid") or "").upper() == current), None)
    if active is None:
        raise ValueError("Current BSSID was not present in the observations")
    try:
        active_rssi = float(active["rssi"])
    except (KeyError, TypeError, ValueError):
        raise ValueError("Current BSSID requires a measured RSSI")
    ssid = str(active.get("ssid") or "")
    candidates = []
    for item in records:
        bssid = str(item.get("bssid") or "").upper()
        if bssid == current or not bssid or str(item.get("ssid") or "") != ssid:
            continue
        try:
            rssi = float(item["rssi"])
        except (KeyError, TypeError, ValueError):
            continue
        if not math.isfinite(rssi):
            continue
        improvement = round(rssi - active_rssi, 1)
        if improvement >= minimum:
            candidates.append({"bssid": bssid, "band": item.get("band"), "rssi_dbm": rssi, "improvement_db": improvement})
    candidates.sort(key=lambda item: (-item["improvement_db"], item["bssid"]))
    return {"ssid": ssid, "current_bssid": current, "current_rssi_dbm": active_rssi,
            "candidates": candidates, "note": "Candidate ranking only; roaming policy and client-side measurements may differ."}

FEATURE = {
    "id": "F103",
    "slug": "roaming_candidate_ranking",
    "name": "Roaming candidate ranking",
    "category": "Roaming",
    "description": "Rank same-SSID BSSIDs by measured signal improvement over the connected BSSID.",
    "parameters": {"networks":"network[]","current_bssid":"MAC","min_improvement_db":"number"},
    "run": run,
}
