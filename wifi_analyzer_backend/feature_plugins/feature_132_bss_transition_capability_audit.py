"""802.11k/v/r capability audit: Report explicit neighbour-report, BSS-transition and fast-transition capabilities per AP."""
from __future__ import annotations
import math
import re
import statistics
from datetime import datetime, timezone

def run(p: dict) -> dict:
    aps = p.get("access_points", [])
    if not isinstance(aps, list):
        raise ValueError("'access_points' must be a list")
    fields = ("dot11k_neighbor_report", "dot11v_bss_transition", "dot11r_fast_transition")
    summary = {field: {"enabled": 0, "disabled": 0, "unknown": 0} for field in fields}
    records = []
    for ap in aps:
        if not isinstance(ap, dict) or not ap.get("bssid"):
            raise ValueError("Each AP needs a bssid")
        values = {}
        for field in fields:
            value = ap.get(field)
            state = "enabled" if value is True else "disabled" if value is False else "unknown"
            summary[field][state] += 1
            values[field] = value if isinstance(value, bool) else None
        records.append({"bssid": str(ap["bssid"]).upper(), "ssid": ap.get("ssid"), **values})
    return {"access_points": records, "summary": summary,
            "note": "Capability flags must come from beacon/controller evidence; support does not prove clients use the feature."}

FEATURE = {
    "id": "F132",
    "slug": "bss_transition_capability_audit",
    "name": "802.11k/v/r capability audit",
    "category": "Roaming",
    "description": "Report explicit neighbour-report, BSS-transition and fast-transition capabilities per AP.",
    "parameters": {"access_points":"AP[]"},
    "run": run,
}
