"""Protected Management Frames audit: Audit explicit PMF/802.11w states from scan or controller observations."""
from __future__ import annotations
import math
import statistics
from datetime import datetime

FEATURE = None

def run(p: dict) -> dict:
    networks = p.get("networks", [])
    if not isinstance(networks, list):
        raise ValueError("'networks' must be a list")
    allowed = {"required", "capable", "optional", "disabled", "unknown"}
    counts = {key: 0 for key in allowed}
    records = []
    for item in networks:
        if not isinstance(item, dict):
            raise ValueError("Each network must be an object")
        state = str(item.get("pmf") or "unknown").strip().lower()
        if state not in allowed:
            state = "unknown"
        counts[state] += 1
        records.append({"ssid": item.get("ssid") or "", "bssid": item.get("bssid"), "pmf": state})
    return {"records": records, "counts": counts,
            "not_required_or_disabled": counts["disabled"] + counts["optional"],
            "note": "Unknown means the source did not provide PMF evidence; it is not treated as disabled."}

FEATURE = {
    "id": "F119",
    "slug": "pmf_security_audit",
    "name": "Protected Management Frames audit",
    "category": "Security",
    "description": "Audit explicit PMF/802.11w states from scan or controller observations.",
    "parameters": {"networks":"network[]"},
    "run": run,
}
