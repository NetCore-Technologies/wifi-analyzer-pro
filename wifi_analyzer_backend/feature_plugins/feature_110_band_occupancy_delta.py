"""Band occupancy delta: Compare per-band BSS observation counts between two scans."""
from __future__ import annotations
import math
import statistics
from datetime import datetime

FEATURE = None

def run(p: dict) -> dict:
    output = []
    for label in ("previous", "current"):
        if not isinstance(p.get(label, []), list):
            raise ValueError(f"'{label}' must be a list")
    previous, current = p.get("previous", []), p.get("current", [])
    bands = ("2.4GHz", "5GHz", "6GHz", "unknown")
    for band in bands:
        before = sum(1 for item in previous if isinstance(item, dict) and item.get("band", "unknown") == band)
        after = sum(1 for item in current if isinstance(item, dict) and item.get("band", "unknown") == band)
        output.append({"band": band, "previous_count": before, "current_count": after, "delta": after - before})
    return {"bands": output, "previous_total": len(previous), "current_total": len(current)}

FEATURE = {
    "id": "F110",
    "slug": "band_occupancy_delta",
    "name": "Band occupancy delta",
    "category": "RF planning",
    "description": "Compare per-band BSS observation counts between two scans.",
    "parameters": {"previous":"network[]","current":"network[]"},
    "run": run,
}
