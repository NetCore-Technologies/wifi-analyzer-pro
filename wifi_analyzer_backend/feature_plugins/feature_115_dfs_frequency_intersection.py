"""DFS frequency intersection: Check whether a nominal 5 GHz channel span intersects the commonly used DFS frequency range."""
from __future__ import annotations
import math
import statistics
from datetime import datetime

FEATURE = None

def run(p: dict) -> dict:
    try:
        center, width = float(p["center_frequency_mhz"]), float(p["width_mhz"])
    except (KeyError, TypeError, ValueError):
        raise ValueError("center_frequency_mhz and width_mhz must be numeric")
    if not math.isfinite(center) or not math.isfinite(width) or width <= 0:
        raise ValueError("Frequency and width must be finite; width must be positive")
    low, high = center - width / 2, center + width / 2
    dfs_low, dfs_high = 5260.0, 5700.0
    overlap = max(0.0, min(high, dfs_high) - max(low, dfs_low))
    return {"span_mhz": [low, high], "common_dfs_range_mhz": [dfs_low, dfs_high],
            "intersects_common_dfs_range": overlap > 0, "overlap_mhz": round(overlap, 2),
            "note": "This identifies a frequency-range intersection; local regulatory requirements must be checked separately."}

FEATURE = {
    "id": "F115",
    "slug": "dfs_frequency_intersection",
    "name": "DFS frequency intersection",
    "category": "RF planning",
    "description": "Check whether a nominal 5 GHz channel span intersects the commonly used DFS frequency range.",
    "parameters": {"center_frequency_mhz":"number","width_mhz":"number"},
    "run": run,
}
