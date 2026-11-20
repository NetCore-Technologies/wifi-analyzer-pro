"""Frequency overlap score: Compute frequency-span overlap between two channel observations with measured widths."""
from __future__ import annotations
import math
import statistics
from datetime import datetime

FEATURE = None

def _span(item):
    if not isinstance(item, dict):
        raise ValueError("Channel blocks must be objects")
    try:
        center, width = float(item["center_frequency_mhz"]), float(item["width_mhz"])
    except (KeyError, TypeError, ValueError):
        raise ValueError("Each block needs numeric center_frequency_mhz and width_mhz")
    if not math.isfinite(center) or not math.isfinite(width) or width <= 0:
        raise ValueError("Channel centre and width must be finite; width must be positive")
    return center - width / 2, center + width / 2

def run(p: dict) -> dict:
    low_a, high_a = _span(p.get("a"))
    low_b, high_b = _span(p.get("b"))
    overlap = max(0.0, min(high_a, high_b) - max(low_a, low_b))
    smaller = min(high_a - low_a, high_b - low_b)
    return {"overlap_mhz": round(overlap, 3),
            "overlap_ratio": round(overlap / smaller, 4) if smaller else 0,
            "overlaps": overlap > 0}

FEATURE = {
    "id": "F112",
    "slug": "frequency_overlap_score",
    "name": "Frequency overlap score",
    "category": "RF planning",
    "description": "Compute frequency-span overlap between two channel observations with measured widths.",
    "parameters": {"a":"channel block","b":"channel block"},
    "run": run,
}
