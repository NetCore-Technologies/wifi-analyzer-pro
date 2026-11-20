"""Channel separation ranking: Rank candidate channel centres by minimum non-overlap separation from observed channel spans."""
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
        raise ValueError("Each block needs numeric centre and width")
    if not math.isfinite(center) or not math.isfinite(width) or width <= 0:
        raise ValueError("Channel centre and width must be finite; width must be positive")
    return center - width / 2, center + width / 2

def run(p: dict) -> dict:
    candidates, observed = p.get("candidates", []), p.get("observed", [])
    if not isinstance(candidates, list) or not isinstance(observed, list):
        raise ValueError("candidates and observed must be lists")
    ranked = []
    for candidate in candidates:
        low, high = _span(candidate)
        gaps = []
        for item in observed:
            other_low, other_high = _span(item)
            gaps.append(max(other_low - high, low - other_high, 0.0))
        ranked.append({"candidate": candidate, "minimum_gap_mhz": round(min(gaps), 3) if gaps else None,
                       "overlapping_observations": sum(1 for item in observed if max(_span(item)[0], low) < min(_span(item)[1], high))})
    ranked.sort(key=lambda item: (item["minimum_gap_mhz"] is None, -(item["minimum_gap_mhz"] or 0)))
    return {"ranked_candidates": ranked, "note": "Geometric separation only; RF noise and airtime are not measured."}

FEATURE = {
    "id": "F113",
    "slug": "channel_separation_rank",
    "name": "Channel separation ranking",
    "category": "RF planning",
    "description": "Rank candidate channel centres by minimum non-overlap separation from observed channel spans.",
    "parameters": {"candidates":"channel block[]","observed":"channel block[]"},
    "run": run,
}
