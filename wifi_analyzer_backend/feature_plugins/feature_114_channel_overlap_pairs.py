"""Channel overlap pairs: Find overlapping nominal channel spans in a set of access-point observations."""
from __future__ import annotations
import math
import statistics
from datetime import datetime

FEATURE = None

def run(p: dict) -> dict:
    channels = p.get("channels", [])
    if not isinstance(channels, list):
        raise ValueError("'channels' must be a list")
    spans = []
    for index, item in enumerate(channels):
        if not isinstance(item, dict) or item.get("center_frequency_mhz") is None or item.get("width_mhz") is None:
            raise ValueError("Each channel needs center_frequency_mhz and width_mhz")
        center, width = float(item["center_frequency_mhz"]), float(item["width_mhz"])
        if not math.isfinite(center) or not math.isfinite(width) or width <= 0:
            raise ValueError("Channel centre and width must be finite; width must be positive")
        spans.append((index, item, center - width / 2, center + width / 2))
    pairs = []
    for index, left in enumerate(spans):
        for right in spans[index + 1:]:
            overlap = min(left[3], right[3]) - max(left[2], right[2])
            if overlap > 0:
                pairs.append({"a": left[1].get("id", left[0]), "b": right[1].get("id", right[0]),
                              "overlap_mhz": round(overlap, 3)})
    return {"overlap_pairs": pairs, "pair_count": len(pairs)}

FEATURE = {
    "id": "F114",
    "slug": "channel_overlap_pairs",
    "name": "Channel overlap pairs",
    "category": "RF planning",
    "description": "Find overlapping nominal channel spans in a set of access-point observations.",
    "parameters": {"channels":"channel block[]"},
    "run": run,
}
