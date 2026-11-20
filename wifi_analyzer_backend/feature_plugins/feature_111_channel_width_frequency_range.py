"""Channel width frequency range: Calculate the nominal occupied frequency span for a channel centre and channel width."""
from __future__ import annotations
import math
import statistics
from datetime import datetime

FEATURE = None

def run(p: dict) -> dict:
    try:
        center = float(p["center_frequency_mhz"])
        width = float(p["width_mhz"])
    except (KeyError, TypeError, ValueError):
        raise ValueError("center_frequency_mhz and width_mhz must be numeric")
    if not math.isfinite(center) or not 2300 <= center <= 7125:
        raise ValueError("center_frequency_mhz must be between 2300 and 7125")
    if width not in (20, 40, 80, 160, 320):
        raise ValueError("width_mhz must be one of 20, 40, 80, 160 or 320")
    return {"center_frequency_mhz": center, "width_mhz": width,
            "lower_edge_mhz": center - width / 2, "upper_edge_mhz": center + width / 2,
            "note": "Nominal channel geometry; regulatory and device-supported widths vary by region and hardware."}

FEATURE = {
    "id": "F111",
    "slug": "channel_width_frequency_range",
    "name": "Channel width frequency range",
    "category": "RF planning",
    "description": "Calculate the nominal occupied frequency span for a channel centre and channel width.",
    "parameters": {"center_frequency_mhz":"number","width_mhz":"number"},
    "run": run,
}
