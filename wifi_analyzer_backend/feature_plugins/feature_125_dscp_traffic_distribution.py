"""DSCP traffic distribution: Summarise packet counts by observed six-bit DSCP value from a supplied capture or controller export."""
from __future__ import annotations
import math
import re
import statistics
from datetime import datetime, timezone

def run(p: dict) -> dict:
    samples = p.get("samples", [])
    if not isinstance(samples, list):
        raise ValueError("'samples' must be a list")
    counts = {}
    total = 0
    for sample in samples:
        if not isinstance(sample, dict):
            raise ValueError("Each sample must be an object")
        try:
            dscp = int(sample["dscp"])
            packets = int(sample.get("packets", 1))
        except (KeyError, TypeError, ValueError):
            raise ValueError("Each sample needs integer dscp and optional packets")
        if not 0 <= dscp <= 63 or packets < 0:
            raise ValueError("DSCP must be 0–63 and packet counts non-negative")
        counts[dscp] = counts.get(dscp, 0) + packets
        total += packets
    result = [{"dscp": key, "packets": value, "share_pct": round(value / total * 100, 2) if total else None}
              for key, value in sorted(counts.items())]
    return {"total_packets": total, "dscp_distribution": result,
            "note": "Requires DSCP metadata from a capture or controller export; no traffic is captured by this analysis."}

FEATURE = {
    "id": "F125",
    "slug": "dscp_traffic_distribution",
    "name": "DSCP traffic distribution",
    "category": "Client QoS",
    "description": "Summarise packet counts by observed six-bit DSCP value from a supplied capture or controller export.",
    "parameters": {"samples":"sample[]"},
    "run": run,
}
