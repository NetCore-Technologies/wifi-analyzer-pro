"""Roam latency summary: Compare latency measurements before and after roaming, preserving sample counts and median values."""
from __future__ import annotations
import math
import statistics
from datetime import datetime

FEATURE = None

def run(p: dict) -> dict:
    samples = p.get("samples", [])
    if not isinstance(samples, list):
        raise ValueError("'samples' must be a list")
    before, after = [], []
    for sample in samples:
        if not isinstance(sample, dict):
            raise ValueError("Each latency sample must be an object")
        for key, target in (("before_ms", before), ("after_ms", after)):
            if sample.get(key) is None:
                continue
            try:
                value = float(sample[key])
            except (TypeError, ValueError):
                raise ValueError(f"{key} must be numeric")
            if not math.isfinite(value) or value < 0:
                raise ValueError(f"{key} must be finite and non-negative")
            target.append(value)
    before_median = statistics.median(before) if before else None
    after_median = statistics.median(after) if after else None
    delta = round(after_median - before_median, 2) if before_median is not None and after_median is not None else None
    return {"before_median_ms": before_median, "after_median_ms": after_median, "delta_ms": delta,
            "before_samples": len(before), "after_samples": len(after)}

FEATURE = {
    "id": "F108",
    "slug": "roam_latency_summary",
    "name": "Roam latency summary",
    "category": "Roaming",
    "description": "Compare latency measurements before and after roaming, preserving sample counts and median values.",
    "parameters": {"samples":"sample[]"},
    "run": run,
}
