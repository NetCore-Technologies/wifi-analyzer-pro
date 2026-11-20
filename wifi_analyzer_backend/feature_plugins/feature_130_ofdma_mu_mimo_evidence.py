"""OFDMA and MU-MIMO evidence: Summarise explicit AP/controller OFDMA and MU-MIMO support and usage counters."""
from __future__ import annotations
import math
import re
import statistics
from datetime import datetime, timezone

def run(p: dict) -> dict:
    observations = p.get("observations", [])
    if not isinstance(observations, list):
        raise ValueError("'observations' must be a list")
    features = ("ofdma_supported", "ofdma_active", "mu_mimo_supported", "mu_mimo_active")
    summary = {}
    for key in features:
        known = [item[key] for item in observations if isinstance(item, dict) and isinstance(item.get(key), bool)]
        summary[key] = {"true": sum(known), "false": len(known)-sum(known), "unknown": len(observations)-len(known)}
    counters = {}
    for key in ("ofdma_ppdu_count", "mu_mimo_ppdu_count"):
        values = []
        for item in observations:
            if isinstance(item, dict) and item.get(key) is not None:
                value = int(item[key])
                if value < 0:
                    raise ValueError("PPDU counters must be non-negative")
                values.append(value)
        counters[key] = sum(values) if values else None
    return {"feature_evidence": summary, "ppdu_counters": counters,
            "note": "A missing counter is unknown, not zero; usage requires AP/controller telemetry."}

FEATURE = {
    "id": "F130",
    "slug": "ofdma_mu_mimo_evidence",
    "name": "OFDMA and MU-MIMO evidence",
    "category": "PHY analysis",
    "description": "Summarise explicit AP/controller OFDMA and MU-MIMO support and usage counters.",
    "parameters": {"observations":"observation[]"},
    "run": run,
}
