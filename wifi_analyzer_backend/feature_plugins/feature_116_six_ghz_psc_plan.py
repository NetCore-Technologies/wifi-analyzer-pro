"""6 GHz PSC availability plan: List Preferred Scanning Channels not present in a supplied 6 GHz scan."""
from __future__ import annotations
import math
import statistics
from datetime import datetime

FEATURE = None

def run(p: dict) -> dict:
    observed = p.get("observed_channels", [])
    candidates = p.get("candidate_channels")
    if not isinstance(observed, list):
        raise ValueError("'observed_channels' must be a list")
    if candidates is None:
        candidates = list(range(5, 230, 16))
    if not isinstance(candidates, list):
        raise ValueError("'candidate_channels' must be a list")
    try:
        observed_set = {int(value) for value in observed}
        psc_set = {int(value) for value in candidates}
    except (TypeError, ValueError):
        raise ValueError("Channel lists must contain integers")
    invalid = sorted(value for value in psc_set if value < 1 or value > 233 or (value - 5) % 16 != 0)
    if invalid:
        raise ValueError(f"Candidate channels are not 6 GHz PSC values: {invalid}")
    available = sorted(psc_set - observed_set)
    return {"psc_channels": sorted(psc_set), "observed_psc_channels": sorted(psc_set & observed_set),
            "unobserved_candidates": available, "candidate_count": len(available),
            "note": "Unobserved does not mean interference-free or legally available at the deployment location."}

FEATURE = {
    "id": "F116",
    "slug": "six_ghz_psc_plan",
    "name": "6 GHz PSC availability plan",
    "category": "RF planning",
    "description": "List Preferred Scanning Channels not present in a supplied 6 GHz scan.",
    "parameters": {"observed_channels":"integer[]","candidate_channels":"integer[]"},
    "run": run,
}
