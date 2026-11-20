"""Application QoS policy audit: Compare observed per-application DSCP markings with an explicit operator-supplied policy map."""
from __future__ import annotations
import math
import statistics
from datetime import datetime, timezone

def run(p: dict) -> dict:
    policy, observations = p.get("policy", []), p.get("observations", [])
    if not isinstance(policy, list) or not isinstance(observations, list):
        raise ValueError("policy and observations must be lists")
    expected = {}
    for item in policy:
        if not isinstance(item, dict) or not item.get("application"):
            raise ValueError("Each policy needs an application")
        dscp = int(item.get("dscp", -1))
        if not 0 <= dscp <= 63:
            raise ValueError("Policy DSCP values must be 0–63")
        expected[str(item["application"]).casefold()] = dscp
    checked, mismatches, unknown = [], [], []
    for item in observations:
        if not isinstance(item, dict):
            raise ValueError("Each observation must be an object")
        app = str(item.get("application") or "")
        dscp = int(item.get("dscp", -1))
        if not 0 <= dscp <= 63:
            raise ValueError("Observed DSCP values must be 0–63")
        target = expected.get(app.casefold())
        row = {"application": app, "observed_dscp": dscp, "expected_dscp": target,
               "packets": int(item.get("packets", 1))}
        checked.append(row)
        if target is None:
            unknown.append(row)
        elif target != dscp:
            mismatches.append(row)
    return {"checked_observations": len(checked), "mismatches": mismatches,
            "unknown_applications": unknown, "match_count": len(checked)-len(mismatches)-len(unknown)}

FEATURE = {
    "id": "F126",
    "slug": "application_qos_policy_audit",
    "name": "Application QoS policy audit",
    "category": "Client QoS",
    "description": "Compare observed per-application DSCP markings with an explicit operator-supplied policy map.",
    "parameters": {"policy":"policy[]","observations":"observation[]"},
    "run": run,
}
