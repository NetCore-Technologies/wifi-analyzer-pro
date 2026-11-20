"""Gateway reachability matrix: Summarise reachability and latency evidence from explicit gateway/next-hop probes."""
from __future__ import annotations
import math
import re
import statistics
from datetime import datetime, timezone

def run(p: dict) -> dict:
    probes = p.get("probes", [])
    if not isinstance(probes, list):
        raise ValueError("'probes' must be a list")
    groups = {}
    for probe in probes:
        if not isinstance(probe, dict) or not probe.get("target"):
            raise ValueError("Each probe needs target")
        target = str(probe["target"])
        item = groups.setdefault(target, {"reachable": 0, "unreachable": 0, "rtt_ms": []})
        if probe.get("reachable") is True:
            item["reachable"] += 1
            if probe.get("rtt_ms") is not None:
                rtt = float(probe["rtt_ms"])
                if not math.isfinite(rtt) or rtt < 0:
                    raise ValueError("rtt_ms must be finite and non-negative")
                item["rtt_ms"].append(rtt)
        elif probe.get("reachable") is False:
            item["unreachable"] += 1
        else:
            raise ValueError("reachable must be boolean")
    results = []
    for target, item in sorted(groups.items()):
        values = item["rtt_ms"]
        results.append({"target": target, "reachable_probes": item["reachable"],
                        "unreachable_probes": item["unreachable"],
                        "availability_pct": round(item["reachable"]/(item["reachable"]+item["unreachable"])*100, 2),
                        "median_rtt_ms": statistics.median(values) if values else None})
    return {"targets": results, "target_count": len(results)}

FEATURE = {
    "id": "F136",
    "slug": "gateway_reachability_matrix",
    "name": "Gateway reachability matrix",
    "category": "Network operations",
    "description": "Summarise reachability and latency evidence from explicit gateway/next-hop probes.",
    "parameters": {"probes":"probe[]"},
    "run": run,
}
