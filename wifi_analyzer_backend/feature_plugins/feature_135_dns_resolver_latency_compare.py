"""DNS resolver latency comparison: Compare measured resolver lookup success, median and p95 latency across supplied probes."""
from __future__ import annotations
import math
import re
import statistics
from datetime import datetime, timezone

def run(p: dict) -> dict:
    samples = p.get("samples", [])
    if not isinstance(samples, list):
        raise ValueError("'samples' must be a list")
    groups = {}
    for item in samples:
        if not isinstance(item, dict) or not item.get("resolver"):
            raise ValueError("Each sample needs resolver")
        resolver = str(item["resolver"])
        group = groups.setdefault(resolver, {"latencies": [], "success": 0, "failure": 0})
        if item.get("success") is True:
            group["success"] += 1
        elif item.get("success") is False:
            group["failure"] += 1
        else:
            raise ValueError("Each sample needs boolean success")
        if item.get("latency_ms") is not None:
            latency = float(item["latency_ms"])
            if not math.isfinite(latency) or latency < 0:
                raise ValueError("latency_ms must be finite and non-negative")
            if item["success"] is True:
                group["latencies"].append(latency)
    result = []
    for resolver, group in sorted(groups.items()):
        values = group["latencies"]
        result.append({"resolver": resolver, "successes": group["success"], "failures": group["failure"],
                       "median_ms": statistics.median(values) if values else None,
                       "p95_ms": sorted(values)[math.ceil(.95*len(values))-1] if values else None})
    return {"resolvers": result, "sample_count": len(samples),
            "note": "Uses caller-supplied probe timings. It does not select or change DNS configuration."}

FEATURE = {
    "id": "F135",
    "slug": "dns_resolver_latency_compare",
    "name": "DNS resolver latency comparison",
    "category": "Network operations",
    "description": "Compare measured resolver lookup success, median and p95 latency across supplied probes.",
    "parameters": {"samples":"sample[]"},
    "run": run,
}
