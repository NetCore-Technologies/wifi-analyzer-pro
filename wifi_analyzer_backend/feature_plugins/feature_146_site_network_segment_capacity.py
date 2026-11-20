"""Estimate IP segment utilisation from explicitly supplied allocation counts."""
from __future__ import annotations

import ipaddress
import math


def _count(value: object, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a non-negative integer")
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{field} must be a non-negative integer")
    if number < 0 or str(number) != str(value).strip():
        raise ValueError(f"{field} must be a non-negative integer")
    return number


def run(payload: dict) -> dict:
    segments = payload.get("segments", [])
    if not isinstance(segments, list):
        raise ValueError("'segments' must be a list")
    if len(segments) > 4096:
        raise ValueError("'segments' may contain no more than 4096 records")

    warning = float(payload.get("warning_pct", 80))
    critical = float(payload.get("critical_pct", 95))
    if not math.isfinite(warning) or not math.isfinite(critical) or not 0 <= warning < critical <= 100:
        raise ValueError("Thresholds must satisfy 0 <= warning_pct < critical_pct <= 100")

    seen = set()
    rows = []
    for item in segments:
        if not isinstance(item, dict) or not item.get("segment_id"):
            raise ValueError("Each segment needs segment_id and cidr")
        segment_id = str(item["segment_id"]).strip()
        if segment_id in seen:
            raise ValueError("segment_id values must be unique")
        seen.add(segment_id)
        try:
            network = ipaddress.ip_network(str(item.get("cidr") or ""), strict=False)
        except ValueError as error:
            raise ValueError("Each segment needs a valid IPv4 or IPv6 CIDR") from error

        supplied_capacity = item.get("usable_addresses")
        if supplied_capacity is None:
            capacity = network.num_addresses
            if network.version == 4 and network.prefixlen < 31:
                capacity = max(0, capacity - 2)
        else:
            capacity = _count(supplied_capacity, "usable_addresses")

        used = None if item.get("in_use_count") is None else _count(item["in_use_count"], "in_use_count")
        reserved = _count(item.get("reserved_count", 0), "reserved_count")
        if used is not None and used + reserved > capacity:
            raise ValueError(f"Allocation counts exceed usable capacity for segment {segment_id}")

        allocated = used + reserved if used is not None else None
        utilisation = allocated * 100.0 / capacity if allocated is not None and capacity else None
        state = (
            "unknown" if utilisation is None else
            "critical" if utilisation >= critical else
            "warning" if utilisation >= warning else
            "healthy"
        )
        rows.append({
            "segment_id": segment_id,
            "site_id": str(item.get("site_id") or "unassigned"),
            "cidr": str(network),
            "address_family": network.version,
            "usable_capacity": capacity,
            "in_use_count": used,
            "reserved_count": reserved,
            "allocated_count": allocated,
            "available_count": capacity - allocated if allocated is not None else None,
            "utilisation_pct": round(utilisation, 2) if utilisation is not None else None,
            "status": state,
        })

    measured = [row for row in rows if row["utilisation_pct"] is not None]
    return {
        "segment_count": len(rows),
        "measured_segment_count": len(measured),
        "unknown_segment_count": len(rows) - len(measured),
        "warning_segment_count": sum(row["status"] == "warning" for row in rows),
        "critical_segment_count": sum(row["status"] == "critical" for row in rows),
        "segments": rows,
        "thresholds": {"warning_pct": warning, "critical_pct": critical},
        "note": (
            "Utilisation uses caller-supplied in-use/reserved counts, not active scans or DHCP queries. "
            "IPv4 network/broadcast addresses are excluded for prefixes shorter than /31; IPv6 uses the full prefix size."
        ),
    }


FEATURE = {
    "id": "F146",
    "slug": "site_network_segment_capacity",
    "name": "Site network segment capacity",
    "category": "Site inventory",
    "description": "Calculate subnet capacity and utilisation from explicit allocation counts with configurable warning thresholds.",
    "parameters": {"segments": "network_segment[]", "warning_pct": "number", "critical_pct": "number"},
    "run": run,
}
