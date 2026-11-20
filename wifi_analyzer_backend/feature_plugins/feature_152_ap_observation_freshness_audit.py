"""Audit AP observation freshness using caller-supplied timestamps and a fixed clock."""
from __future__ import annotations

import math
from datetime import datetime, timezone


def _time(value: object, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field} must be an ISO-8601 timestamp") from error
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


def run(payload: dict) -> dict:
    access_points = payload.get("access_points", [])
    if not isinstance(access_points, list):
        raise ValueError("'access_points' must be a list")
    if len(access_points) > 4096:
        raise ValueError("'access_points' may contain no more than 4096 records")
    try:
        threshold = float(payload.get("stale_after_seconds", 900))
    except (TypeError, ValueError) as error:
        raise ValueError("stale_after_seconds must be numeric") from error
    if not math.isfinite(threshold) or not 1 <= threshold <= 31_536_000:
        raise ValueError("stale_after_seconds must be between 1 second and one year")
    now = _time(payload["now"], "now") if payload.get("now") else datetime.now(timezone.utc)

    seen = set()
    records = []
    for ap in access_points:
        if not isinstance(ap, dict) or not ap.get("ap_id"):
            raise ValueError("Each AP needs ap_id")
        ap_id = str(ap["ap_id"]).strip()
        if not ap_id or ap_id in seen:
            raise ValueError("AP identifiers must be unique and non-empty")
        seen.add(ap_id)
        last_seen_value = ap.get("last_seen")
        if last_seen_value is None:
            records.append({
                "ap_id": ap_id, "site_id": ap.get("site_id"),
                "last_seen": None, "age_seconds": None, "status": "unknown",
            })
            continue
        last_seen = _time(last_seen_value, "last_seen")
        age = (now - last_seen).total_seconds()
        records.append({
            "ap_id": ap_id,
            "site_id": ap.get("site_id"),
            "last_seen": last_seen.isoformat(),
            "age_seconds": round(age, 2),
            "status": "future_timestamp" if age < 0 else "stale" if age > threshold else "fresh",
        })

    counts = {key: sum(item["status"] == key for item in records)
              for key in ("fresh", "stale", "unknown", "future_timestamp")}
    return {
        "access_point_count": len(records),
        "threshold_seconds": threshold,
        "status_counts": counts,
        "stale_access_points": [item for item in records if item["status"] == "stale"],
        "future_timestamp_ap_ids": [item["ap_id"] for item in records if item["status"] == "future_timestamp"],
        "access_points": records,
        "note": "Freshness is measured from supplied last_seen values; missing telemetry is unknown, not stale.",
    }


FEATURE = {
    "id": "F152",
    "slug": "ap_observation_freshness_audit",
    "name": "AP observation freshness audit",
    "category": "Site inventory",
    "description": "Detect stale and future-dated AP observations without treating missing timestamps as failures.",
    "parameters": {"access_points": "access_point[]", "now": "ISO-8601", "stale_after_seconds": "number"},
    "run": run,
}
