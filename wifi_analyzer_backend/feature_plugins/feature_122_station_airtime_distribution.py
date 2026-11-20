"""Station airtime distribution from comparable per-client airtime observations."""
from __future__ import annotations

import math


def _airtime(record: dict) -> float | None:
    raw = record.get("airtime_us")
    if raw is None:
        return None
    if isinstance(raw, bool):
        raise ValueError("airtime_us must be a non-negative number")
    try:
        value = float(raw)
    except (TypeError, ValueError):
        raise ValueError("airtime_us must be a non-negative number")
    if not math.isfinite(value) or value < 0:
        raise ValueError("airtime_us must be finite and non-negative")
    return value


def run(payload: dict) -> dict:
    stations = payload.get("stations", [])
    if not isinstance(stations, list):
        raise ValueError("'stations' must be a list")
    if len(stations) > 512:
        raise ValueError("'stations' may contain no more than 512 records")

    records = []
    seen = set()
    measured = []
    for index, station in enumerate(stations):
        if not isinstance(station, dict):
            raise ValueError("Each station must be an object")
        station_id = str(station.get("station_id") or station.get("client_mac") or station.get("mac") or f"station-{index + 1}")
        if station_id in seen:
            raise ValueError("Station identifiers must be unique within one sample")
        seen.add(station_id)
        airtime = _airtime(station)
        record = {"station_id": station_id, "airtime_us": airtime, "airtime_share_pct": None}
        records.append(record)
        if airtime is not None:
            measured.append(record)

    total = sum(item["airtime_us"] for item in measured)
    distribution_available = bool(measured) and total > 0
    jain_index = None
    largest_station = None
    if distribution_available:
        for item in measured:
            item["airtime_share_pct"] = round(item["airtime_us"] * 100.0 / total, 2)
        values = [item["airtime_us"] for item in measured]
        denominator = len(values) * sum(value * value for value in values)
        jain_index = round((total * total) / denominator, 4) if denominator > 0 else None
        largest_station = max(measured, key=lambda item: item["airtime_us"])["station_id"]

    ordered = sorted(
        records,
        key=lambda item: item["airtime_us"] if item["airtime_us"] is not None else -1,
        reverse=True,
    )
    return {
        "station_count": len(records),
        "measured_station_count": len(measured),
        "unmeasured_station_count": len(records) - len(measured),
        "total_observed_airtime_us": round(total, 2) if distribution_available else None,
        "distribution_available": distribution_available,
        "jain_equal_share_index": jain_index,
        "largest_airtime_share_station": largest_station,
        "stations": ordered,
        "note": (
            "Jain's index describes how evenly the supplied airtime totals are distributed, "
            "not whether allocation is fair for each station's demand. Supply counter deltas "
            "from the same observation interval; absent counters are not treated as zero."
        ),
    }


FEATURE = {
    "id": "F122",
    "slug": "station_airtime_distribution",
    "name": "Station airtime distribution",
    "category": "Client quality",
    "description": "Compare per-station airtime counter deltas and calculate an evidence-backed equal-share distribution index.",
    "parameters": {"stations": "station[]"},
    "run": run,
}
