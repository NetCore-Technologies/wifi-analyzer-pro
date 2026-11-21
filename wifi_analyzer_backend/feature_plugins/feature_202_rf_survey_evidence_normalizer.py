"""Normalise caller-supplied RF survey/controller observations for F201.

The output is a relative co-visibility/load proxy, not measured RF coupling,
capacity, airtime contention or a probability of interference.
"""
from __future__ import annotations

import math
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from statistics import median

MAX_RADIOS = 256
MAX_OBSERVATIONS = 8192
MAX_AGE_DAYS = 30
VALID_BANDS = {"2.4GHz", "5GHz", "6GHz"}
EVIDENCE_SOURCES = {"survey", "controller"}
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
MIN_RSSI_DBM = -120.0
MAX_RSSI_DBM = -10.0
MAX_CLOCK_SKEW_SECONDS = 300


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value.strip()):
        raise ValueError(f"{field} must be a 1 to 64 character identifier")
    return value.strip()


def _number(value: object, field: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a finite number from {minimum:g} to {maximum:g}")
    try:
        result = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field} must be numeric") from error
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise ValueError(f"{field} must be a finite number from {minimum:g} to {maximum:g}")
    return result


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp")
    try:
        result = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp") from error
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp")
    return result.astimezone(timezone.utc)


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    radio_values = payload.get("radios")
    observations = payload.get("observations")
    max_age_days = payload.get("max_age_days", 7)
    if not isinstance(radio_values, list) or not 2 <= len(radio_values) <= MAX_RADIOS:
        raise ValueError(f"radios must contain 2 to {MAX_RADIOS} records")
    if not isinstance(observations, list) or not 1 <= len(observations) <= MAX_OBSERVATIONS:
        raise ValueError(f"observations must contain 1 to {MAX_OBSERVATIONS} records")
    if isinstance(max_age_days, bool) or not isinstance(max_age_days, int) or not 1 <= max_age_days <= MAX_AGE_DAYS:
        raise ValueError(f"max_age_days must be an integer from 1 to {MAX_AGE_DAYS}")

    radios = {}
    for index, record in enumerate(radio_values):
        if not isinstance(record, dict):
            raise ValueError(f"radios[{index}] must be an object")
        radio_id = _identifier(record.get("radio_id"), f"radios[{index}].radio_id")
        site_id = _identifier(record.get("site_id"), f"radios[{index}].site_id")
        band = record.get("band")
        if not isinstance(band, str) or band not in VALID_BANDS:
            raise ValueError(f"radios[{index}].band must be one of {sorted(VALID_BANDS)}")
        if radio_id in radios:
            raise ValueError("radio_id values must be unique")
        radios[radio_id] = {"site_id": site_id, "band": band}

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=max_age_days)
    seen_sample_ids = set()
    groups = defaultdict(list)
    stale_count = 0
    for index, observation in enumerate(observations):
        field = f"observations[{index}]"
        if not isinstance(observation, dict):
            raise ValueError(f"{field} must be an object")
        sample_id = _identifier(observation.get("sample_id"), f"{field}.sample_id")
        if sample_id in seen_sample_ids:
            raise ValueError("sample_id values must be unique")
        seen_sample_ids.add(sample_id)

        radio_ids = observation.get("radio_ids")
        if not isinstance(radio_ids, list) or len(radio_ids) != 2:
            raise ValueError(f"{field}.radio_ids must contain exactly two radio IDs")
        first_id = _identifier(radio_ids[0], f"{field}.radio_ids[0]")
        second_id = _identifier(radio_ids[1], f"{field}.radio_ids[1]")
        if first_id == second_id:
            raise ValueError("an observation must reference two different radios")
        if first_id not in radios or second_id not in radios:
            raise ValueError(f"{field} references an unknown radio")
        first, second = radios[first_id], radios[second_id]
        if first["site_id"] != second["site_id"] or first["band"] != second["band"]:
            raise ValueError("observations must join radios in the same site and band")

        source = observation.get("evidence_source")
        if not isinstance(source, str) or source not in EVIDENCE_SOURCES:
            raise ValueError(f"{field}.evidence_source must be one of {sorted(EVIDENCE_SOURCES)}")
        observed_at = _timestamp(observation.get("observed_at"), f"{field}.observed_at")
        age_seconds = (now - observed_at).total_seconds()
        if age_seconds < -MAX_CLOCK_SKEW_SECONDS:
            raise ValueError(f"{field}.observed_at is too far in the future")
        if observed_at < cutoff:
            stale_count += 1
            continue

        # Each value is the measured RSSI of the other radio at this radio's receiver.
        rssi_values = observation.get("radio_rssi_dbm")
        if not isinstance(rssi_values, list) or len(rssi_values) != 2:
            raise ValueError(f"{field}.radio_rssi_dbm must contain two measured RSSI values")
        rssi_a = _number(rssi_values[0], f"{field}.radio_rssi_dbm[0]", MIN_RSSI_DBM, MAX_RSSI_DBM)
        rssi_b = _number(rssi_values[1], f"{field}.radio_rssi_dbm[1]", MIN_RSSI_DBM, MAX_RSSI_DBM)

        utilization = observation.get("channel_utilization_pct")
        retry_rate = observation.get("retry_rate_pct")
        if utilization is not None:
            utilization = _number(utilization, f"{field}.channel_utilization_pct", 0.0, 100.0)
        if retry_rate is not None:
            retry_rate = _number(retry_rate, f"{field}.retry_rate_pct", 0.0, 100.0)
        load_values = [value for value in (utilization, retry_rate) if value is not None]
        load_pressure = max(load_values) if load_values else None

        pair = tuple(sorted((first_id, second_id)))
        group = groups[pair]
        if group and group[0]["evidence_source"] != source:
            raise ValueError("all observations for a radio pair must use the same evidence_source")
        group.append({
            "evidence_source": source,
            "weakest_rssi_dbm": min(rssi_a, rssi_b),
            "channel_utilization_pct": utilization,
            "retry_rate_pct": retry_rate,
            "load_pressure_pct": load_pressure,
            "observed_at": observed_at,
        })

    edges = []
    for pair in sorted(groups):
        samples = groups[pair]
        signal = float(median(item["weakest_rssi_dbm"] for item in samples))
        utilization_values = [item["channel_utilization_pct"] for item in samples if item["channel_utilization_pct"] is not None]
        retry_values = [item["retry_rate_pct"] for item in samples if item["retry_rate_pct"] is not None]
        pressure_values = [item["load_pressure_pct"] for item in samples if item["load_pressure_pct"] is not None]
        utilization = float(median(utilization_values)) if utilization_values else None
        retry_rate = float(median(retry_values)) if retry_values else None
        pressure = float(median(pressure_values)) if pressure_values else None

        # Linear RSSI visibility heuristic: -95 dBm -> 0; -50 dBm or stronger -> 1.
        visibility_weight = min(1.0, max(0.0, (signal + 95.0) / 45.0))
        weight = visibility_weight if pressure is None else visibility_weight * (0.5 + 0.5 * pressure / 100.0)
        last_seen = max(item["observed_at"] for item in samples)
        radio = radios[pair[0]]
        sample_count = len(samples)
        grade = "low" if sample_count < 3 else "medium" if sample_count < 8 else "high"
        load_sample_count = sum(item["load_pressure_pct"] is not None for item in samples)
        edges.append({
            "radio_ids": list(pair),
            "site_id": radio["site_id"],
            "band": radio["band"],
            "weight": round(weight, 4),
            "evidence_source": samples[0]["evidence_source"],
            "sample_count": sample_count,
            "load_sample_count": load_sample_count,
            "missing_load_sample_count": sample_count - load_sample_count,
            "median_weakest_rssi_dbm": round(signal, 2),
            "median_channel_utilization_pct": round(utilization, 2) if utilization is not None else None,
            "median_retry_rate_pct": round(retry_rate, 2) if retry_rate is not None else None,
            "weight_basis": "co_visibility_and_measured_load" if pressure is not None else "co_visibility_only",
            "evidence_grade": grade,
            "last_observed_at": last_seen.isoformat().replace("+00:00", "Z"),
        })

    accepted_count = sum(len(group) for group in groups.values())
    return {
        "status": "normalised" if edges else "insufficient_fresh_evidence",
        "normalised_at": now.isoformat().replace("+00:00", "Z"),
        "freshness_window_days": max_age_days,
        "radio_count": len(radios),
        "accepted_observation_count": accepted_count,
        "skipped_stale_observation_count": stale_count,
        "normalised_edge_count": len(edges),
        "interference_edges": edges,
        "weight_definition": (
            "weight = weakest-radio RSSI visibility score multiplied by an optional measured-load factor. "
            "RSSI visibility maps -95 dBm to 0 and -50 dBm or stronger to 1; when channel utilisation or retry "
            "rate is supplied, the load factor is 0.5 + 0.5 * median(max(utilisation, retry rate)) / 100."
        ),
        "note": (
            "These are caller-supplied survey/controller observations with self-declared provenance. The weight "
            "is a relative co-visibility/load proxy, not an interference probability, measured RF coupling, "
            "airtime contention or capacity result. Sample-count grade is a volume indicator, not statistical "
            "confidence. Missing load measurements remain unknown; stale observations are excluded. No MAC "
            "addresses, SSIDs, observer identities or raw sample identifiers are returned."
        ),
    }


FEATURE = {
    "id": "F202",
    "slug": "rf_survey_evidence_normalizer",
    "name": "RF survey evidence normalizer",
    "category": "RF planning",
    "description": (
        "Normalize timestamped pairwise survey/controller RSSI and optional channel-load observations into "
        "fresh, provenance-labelled relative edge weights consumable by the F201 multi-AP planner."
    ),
    "parameters": {
        "radios": "2-256 radio IDs with site and band context",
        "observations": "1-8192 pair observations with sample ID, radio IDs, timezone-aware timestamp, two directional RSSI values and optional channel utilization/retry percentages",
        "max_age_days": "Optional 1-30 day freshness window; defaults to 7 days",
    },
    "run": run,
}
