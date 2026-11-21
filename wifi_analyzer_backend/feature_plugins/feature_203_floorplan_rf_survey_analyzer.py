"""Floor-plan aligned, evidence-only RF survey analysis (F203).

Operator-supplied AP locations, scale references and measured survey readings
are correlated into same-floor distances. No RF propagation, coverage, wall
attenuation, channel capacity or interference predictions are fabricated.
"""
from __future__ import annotations

import hashlib
import math
import re
from datetime import datetime, timedelta, timezone
from statistics import median

MAX_APS = 256
MAX_SAMPLES = 8192
MAX_SCALE_REFERENCES = 20
MAX_READINGS = 20_000
MAX_AGE_DAYS = 30
MAX_COORDINATE_PX = 100_000
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
VALID_SOURCES = {"survey", "controller", "operator"}
DISTANCE_BUCKETS = (
    ("0-5m", 0.0, 5.0),
    ("5-10m", 5.0, 10.0),
    ("10-20m", 10.0, 20.0),
    ("20-40m", 20.0, 40.0),
    ("40m+", 40.0, float("inf")),
)


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value.strip()):
        raise ValueError(f"{field} must be a 1 to 64 character identifier")
    return value.strip()


def _number(value: object, field: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a finite number from {minimum:g} to {maximum:g}")
    try:
        number = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field} must be numeric") from error
    if not math.isfinite(number) or not minimum <= number <= maximum:
        raise ValueError(f"{field} must be a finite number from {minimum:g} to {maximum:g}")
    return number


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone offset")
    return parsed.astimezone(timezone.utc)


def _coordinate(value: object, field: str, maximum: float) -> float:
    return _number(value, field, 0.0, maximum)


def _mean(values: list[float]) -> float | None:
    return round(sum(values) / len(values), 4) if values else None


def _median(values: list[float]) -> float | None:
    return round(median(values), 4) if values else None


def _trend(observations: list[dict]) -> dict:
    points = [
        (math.log10(item["distance_m"]), item["rssi_dbm"])
        for item in observations
        if item["distance_m"] > 0
    ]
    if len(points) < 3 or len({round(point[0], 8) for point in points}) < 3:
        return {
            "status": "insufficient_distance_variation",
            "sample_count": len(points),
            "slope_db_per_distance_decade": None,
            "r_squared": None,
        }
    mean_x = sum(x for x, _ in points) / len(points)
    mean_y = sum(y for _, y in points) / len(points)
    variance_x = sum((x - mean_x) ** 2 for x, _ in points)
    variance_y = sum((y - mean_y) ** 2 for _, y in points)
    if variance_x <= 1e-12 or variance_y <= 1e-12:
        return {
            "status": "insufficient_signal_variation",
            "sample_count": len(points),
            "slope_db_per_distance_decade": None,
            "r_squared": None,
        }
    covariance = sum((x - mean_x) * (y - mean_y) for x, y in points)
    slope = covariance / variance_x
    intercept = mean_y - slope * mean_x
    residual = sum((y - (intercept + slope * x)) ** 2 for x, y in points)
    r_squared = max(0.0, min(1.0, 1.0 - residual / variance_y))
    return {
        "status": "descriptive_measured_trend",
        "sample_count": len(points),
        "slope_db_per_distance_decade": round(slope, 4),
        "r_squared": round(r_squared, 4),
    }


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")

    site_id = _identifier(payload.get("site_id"), "site_id")
    floorplan = payload.get("floorplan")
    if not isinstance(floorplan, dict):
        raise ValueError("floorplan must be an object")
    floorplan_id = _identifier(floorplan.get("floorplan_id"), "floorplan.floorplan_id")
    floor_id = _identifier(floorplan.get("floor_id"), "floorplan.floor_id")
    width_px = _number(floorplan.get("width_px"), "floorplan.width_px", 100.0, MAX_COORDINATE_PX)
    height_px = _number(floorplan.get("height_px"), "floorplan.height_px", 100.0, MAX_COORDINATE_PX)

    references = floorplan.get("scale_references")
    if not isinstance(references, list) or not 1 <= len(references) <= MAX_SCALE_REFERENCES:
        raise ValueError(f"floorplan.scale_references must contain 1 to {MAX_SCALE_REFERENCES} references")
    scales = []
    for index, reference in enumerate(references):
        prefix = f"floorplan.scale_references[{index}]"
        if not isinstance(reference, dict):
            raise ValueError(f"{prefix} must be an object")
        x1 = _coordinate(reference.get("x1_px"), prefix + ".x1_px", width_px)
        y1 = _coordinate(reference.get("y1_px"), prefix + ".y1_px", height_px)
        x2 = _coordinate(reference.get("x2_px"), prefix + ".x2_px", width_px)
        y2 = _coordinate(reference.get("y2_px"), prefix + ".y2_px", height_px)
        distance_m = _number(reference.get("distance_m"), prefix + ".distance_m", 0.1, 10_000.0)
        pixel_distance = math.hypot(x2 - x1, y2 - y1)
        if pixel_distance < 1.0:
            raise ValueError(f"{prefix} endpoints must be at least one pixel apart")
        scales.append(distance_m / pixel_distance)

    metres_per_pixel = median(scales)
    relative_deviation = max(abs(scale - metres_per_pixel) / metres_per_pixel for scale in scales)
    if relative_deviation > 0.15:
        raise ValueError("floorplan scale references disagree by more than 15 percent")

    access_point_values = payload.get("access_points")
    if not isinstance(access_point_values, list) or not 1 <= len(access_point_values) <= MAX_APS:
        raise ValueError(f"access_points must contain 1 to {MAX_APS} records")
    access_points = {}
    for index, access_point in enumerate(access_point_values):
        prefix = f"access_points[{index}]"
        if not isinstance(access_point, dict):
            raise ValueError(f"{prefix} must be an object")
        ap_id = _identifier(access_point.get("ap_id"), prefix + ".ap_id")
        ap_floor = _identifier(access_point.get("floor_id", floor_id), prefix + ".floor_id")
        if ap_floor != floor_id:
            raise ValueError(f"{prefix} belongs to another floor")
        if ap_id in access_points:
            raise ValueError("ap_id values must be unique")
        access_points[ap_id] = {
            "ap_id": ap_id,
            "floor_id": ap_floor,
            "x_px": _coordinate(access_point.get("x_px"), prefix + ".x_px", width_px),
            "y_px": _coordinate(access_point.get("y_px"), prefix + ".y_px", height_px),
        }

    sample_values = payload.get("survey_samples")
    if not isinstance(sample_values, list) or not 1 <= len(sample_values) <= MAX_SAMPLES:
        raise ValueError(f"survey_samples must contain 1 to {MAX_SAMPLES} records")

    as_of = _timestamp(payload["as_of"], "as_of") if payload.get("as_of") is not None else datetime.now(timezone.utc)
    if as_of > datetime.now(timezone.utc) + timedelta(minutes=5):
        raise ValueError("as_of is too far in the future")
    max_age_days = payload.get("max_age_days", 7)
    if isinstance(max_age_days, bool) or not isinstance(max_age_days, int) or not 1 <= max_age_days <= MAX_AGE_DAYS:
        raise ValueError(f"max_age_days must be an integer between 1 and {MAX_AGE_DAYS}")
    freshness_cutoff = as_of - timedelta(days=max_age_days)

    seen_sample_ids = set()
    accepted_measurements = []
    skipped_stale = 0
    total_readings = 0

    for sample_index, sample in enumerate(sample_values):
        prefix = f"survey_samples[{sample_index}]"
        if not isinstance(sample, dict):
            raise ValueError(f"{prefix} must be an object")
        sample_id = _identifier(sample.get("sample_id"), prefix + ".sample_id")
        if sample_id in seen_sample_ids:
            raise ValueError("sample_id values must be unique")
        seen_sample_ids.add(sample_id)

        sample_floor = _identifier(sample.get("floor_id", floor_id), prefix + ".floor_id")
        if sample_floor != floor_id:
            raise ValueError(f"{prefix} belongs to another floor")
        observed_at = _timestamp(sample.get("observed_at"), prefix + ".observed_at")
        if observed_at > as_of + timedelta(minutes=5):
            raise ValueError(f"{prefix}.observed_at is too far in the future")
        source = sample.get("evidence_source")
        if not isinstance(source, str) or source not in VALID_SOURCES:
            raise ValueError(f"{prefix}.evidence_source must be one of {sorted(VALID_SOURCES)}")
        survey_x_px = _coordinate(sample.get("x_px"), prefix + ".x_px", width_px)
        survey_y_px = _coordinate(sample.get("y_px"), prefix + ".y_px", height_px)
        readings = sample.get("measurements")
        if not isinstance(readings, list) or not readings:
            raise ValueError(f"{prefix}.measurements must contain at least one reading")
        total_readings += len(readings)
        if total_readings > MAX_READINGS:
            raise ValueError(f"survey readings must not exceed {MAX_READINGS}")

        is_stale = observed_at < freshness_cutoff
        if is_stale:
            skipped_stale += 1

        seen_aps = set()
        fingerprint = hashlib.sha256(
            (site_id + "\0" + floorplan_id + "\0" + sample_id + "\0" + observed_at.isoformat()).encode("utf-8")
        ).hexdigest()[:16]
        for reading_index, reading in enumerate(readings):
            reading_prefix = f"{prefix}.measurements[{reading_index}]"
            if not isinstance(reading, dict):
                raise ValueError(f"{reading_prefix} must be an object")
            ap_id = _identifier(reading.get("ap_id"), reading_prefix + ".ap_id")
            if ap_id not in access_points:
                raise ValueError(f"{reading_prefix}.ap_id references an unknown AP")
            if ap_id in seen_aps:
                raise ValueError(f"{prefix} contains duplicate readings for one AP")
            seen_aps.add(ap_id)
            rssi = _number(reading.get("rssi_dbm"), reading_prefix + ".rssi_dbm", -120.0, -10.0)
            noise_value = reading.get("noise_dbm")
            noise = None if noise_value is None else _number(noise_value, reading_prefix + ".noise_dbm", -150.0, -10.0)

            if is_stale:
                continue

            ap = access_points[ap_id]
            distance_m = math.hypot(
                survey_x_px - ap["x_px"],
                survey_y_px - ap["y_px"],
            ) * metres_per_pixel
            accepted_measurements.append({
                "ap_id": ap_id,
                "floorplan_id": floorplan_id,
                "floor_id": floor_id,
                "sample_fingerprint": fingerprint,
                "observed_at": observed_at.isoformat(timespec="seconds"),
                "evidence_source": source,
                "survey_x_px": survey_x_px,
                "survey_y_px": survey_y_px,
                "ap_x_px": ap["x_px"],
                "ap_y_px": ap["y_px"],
                "distance_m": round(distance_m, 3),
                "rssi_dbm": rssi,
                "noise_dbm": noise,
                "snr_db": round(rssi - noise, 2) if noise is not None else None,
            })

    summaries = []
    for ap_id in sorted(access_points):
        ap = access_points[ap_id]
        observations = [item for item in accepted_measurements if item["ap_id"] == ap_id]
        distances = [item["distance_m"] for item in observations]
        signals = [item["rssi_dbm"] for item in observations]
        distance_buckets = {}
        for label, lower, upper in DISTANCE_BUCKETS:
            subset = [
                item["rssi_dbm"]
                for item in observations
                if lower <= item["distance_m"] < upper
            ]
            distance_buckets[label] = {
                "sample_count": len(subset),
                "average_rssi_dbm": _mean(subset),
            }
        summaries.append({
            "ap_id": ap_id,
            "x_px": ap["x_px"],
            "y_px": ap["y_px"],
            "sample_count": len(observations),
            "average_rssi_dbm": _mean(signals),
            "median_rssi_dbm": _median(signals),
            "minimum_rssi_dbm": min(signals) if signals else None,
            "maximum_rssi_dbm": max(signals) if signals else None,
            "minimum_distance_m": round(min(distances), 3) if distances else None,
            "maximum_distance_m": round(max(distances), 3) if distances else None,
            "average_distance_m": _mean(distances),
            "distance_buckets": distance_buckets,
            "rssi_distance_trend": _trend(observations),
        })

    return {
        "status": "analysed" if accepted_measurements else "insufficient_fresh_survey_evidence",
        "site_id": site_id,
        "floorplan_id": floorplan_id,
        "floor_id": floor_id,
        "floorplan": {"width_px": width_px, "height_px": height_px},
        "coordinate_system": "operator-supplied pixel coordinates mapped to metres using median scale references",
        "scale": {
            "metres_per_pixel": round(metres_per_pixel, 8),
            "reference_count": len(scales),
            "maximum_relative_deviation_pct": round(relative_deviation * 100.0, 3),
        },
        "access_point_count": len(access_points),
        "survey_sample_count": len(sample_values),
        "accepted_sample_count": len({item["sample_fingerprint"] for item in accepted_measurements}),
        "skipped_stale_sample_count": skipped_stale,
        "accepted_measurement_count": len(accepted_measurements),
        "access_points": summaries,
        "measurements": accepted_measurements,
        "limitations": [
            "AP and survey coordinates are operator-supplied and are not independently verified against a physical floor plan.",
            "Distances are planar same-floor coordinate distances; walls, doors, floors, antenna patterns and Fresnel clearance are not modelled.",
            "RSSI and optional SNR are caller-supplied measurements; the output does not estimate path loss, coverage, capacity or interference.",
            "The RSSI-versus-distance trend is a descriptive fit to supplied observations, not a calibrated propagation model or a coverage prediction.",
            "Evidence-source labels are caller-declared and are not cryptographically attested.",
        ],
    }


FEATURE = {
    "id": "F203",
    "slug": "floorplan_rf_survey_analyzer",
    "name": "Floor-plan aligned RF survey analyzer",
    "category": "RF planning",
    "description": (
        "Align timestamped same-floor RSSI/noise survey readings to AP coordinates using operator-supplied scale references; report measured distances, summaries, distance buckets and descriptive signal trends without inventing propagation or coverage."
    ),
    "parameters": {
        "site_id": "A 1-64 character site identifier",
        "floorplan": "One floorplan ID/floor ID, pixel dimensions and 1-20 known-distance scale references",
        "access_points": "1-256 AP identities with same-floor pixel coordinates",
        "survey_samples": "1-8192 timestamped same-floor survey points; 20,000 per-AP readings total maximum",
        "as_of": "Optional timezone-aware assessment time; defaults to server UTC time",
        "max_age_days": "1-30 day freshness window; defaults to 7",
    },
    "run": run,
}
