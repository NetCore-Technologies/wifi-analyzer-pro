"""Customer-policy audit for measured Wi-Fi survey points (F205).

The auditor evaluates only fresh, supplied RF measurements against explicit
operator policy thresholds. It never interpolates coverage between sample
points or claims service outside the measured coordinates.
"""
from __future__ import annotations

import math
import re
from datetime import datetime, timedelta, timezone

MAX_MEASUREMENTS = 20_000
MAX_ZONES = 100
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SAMPLE_FINGERPRINT = re.compile(r"^[0-9a-f]{16,64}$")


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value.strip()):
        raise ValueError(f"{field} must be a valid identifier")
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


def _policy(value: object) -> dict:
    if not isinstance(value, dict):
        raise ValueError("policy must be an object")
    allowed = {
        "minimum_rssi_dbm", "minimum_snr_db", "minimum_passing_points_pct",
        "minimum_sample_count", "minimum_qualifying_aps", "maximum_sample_age_days",
    }
    unknown = set(value) - allowed
    if unknown:
        raise ValueError("policy contains unsupported fields: " + ", ".join(sorted(unknown)))
    rssi = _number(value.get("minimum_rssi_dbm", -67), "policy.minimum_rssi_dbm", -120.0, -10.0)
    snr_raw = value.get("minimum_snr_db")
    snr = None if snr_raw is None or snr_raw == "" else _number(snr_raw, "policy.minimum_snr_db", -20.0, 150.0)
    passing_pct = _number(
        value.get("minimum_passing_points_pct", 95.0),
        "policy.minimum_passing_points_pct",
        0.0, 100.0,
    )
    minimum_points = value.get("minimum_sample_count", 10)
    if isinstance(minimum_points, bool) or not isinstance(minimum_points, int) or not 1 <= minimum_points <= MAX_MEASUREMENTS:
        raise ValueError(f"policy.minimum_sample_count must be an integer from 1 to {MAX_MEASUREMENTS}")
    minimum_aps = value.get("minimum_qualifying_aps", 1)
    if isinstance(minimum_aps, bool) or not isinstance(minimum_aps, int) or not 1 <= minimum_aps <= 16:
        raise ValueError("policy.minimum_qualifying_aps must be an integer from 1 to 16")
    max_age = value.get("maximum_sample_age_days", 7)
    if isinstance(max_age, bool) or not isinstance(max_age, int) or not 1 <= max_age <= 30:
        raise ValueError("policy.maximum_sample_age_days must be an integer from 1 to 30")
    return {
        "minimum_rssi_dbm": rssi,
        "minimum_snr_db": snr,
        "minimum_passing_points_pct": passing_pct,
        "minimum_sample_count": minimum_points,
        "minimum_qualifying_aps": minimum_aps,
        "maximum_sample_age_days": max_age,
    }


def _zones(value: object, width: float, height: float) -> list[dict]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > MAX_ZONES:
        raise ValueError(f"zones must be a list of no more than {MAX_ZONES} records")
    zones = []
    seen = set()
    for index, zone in enumerate(value):
        prefix = f"zones[{index}]"
        if not isinstance(zone, dict):
            raise ValueError(f"{prefix} must be an object")
        zone_id = _identifier(zone.get("zone_id"), prefix + ".zone_id")
        if zone_id in seen:
            raise ValueError("zone_id values must be unique")
        seen.add(zone_id)
        x1 = _number(zone.get("x1_px"), prefix + ".x1_px", 0.0, width)
        y1 = _number(zone.get("y1_px"), prefix + ".y1_px", 0.0, height)
        x2 = _number(zone.get("x2_px"), prefix + ".x2_px", 0.0, width)
        y2 = _number(zone.get("y2_px"), prefix + ".y2_px", 0.0, height)
        if x1 >= x2 or y1 >= y2:
            raise ValueError(f"{prefix} must have positive width and height")
        zones.append({"zone_id": zone_id, "x1_px": x1, "y1_px": y1, "x2_px": x2, "y2_px": y2})
    return zones


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    site_id = _identifier(payload.get("site_id"), "site_id")
    bundle = payload.get("report")
    if not isinstance(bundle, dict) or not isinstance(bundle.get("report"), dict) or not isinstance(bundle.get("result"), dict):
        raise ValueError("report must contain report and result objects")
    metadata = bundle["report"]
    report = bundle["result"]
    if metadata.get("site_id") != site_id or report.get("site_id") != site_id:
        raise ValueError("report belongs to another site")
    if metadata.get("floorplan_id") != report.get("floorplan_id") or metadata.get("floor_id") != report.get("floor_id"):
        raise ValueError("report metadata does not match its stored result")
    if not isinstance(report.get("status"), str) or report.get("status") not in {"analysed", "insufficient_fresh_survey_evidence"}:
        raise ValueError("report has an unsupported F203 status")
    survey_id = _identifier(metadata.get("survey_id"), "report.report.survey_id")
    _timestamp(metadata.get("created_at"), "report.report.created_at")
    floorplan_id = _identifier(report.get("floorplan_id"), "report.floorplan_id")
    floor_id = _identifier(report.get("floor_id"), "report.floor_id")
    floorplan = report.get("floorplan")
    if not isinstance(floorplan, dict):
        raise ValueError("report must include floor-plan coordinate dimensions")
    width = _number(floorplan.get("width_px"), "report.floorplan.width_px", 100.0, 100_000.0)
    height = _number(floorplan.get("height_px"), "report.floorplan.height_px", 100.0, 100_000.0)
    policy = _policy(payload.get("policy", {}))
    zones = _zones(payload.get("zones"), width, height)
    as_of = _timestamp(payload["as_of"], "as_of") if payload.get("as_of") is not None else datetime.now(timezone.utc)
    now = datetime.now(timezone.utc)
    if as_of > now + timedelta(minutes=5):
        raise ValueError("as_of is too far in the future")
    cutoff = as_of - timedelta(days=policy["maximum_sample_age_days"])
    ap_values = report.get("access_points")
    if not isinstance(ap_values, list) or not 1 <= len(ap_values) <= 256:
        raise ValueError("report.access_points must contain 1 to 256 records")
    known_aps = set()
    for index, ap in enumerate(ap_values):
        prefix = f"report.access_points[{index}]"
        if not isinstance(ap, dict):
            raise ValueError(f"{prefix} must be an object")
        ap_id = _identifier(ap.get("ap_id"), prefix + ".ap_id")
        if ap_id in known_aps:
            raise ValueError("report contains duplicate AP IDs")
        known_aps.add(ap_id)
        _number(ap.get("x_px"), prefix + ".x_px", 0.0, width)
        _number(ap.get("y_px"), prefix + ".y_px", 0.0, height)

    measurements = report.get("measurements")
    if not isinstance(measurements, list) or len(measurements) > MAX_MEASUREMENTS:
        raise ValueError(f"report.measurements must contain no more than {MAX_MEASUREMENTS} records")

    points = {}
    stale_measurements = 0
    duplicate_keys = set()
    sample_metadata = {}
    for index, measurement in enumerate(measurements):
        prefix = f"report.measurements[{index}]"
        if not isinstance(measurement, dict):
            raise ValueError(f"{prefix} must be an object")
        ap_id = _identifier(measurement.get("ap_id"), prefix + ".ap_id")
        if ap_id not in known_aps:
            raise ValueError(f"{prefix}.ap_id references an unknown AP")
        if measurement.get("floorplan_id") != floorplan_id:
            raise ValueError(f"{prefix} belongs to another floorplan")
        if measurement.get("floor_id") != floor_id:
            raise ValueError(f"{prefix} belongs to another floor")
        observed_at = _timestamp(measurement.get("observed_at"), prefix + ".observed_at")
        if observed_at > as_of + timedelta(minutes=5):
            raise ValueError(f"{prefix}.observed_at is too far in the future")
        evidence_source = measurement.get("evidence_source")
        if not isinstance(evidence_source, str) or evidence_source not in {"survey", "controller", "operator"}:
            raise ValueError(f"{prefix}.evidence_source is invalid")
        fingerprint = measurement.get("sample_fingerprint")
        if not isinstance(fingerprint, str) or not SAMPLE_FINGERPRINT.fullmatch(fingerprint):
            raise ValueError(f"{prefix}.sample_fingerprint is invalid")
        x = _number(measurement.get("survey_x_px"), prefix + ".survey_x_px", 0.0, width)
        y = _number(measurement.get("survey_y_px"), prefix + ".survey_y_px", 0.0, height)
        sample_time = observed_at.isoformat(timespec="seconds")
        prior_sample = sample_metadata.get(fingerprint)
        if prior_sample is not None and prior_sample != (x, y, sample_time):
            raise ValueError("one sample_fingerprint cannot refer to multiple survey points or timestamps")
        sample_metadata[fingerprint] = (x, y, sample_time)
        rssi = _number(measurement.get("rssi_dbm"), prefix + ".rssi_dbm", -120.0, -10.0)
        noise_raw = measurement.get("noise_dbm")
        noise = None if noise_raw is None else _number(noise_raw, prefix + ".noise_dbm", -150.0, -10.0)
        snr_raw = measurement.get("snr_db")
        snr = None if snr_raw is None else _number(snr_raw, prefix + ".snr_db", -20.0, 150.0)
        if noise is not None:
            calculated_snr = rssi - noise
            if snr is not None and abs(snr - calculated_snr) > 0.2:
                raise ValueError(f"{prefix}.snr_db does not match its measured RSSI/noise values")
            snr = calculated_snr
        elif snr is not None:
            # F203 only supplies an SNR with a measured noise floor. Do not
            # accept a caller-supplied SNR detached from the source readings.
            raise ValueError(f"{prefix}.snr_db requires a measured noise_dbm value")

        key = (fingerprint, x, y, ap_id)
        if key in duplicate_keys:
            raise ValueError("report contains duplicate AP readings at the same survey point")
        duplicate_keys.add(key)
        if observed_at < cutoff:
            stale_measurements += 1
            continue
        point_key = (fingerprint, x, y)
        point = points.setdefault(point_key, {
            "sample_fingerprint": fingerprint,
            "x_px": x,
            "y_px": y,
            "observed_at": observed_at.isoformat(timespec="seconds"),
            "readings": [],
        })
        point["readings"].append({
            "ap_id": ap_id,
            "rssi_dbm": rssi,
            "snr_db": snr,
            "rssi_pass": rssi >= policy["minimum_rssi_dbm"],
            "snr_pass": policy["minimum_snr_db"] is None or (
                snr is not None and snr >= policy["minimum_snr_db"]
            ),
        })

    evaluated = []
    for point in points.values():
        qualifying = [
            reading for reading in point["readings"]
            if reading["rssi_pass"] and reading["snr_pass"]
        ]
        point_passed = len(qualifying) >= policy["minimum_qualifying_aps"]
        evaluated.append({
            "sample_fingerprint": point["sample_fingerprint"],
            "x_px": point["x_px"],
            "y_px": point["y_px"],
            "observed_at": point["observed_at"],
            "qualifying_ap_count": len(qualifying),
            "observed_ap_count": len(point["readings"]),
            "status": "pass" if point_passed else "fail",
        })
    evaluated.sort(key=lambda point: (point["observed_at"], point["sample_fingerprint"], point["x_px"], point["y_px"]))

    point_count = len(evaluated)
    passing_count = sum(point["status"] == "pass" for point in evaluated)
    failing_count = point_count - passing_count
    pass_pct = round(passing_count / point_count * 100.0, 2) if point_count else None
    enough_evidence = point_count >= policy["minimum_sample_count"]
    status = (
        "insufficient_evidence" if not enough_evidence
        else "accepted" if pass_pct is not None and pass_pct >= policy["minimum_passing_points_pct"]
        else "rejected"
    )

    per_zone = []
    for zone in zones:
        zone_points = [
            point for point in evaluated
            if zone["x1_px"] <= point["x_px"] <= zone["x2_px"]
            and zone["y1_px"] <= point["y_px"] <= zone["y2_px"]
        ]
        zone_pass = sum(point["status"] == "pass" for point in zone_points)
        zone_count = len(zone_points)
        zone_pct = round(zone_pass / zone_count * 100.0, 2) if zone_count else None
        per_zone.append({
            "zone_id": zone["zone_id"],
            "sampled_point_count": zone_count,
            "passing_point_count": zone_pass,
            "failing_point_count": zone_count - zone_pass,
            "passing_points_pct": zone_pct,
            "status": (
                "insufficient_evidence" if zone_count < policy["minimum_sample_count"]
                else "accepted" if zone_pct is not None and zone_pct >= policy["minimum_passing_points_pct"]
                else "rejected"
            ),
        })

    return {
        "status": status,
        "site_id": site_id,
        "survey_id": survey_id,
        "report_label": metadata.get("label"),
        "floorplan_id": floorplan_id,
        "floor_id": floor_id,
        "policy": policy,
        "summary": {
            "sampled_point_count": point_count,
            "passing_point_count": passing_count,
            "failing_point_count": failing_count,
            "passing_points_pct": pass_pct,
            "stale_measurement_count_excluded": stale_measurements,
            "minimum_sample_count_met": enough_evidence,
        },
        "zones": per_zone,
        "points": evaluated[:MAX_MEASUREMENTS],
        "limitations": [
            "Only imported, timestamped survey points are evaluated; unsampled floor-plan areas are not inferred or scored.",
            "A point passes only when its observed count of qualifying AP readings satisfies the configured policy.",
            "Missing SNR fails an SNR-required policy; no noise floor or SNR is estimated.",
            "Thresholds are customer-supplied acceptance criteria, not universal Wi-Fi standards or a guarantee of application performance.",
            "Evidence-source and measurement-context metadata are caller-declared and are not cryptographically attested.",
            "Zones are operator-drawn rectangles in the floor-plan pixel coordinate system and may overlap.",
        ],
    }


FEATURE = {
    "id": "F205",
    "slug": "rf_survey_acceptance_auditor",
    "name": "RF survey acceptance auditor",
    "category": "RF assurance",
    "description": (
        "Evaluate fresh measured Wi-Fi survey points against a customer-defined RSSI/SNR and sampled-point acceptance policy, with optional floor-plan zones and explicit insufficient-evidence outcomes; never infer unsampled coverage."
    ),
    "parameters": {
        "site_id": "Site identifier which must match the saved report",
        "report": "Stored F203 report metadata and immutable result",
        "policy": "Customer-defined minimum RSSI/SNR, passing-point percentage, minimum point count and qualifying AP count",
        "zones": "Optional 1-100 axis-aligned rectangles in floor-plan pixel coordinates",
        "as_of": "Optional timezone-aware assessment timestamp",
    },
    "run": run,
}
