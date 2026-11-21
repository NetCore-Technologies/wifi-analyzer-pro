"""Evidence-bounded comparison of two retained F203 RF survey reports (F204)."""
from __future__ import annotations

import math
import re
from datetime import datetime
from statistics import median, fmean

MAX_REPORT_MEASUREMENTS = 20_000
MAX_COMPARE_POINTS = 20_000
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
CONTEXT_FIELDS = (
    "device_model",
    "radio_band",
    "channel",
    "channel_width_mhz",
    "antenna_type",
    "antenna_orientation_deg",
    "antenna_height_m",
    "calibration_id",
)


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value.strip()):
        raise ValueError(f"{field} must be a valid identifier")
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


def _time(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone offset")
    return parsed.astimezone(timezone.utc)


def _report_bundle(value: object, field: str, site_id: str) -> tuple[dict, dict]:
    if not isinstance(value, dict) or not isinstance(value.get("report"), dict) or not isinstance(value.get("result"), dict):
        raise ValueError(f"{field} must contain report and result objects")
    report = value["report"]
    result = value["result"]
    if report.get("site_id") != site_id or result.get("site_id") != site_id:
        raise ValueError(f"{field} belongs to another site")
    _identifier(report.get("survey_id"), f"{field}.report.survey_id")
    _time(report.get("created_at"), f"{field}.report.created_at")
    if result.get("status") not in {"analysed", "insufficient_fresh_survey_evidence"}:
        raise ValueError(f"{field}.result has an unsupported survey status")
    if report.get("floorplan_id") != result.get("floorplan_id") or report.get("floor_id") != result.get("floor_id"):
        raise ValueError(f"{field} report metadata does not match its stored result")
    return report, result


def _ap_map(result: dict, field: str, width: float, height: float) -> dict:
    access_points = result.get("access_points")
    if not isinstance(access_points, list) or not 1 <= len(access_points) <= 256:
        raise ValueError(f"{field}.access_points must contain 1 to 256 records")
    mapped = {}
    for index, ap in enumerate(access_points):
        prefix = f"{field}.access_points[{index}]"
        if not isinstance(ap, dict):
            raise ValueError(f"{prefix} must be an object")
        ap_id = _identifier(ap.get("ap_id"), prefix + ".ap_id")
        if ap_id in mapped:
            raise ValueError(f"{field} contains duplicate AP IDs")
        mapped[ap_id] = (
            _number(ap.get("x_px"), prefix + ".x_px", 0.0, width),
            _number(ap.get("y_px"), prefix + ".y_px", 0.0, height),
        )
    return mapped


def _measurement_points(result: dict, field: str, ap_map: dict, width: float, height: float) -> dict:
    measurements = result.get("measurements")
    if not isinstance(measurements, list) or len(measurements) > MAX_REPORT_MEASUREMENTS:
        raise ValueError(f"{field}.measurements must not exceed {MAX_REPORT_MEASUREMENTS} records")
    points = {}
    for index, measurement in enumerate(measurements):
        prefix = f"{field}.measurements[{index}]"
        if not isinstance(measurement, dict):
            raise ValueError(f"{prefix} must be an object")
        ap_id = _identifier(measurement.get("ap_id"), prefix + ".ap_id")
        if measurement.get("floorplan_id") != result.get("floorplan_id"):
            raise ValueError(f"{prefix} belongs to another floorplan")
        if measurement.get("floor_id") != result.get("floor_id"):
            raise ValueError(f"{prefix} belongs to another floor")
        _time(measurement.get("observed_at"), prefix + ".observed_at")
        evidence_source = measurement.get("evidence_source")
        if evidence_source not in {"survey", "controller", "operator"}:
            raise ValueError(f"{prefix}.evidence_source is invalid")
        if ap_id not in ap_map:
            raise ValueError(f"{prefix}.ap_id references an unknown AP")
        x = _number(measurement.get("survey_x_px"), prefix + ".survey_x_px", 0.0, width)
        y = _number(measurement.get("survey_y_px"), prefix + ".survey_y_px", 0.0, height)
        rssi = _number(measurement.get("rssi_dbm"), prefix + ".rssi_dbm", -120.0, -10.0)
        key = (ap_id, round(x, 1), round(y, 1))
        points.setdefault(key, []).append(rssi)
    return {key: round(median(values), 2) for key, values in points.items()}


def _context_comparability(baseline: dict, current: dict) -> dict:
    baseline_context = baseline.get("measurement_context")
    current_context = current.get("measurement_context")
    baseline_context = baseline_context if isinstance(baseline_context, dict) else {}
    current_context = current_context if isinstance(current_context, dict) else {}
    missing = []
    mismatched = []
    for field in CONTEXT_FIELDS:
        before = baseline_context.get(field)
        after = current_context.get(field)
        if before is None or after is None:
            missing.append(field)
        elif before != after:
            mismatched.append(field)
    return {
        "status": "comparable" if not missing and not mismatched else "limited",
        "missing_context_fields": missing,
        "mismatched_context_fields": mismatched,
        "baseline_context": baseline_context,
        "current_context": current_context,
    }


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    site_id = _identifier(payload.get("site_id"), "site_id")
    baseline_report, baseline = _report_bundle(payload.get("baseline_report"), "baseline_report", site_id)
    current_report, current = _report_bundle(payload.get("current_report"), "current_report", site_id)
    if baseline_report["survey_id"] == current_report["survey_id"]:
        raise ValueError("baseline_report and current_report must refer to different surveys")
    baseline_time = _time(baseline_report["created_at"], "baseline_report.created_at")
    current_time = _time(current_report["created_at"], "current_report.created_at")
    if baseline_time >= current_time:
        raise ValueError("baseline_report must be older than current_report")

    if baseline.get("floorplan_id") != current.get("floorplan_id"):
        raise ValueError("reports must use the same floorplan_id")
    if baseline.get("floor_id") != current.get("floor_id"):
        raise ValueError("reports must use the same floor_id")
    if baseline.get("floorplan") != current.get("floorplan"):
        raise ValueError("reports must use identical floor-plan coordinate dimensions")
    floorplan = baseline.get("floorplan")
    if not isinstance(floorplan, dict):
        raise ValueError("reports must include floor-plan coordinate dimensions")
    width = _number(floorplan.get("width_px"), "floorplan.width_px", 100.0, 100_000.0)
    height = _number(floorplan.get("height_px"), "floorplan.height_px", 100.0, 100_000.0)

    baseline_scale = _number(
        (baseline.get("scale") or {}).get("metres_per_pixel"),
        "baseline_report.scale.metres_per_pixel", 1e-8, 10_000.0,
    )
    current_scale = _number(
        (current.get("scale") or {}).get("metres_per_pixel"),
        "current_report.scale.metres_per_pixel", 1e-8, 10_000.0,
    )
    scale_delta_pct = abs(current_scale - baseline_scale) / baseline_scale * 100.0
    if scale_delta_pct > 1.0:
        raise ValueError("reports use materially different floor-plan distance scales")

    baseline_aps = _ap_map(baseline, "baseline_report", width, height)
    current_aps = _ap_map(current, "current_report", width, height)
    common_ids = sorted(set(baseline_aps) & set(current_aps))
    stable_ids = [
        ap_id for ap_id in common_ids
        if baseline_aps[ap_id] == current_aps[ap_id]
    ]
    moved_ids = [ap_id for ap_id in common_ids if ap_id not in stable_ids]
    removed_ids = sorted(set(baseline_aps) - set(current_aps))
    added_ids = sorted(set(current_aps) - set(baseline_aps))
    baseline_points = _measurement_points(baseline, "baseline_report", baseline_aps, width, height)
    current_points = _measurement_points(current, "current_report", current_aps, width, height)
    allowed_ids = set(stable_ids)
    baseline_points = {key: value for key, value in baseline_points.items() if key[0] in allowed_ids}
    current_points = {key: value for key, value in current_points.items() if key[0] in allowed_ids}
    matched_keys = sorted(set(baseline_points) & set(current_points))
    threshold = _number(payload.get("change_threshold_db", 5.0), "change_threshold_db", 1.0, 20.0)
    minimum_matches = payload.get("minimum_matched_points", 3)
    if isinstance(minimum_matches, bool) or not isinstance(minimum_matches, int) or not 1 <= minimum_matches <= 1000:
        raise ValueError("minimum_matched_points must be an integer from 1 to 1000")

    matches = []
    by_ap = {}
    for ap_id, x, y in matched_keys:
        before = baseline_points[(ap_id, x, y)]
        after = current_points[(ap_id, x, y)]
        delta = round(after - before, 2)
        row = {
            "ap_id": ap_id,
            "x_px": x,
            "y_px": y,
            "baseline_rssi_dbm": before,
            "current_rssi_dbm": after,
            "delta_rssi_db": delta,
        }
        matches.append(row)
        by_ap.setdefault(ap_id, []).append(row)

    summaries = []
    for ap_id in stable_ids:
        rows = by_ap.get(ap_id, [])
        deltas = [row["delta_rssi_db"] for row in rows]
        summaries.append({
            "ap_id": ap_id,
            "matched_points": len(rows),
            "median_delta_rssi_db": round(median(deltas), 2) if deltas else None,
            "mean_delta_rssi_db": round(fmean(deltas), 2) if deltas else None,
            "minimum_delta_rssi_db": min(deltas) if deltas else None,
            "maximum_delta_rssi_db": max(deltas) if deltas else None,
            "weaker_by_threshold_count": sum(delta <= -threshold for delta in deltas),
            "stronger_by_threshold_count": sum(delta >= threshold for delta in deltas),
        })

    deltas = [row["delta_rssi_db"] for row in matches]
    context = _context_comparability(baseline, current)
    status = "compared" if len(matches) >= minimum_matches else "insufficient_overlap"
    return {
        "status": status,
        "site_id": site_id,
        "floorplan_id": baseline["floorplan_id"],
        "floor_id": baseline["floor_id"],
        "baseline_report": {
            "survey_id": baseline_report["survey_id"],
            "label": baseline_report.get("label"),
            "created_at": baseline_report["created_at"],
        },
        "current_report": {
            "survey_id": current_report["survey_id"],
            "label": current_report.get("label"),
            "created_at": current_report["created_at"],
        },
        "comparability": {
            **context,
            "baseline_scale_m_per_px": baseline_scale,
            "current_scale_m_per_px": current_scale,
            "scale_difference_pct": round(scale_delta_pct, 4),
            "unchanged_ap_count": len(stable_ids),
            "moved_or_repositioned_ap_ids": moved_ids,
            "removed_ap_ids": removed_ids,
            "added_ap_ids": added_ids,
            "limitations": [
                "Missing or mismatched device/antenna/calibration context limits interpretation; survey source metadata is caller-declared.",
                "Only identical AP IDs and exact same-floor survey coordinates are paired; unmatched observations are excluded.",
                "RSSI differences are descriptive. They do not establish a cause, interference source, coverage boundary or service-level failure.",
                "Changes to AP firmware, transmit power, channel, client roaming, weather, occupancy and environmental conditions are not causally modelled.",
            ],
        },
        "summary": {
            "matched_point_count": len(matches),
            "baseline_unique_point_count": len(baseline_points),
            "current_unique_point_count": len(current_points),
            "unmatched_baseline_point_count": len(set(baseline_points) - set(current_points)),
            "unmatched_current_point_count": len(set(current_points) - set(baseline_points)),
            "median_delta_rssi_db": round(median(deltas), 2) if deltas else None,
            "mean_delta_rssi_db": round(fmean(deltas), 2) if deltas else None,
            "weaker_by_threshold_count": sum(delta <= -threshold for delta in deltas),
            "stronger_by_threshold_count": sum(delta >= threshold for delta in deltas),
            "unchanged_within_threshold_count": sum(-threshold < delta < threshold for delta in deltas),
            "change_threshold_db": threshold,
            "minimum_matched_points": minimum_matches,
        },
        "access_points": summaries,
        "matches": matches[:MAX_COMPARE_POINTS],
        "match_output_truncated": len(matches) > MAX_COMPARE_POINTS,
    }


FEATURE = {
    "id": "F204",
    "slug": "rf_survey_report_comparator",
    "name": "RF survey report comparator",
    "category": "RF assurance",
    "description": (
        "Compare two retained F203 surveys at identical AP placements and floor-plan coordinates; report measured RSSI deltas, overlap, and missing/mismatched device or antenna context without inferring causation."
    ),
    "parameters": {
        "site_id": "The site that owns both saved reports",
        "baseline_report": "Older report metadata and immutable F203 result",
        "current_report": "Newer report metadata and immutable F203 result",
        "change_threshold_db": "Optional threshold for weaker/stronger measured points; defaults to 5 dB",
        "minimum_matched_points": "Minimum exact AP/location pairs for a compared status; defaults to 3",
    },
    "run": run,
}
