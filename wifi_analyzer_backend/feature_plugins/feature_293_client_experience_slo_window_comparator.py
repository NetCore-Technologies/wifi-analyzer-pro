"""Compare two non-overlapping client-experience SLO windows using F292."""
from __future__ import annotations

import json
import math
from datetime import datetime, timedelta, timezone

from .feature_292_client_experience_slo_evaluator import run as evaluate_slo

MAX_INPUT_BYTES = 1024 * 1024
MAX_SAMPLES_PER_WINDOW = 10000
MAX_SITES = 500


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


def _window(value: object, name: str) -> tuple[datetime, list[dict]]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object containing as_of and samples")
    unknown = sorted(set(value) - {"as_of", "samples"})
    if unknown:
        raise ValueError(f"{name} contains unsupported field(s): {', '.join(unknown)}")
    as_of = _timestamp(value.get("as_of"), f"{name}.as_of")
    samples = value.get("samples")
    if not isinstance(samples, list) or not 1 <= len(samples) <= MAX_SAMPLES_PER_WINDOW:
        raise ValueError(f"{name}.samples must contain 1 to {MAX_SAMPLES_PER_WINDOW} records")
    site_ids = set()
    sample_ids = set()
    for index, sample in enumerate(samples):
        field = f"{name}.samples[{index}]"
        if not isinstance(sample, dict):
            raise ValueError(f"{field} must be an object")
        observed_at = _timestamp(sample.get("observed_at"), f"{field}.observed_at")
        if observed_at > as_of:
            raise ValueError(f"{field}.observed_at must not be after its window as_of")
        site_id = sample.get("site_id")
        if isinstance(site_id, str):
            site_ids.add(site_id)
        sample_id = sample.get("sample_id")
        if isinstance(sample_id, str):
            if sample_id in sample_ids:
                raise ValueError(f"{name}.samples contains duplicate sample_id values")
            sample_ids.add(sample_id)
    if len(site_ids) > MAX_SITES:
        raise ValueError(f"{name}.samples may contain no more than {MAX_SITES} sites")
    return as_of, samples


def _view(report: dict) -> dict:
    summary = report.get("summary", report)
    return {
        "status": report["status"],
        "observed_sample_count": report.get("observed_sample_count", summary.get("sample_count", 0)),
        "fresh_sample_count": report.get("fresh_sample_count", summary.get("sample_count", 0)),
        "stale_sample_count": report.get("stale_sample_count", 0),
        "eligible_slo_sample_count": summary["eligible_slo_sample_count"],
        "passing_slo_sample_count": summary["passing_slo_sample_count"],
        "breached_slo_sample_count": summary["breached_slo_sample_count"],
        "sla_attainment_pct": summary["sla_attainment_pct"],
        "metric_summary": summary["metric_summary"],
    }


def _metric_deltas(baseline: dict | None, comparison: dict | None) -> dict:
    if baseline is None or comparison is None:
        return {}
    result = {}
    for name, before in baseline["metric_summary"].items():
        after = comparison["metric_summary"].get(name)
        before_p95 = before["p95"]
        after_p95 = after["p95"] if after else None
        result[name] = {
            "baseline_p95": before_p95,
            "comparison_p95": after_p95,
            "p95_delta": round(after_p95 - before_p95, 2)
            if before_p95 is not None and after_p95 is not None else None,
            "baseline_sample_count": before["sample_count"],
            "comparison_sample_count": after["sample_count"] if after else 0,
            "direction": before["direction"],
        }
    return result


def _compare(
    baseline: dict | None,
    comparison: dict | None,
    minimum_eligible_samples: int,
    regression_threshold_pct_points: float,
) -> dict:
    if baseline is None:
        return {
            "status": "new_comparison_evidence",
            "baseline": None,
            "comparison": comparison,
            "sla_attainment_delta_pct_points": None,
            "metric_deltas": {},
        }
    if comparison is None:
        return {
            "status": "missing_comparison_evidence",
            "baseline": baseline,
            "comparison": None,
            "sla_attainment_delta_pct_points": None,
            "metric_deltas": {},
        }

    before_count = baseline["eligible_slo_sample_count"]
    after_count = comparison["eligible_slo_sample_count"]
    before_attainment = baseline["sla_attainment_pct"]
    after_attainment = comparison["sla_attainment_pct"]
    delta = (
        round(after_attainment - before_attainment, 2)
        if before_attainment is not None and after_attainment is not None else None
    )
    if before_count < minimum_eligible_samples or after_count < minimum_eligible_samples or delta is None:
        status = "insufficient_evidence"
    elif delta <= -regression_threshold_pct_points:
        status = "regression"
    elif delta >= regression_threshold_pct_points:
        status = "improvement"
    else:
        status = "stable"
    return {
        "status": status,
        "baseline": baseline,
        "comparison": comparison,
        "sla_attainment_delta_pct_points": delta,
        "metric_deltas": _metric_deltas(baseline, comparison),
    }


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    try:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError("comparison input must contain JSON-compatible finite values") from error
    if len(encoded.encode("utf-8")) > MAX_INPUT_BYTES:
        raise ValueError(f"comparison input exceeds the {MAX_INPUT_BYTES}-byte input limit")
    allowed = {
        "baseline", "comparison", "max_age_days", "required_metrics", "thresholds",
        "minimum_eligible_samples", "regression_threshold_pct_points",
    }
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise ValueError(f"payload contains unsupported field(s): {', '.join(unknown)}")

    max_age_days = payload.get("max_age_days", 7)
    if isinstance(max_age_days, bool) or not isinstance(max_age_days, int) or not 1 <= max_age_days <= 30:
        raise ValueError("max_age_days must be an integer from 1 to 30")
    minimum_eligible_samples = payload.get("minimum_eligible_samples", 5)
    if (
        isinstance(minimum_eligible_samples, bool)
        or not isinstance(minimum_eligible_samples, int)
        or not 1 <= minimum_eligible_samples <= MAX_SAMPLES_PER_WINDOW
    ):
        raise ValueError(f"minimum_eligible_samples must be an integer from 1 to {MAX_SAMPLES_PER_WINDOW}")
    regression_threshold = payload.get("regression_threshold_pct_points", 5.0)
    if isinstance(regression_threshold, bool):
        raise ValueError("regression_threshold_pct_points must be a finite number from 0.1 to 100")
    try:
        regression_threshold = float(regression_threshold)
    except (TypeError, ValueError) as error:
        raise ValueError("regression_threshold_pct_points must be numeric") from error
    if not math.isfinite(regression_threshold) or not 0.1 <= regression_threshold <= 100:
        raise ValueError("regression_threshold_pct_points must be a finite number from 0.1 to 100")

    baseline_as_of, baseline_samples = _window(payload.get("baseline"), "baseline")
    comparison_as_of, comparison_samples = _window(payload.get("comparison"), "comparison")
    if comparison_as_of <= baseline_as_of + timedelta(days=max_age_days):
        raise ValueError("baseline and comparison windows must not overlap; separate their as_of timestamps by more than max_age_days")
    baseline_ids = {item["sample_id"] for item in baseline_samples if isinstance(item.get("sample_id"), str)}
    comparison_ids = {item["sample_id"] for item in comparison_samples if isinstance(item.get("sample_id"), str)}
    if baseline_ids & comparison_ids:
        raise ValueError("sample_id values must be unique across both windows")

    common = {
        "max_age_days": max_age_days,
        "required_metrics": payload.get("required_metrics"),
        "thresholds": payload.get("thresholds"),
    }
    baseline_report = evaluate_slo({
        **common,
        "as_of": baseline_as_of.isoformat().replace("+00:00", "Z"),
        "samples": baseline_samples,
    })
    comparison_report = evaluate_slo({
        **common,
        "as_of": comparison_as_of.isoformat().replace("+00:00", "Z"),
        "samples": comparison_samples,
    })
    baseline_view = _view(baseline_report)
    comparison_view = _view(comparison_report)
    overall = _compare(
        baseline_view, comparison_view, minimum_eligible_samples, regression_threshold,
    )

    baseline_sites = {item["site_id"]: _view(item) for item in baseline_report["sites"]}
    comparison_sites = {item["site_id"]: _view(item) for item in comparison_report["sites"]}
    site_comparisons = [
        {
            "site_id": site_id,
            **_compare(
                baseline_sites.get(site_id),
                comparison_sites.get(site_id),
                minimum_eligible_samples,
                regression_threshold,
            ),
        }
        for site_id in sorted(set(baseline_sites) | set(comparison_sites))
    ]
    comparable = [item for item in site_comparisons if item["status"] in {"regression", "improvement", "stable"}]
    summary = {
        "comparable_site_count": len(comparable),
        "regressing_site_count": sum(item["status"] == "regression" for item in comparable),
        "improving_site_count": sum(item["status"] == "improvement" for item in comparable),
        "stable_site_count": sum(item["status"] == "stable" for item in comparable),
        "insufficient_site_count": sum(item["status"] == "insufficient_evidence" for item in site_comparisons),
        "new_comparison_site_count": sum(item["status"] == "new_comparison_evidence" for item in site_comparisons),
        "missing_comparison_site_count": sum(item["status"] == "missing_comparison_evidence" for item in site_comparisons),
        "baseline_eligible_sample_count": baseline_view["eligible_slo_sample_count"],
        "comparison_eligible_sample_count": comparison_view["eligible_slo_sample_count"],
        "sla_attainment_delta_pct_points": overall["sla_attainment_delta_pct_points"],
    }
    if overall["status"] == "insufficient_evidence":
        status = "insufficient_evidence"
    elif overall["status"] == "regression" or summary["regressing_site_count"]:
        status = "regression_detected"
    elif overall["status"] == "improvement" or summary["improving_site_count"]:
        status = "improvement_detected"
    else:
        status = "stable"

    return {
        "status": status,
        "baseline_as_of": baseline_as_of.isoformat().replace("+00:00", "Z"),
        "comparison_as_of": comparison_as_of.isoformat().replace("+00:00", "Z"),
        "freshness_window_days": max_age_days,
        "minimum_eligible_samples": minimum_eligible_samples,
        "regression_threshold_pct_points": regression_threshold,
        "required_metrics": comparison_report["required_metrics"],
        "thresholds": comparison_report["thresholds"],
        "overall": overall,
        "sites": site_comparisons,
        "summary": summary,
        "note": (
            "Both periods are evaluated by F292 with identical required metrics and thresholds. "
            "Windows are non-overlapping, stale observations are excluded, and a site is compared only "
            "when it has sufficient eligible samples in both periods. SLA attainment is sample-weighted; "
            "a percentage-point change is not duration-weighted uptime or a statistical confidence interval. "
            "Metric p95 deltas are descriptive and do not independently determine regression status. "
            "Client identifiers and raw samples are not returned or persisted."
        ),
    }


FEATURE = {
    "id": "F293",
    "slug": "client_experience_slo_window_comparator",
    "name": "Client experience SLO window comparator",
    "category": "Client QoS",
    "description": (
        "Compare two non-overlapping client-experience measurement windows using the F292 eligibility and "
        "threshold model; report site-level SLO attainment regressions, improvements, missing evidence and "
        "descriptive metric percentile deltas."
    ),
    "parameters": {
        "baseline": "Baseline window object with timezone-aware as_of and 1-10000 timestamped client samples",
        "comparison": "Comparison window object with timezone-aware as_of and 1-10000 timestamped client samples",
        "required_metrics": "Optional F292 required metric names used identically in both windows",
        "thresholds": "Optional F292 metric thresholds applied identically in both windows",
        "max_age_days": "1-30 day window and freshness bound; defaults to 7",
        "minimum_eligible_samples": "Minimum eligible samples required in each window before classifying change; defaults to 5",
        "regression_threshold_pct_points": "Absolute SLA attainment change for regression/improvement; defaults to 5 points",
    },
    "run": run,
}
