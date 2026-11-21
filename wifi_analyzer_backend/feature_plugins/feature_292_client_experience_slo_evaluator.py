"""Evaluate measured Wi-Fi client experience against explicit SLO thresholds.

The evaluator summarises timestamped evidence supplied by a controller, agent,
client or active probe. It does not manufacture missing values or infer
end-user experience from AP-only scans.
"""
from __future__ import annotations

import math
import re
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

MAX_INPUT_BYTES = 1024 * 1024
MAX_SAMPLES = 10000
MAX_CLIENTS = 2048
MAX_DETAIL_CLIENTS = 500
MAX_AGE_DAYS = 30
MAX_FUTURE_SKEW_SECONDS = 300

IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SAMPLE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
EVIDENCE_SOURCES = {"controller", "agent", "client", "probe", "import"}

METRIC_RULES = {
    "rssi_dbm": {"direction": "min", "default": -70.0, "minimum": -120.0, "maximum": -10.0},
    "snr_db": {"direction": "min", "default": 20.0, "minimum": -30.0, "maximum": 100.0},
    "retry_rate_pct": {"direction": "max", "default": 15.0, "minimum": 0.0, "maximum": 100.0},
    "airtime_utilization_pct": {"direction": "max", "default": 80.0, "minimum": 0.0, "maximum": 100.0},
    "packet_loss_pct": {"direction": "max", "default": 1.0, "minimum": 0.0, "maximum": 100.0},
    "rtt_ms": {"direction": "max", "default": 100.0, "minimum": 0.0, "maximum": 60000.0},
    "jitter_ms": {"direction": "max", "default": 30.0, "minimum": 0.0, "maximum": 60000.0},
    "throughput_mbps": {"direction": "min", "default": None, "minimum": 0.0, "maximum": 100000.0},
}


def _identifier(value: object, field: str, *, sample: bool = False) -> str:
    pattern = SAMPLE_ID if sample else IDENTIFIER
    maximum = 64 if sample else 128
    if not isinstance(value, str) or not pattern.fullmatch(value.strip()):
        raise ValueError(f"{field} must be a valid 1 to {maximum} character identifier")
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
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone offset")
    return parsed.astimezone(timezone.utc)


def _percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(len(ordered) * quantile))
    return round(ordered[rank - 1], 2)


def _thresholds(value: object) -> dict[str, float | None]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise ValueError("thresholds must be an object")
    unknown = sorted(set(value) - set(METRIC_RULES))
    if unknown:
        raise ValueError(f"unknown threshold metric(s): {', '.join(unknown)}")
    result = {name: rule["default"] for name, rule in METRIC_RULES.items()}
    for name, raw in value.items():
        if raw is None:
            result[name] = None
        else:
            rule = METRIC_RULES[name]
            result[name] = _number(raw, f"thresholds.{name}", rule["minimum"], rule["maximum"])
    return result


def _required_metrics(value: object, thresholds: dict[str, float | None]) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not 1 <= len(value) <= len(METRIC_RULES):
        raise ValueError("required_metrics must contain 1 to 8 metric names")
    if any(not isinstance(item, str) or item not in METRIC_RULES for item in value):
        raise ValueError(f"required_metrics entries must be one of {sorted(METRIC_RULES)}")
    if len(set(value)) != len(value):
        raise ValueError("required_metrics must not contain duplicates")
    disabled = [item for item in value if thresholds[item] is None]
    if disabled:
        raise ValueError("required_metrics must have an active threshold: " + ", ".join(disabled))
    return sorted(value)


def _normalise_sample(value: object, index: int) -> dict:
    field = f"samples[{index}]"
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    sample_id = _identifier(value.get("sample_id"), f"{field}.sample_id", sample=True)
    site_id = _identifier(value.get("site_id"), f"{field}.site_id")
    client_ref = _identifier(value.get("client_ref"), f"{field}.client_ref")
    observed_at = _timestamp(value.get("observed_at"), f"{field}.observed_at")
    source = value.get("evidence_source")
    if not isinstance(source, str) or source not in EVIDENCE_SOURCES:
        raise ValueError(f"{field}.evidence_source must be one of {sorted(EVIDENCE_SOURCES)}")
    ap_id = value.get("ap_id")
    if ap_id is not None:
        ap_id = _identifier(ap_id, f"{field}.ap_id")
    metrics = value.get("metrics", {})
    if not isinstance(metrics, dict):
        raise ValueError(f"{field}.metrics must be an object")
    unknown = sorted(set(metrics) - set(METRIC_RULES))
    if unknown:
        raise ValueError(f"{field}.metrics contains unknown field(s): {', '.join(unknown)}")
    normalized_metrics = {}
    for name, raw in metrics.items():
        if raw is None:
            continue
        rule = METRIC_RULES[name]
        normalized_metrics[name] = _number(
            raw, f"{field}.metrics.{name}", rule["minimum"], rule["maximum"]
        )
    return {
        "sample_id": sample_id,
        "site_id": site_id,
        "client_ref": client_ref,
        "ap_id": ap_id,
        "observed_at": observed_at,
        "evidence_source": source,
        "metrics": normalized_metrics,
    }


def _summarise(samples: list[dict], thresholds: dict[str, float | None], required_metrics: list[str]) -> dict:
    total = len(samples)
    metric_values = {name: [] for name in METRIC_RULES}
    metric_breaches = Counter()
    sample_status_counts = Counter()
    eligible_count = 0
    passing_count = 0
    breached_eligible_count = 0
    incomplete_required_count = 0
    observed_breach_sample_count = 0
    source_counts = Counter()
    latest = None
    earliest = None

    for sample in samples:
        source_counts[sample["evidence_source"]] += 1
        observed_at = sample["observed_at"]
        earliest = observed_at if earliest is None or observed_at < earliest else earliest
        latest = observed_at if latest is None or observed_at > latest else latest
        metrics = sample["metrics"]
        breaches = []
        for name, measured in metrics.items():
            metric_values[name].append(measured)
            threshold = thresholds[name]
            if threshold is None:
                continue
            direction = METRIC_RULES[name]["direction"]
            if (direction == "min" and measured < threshold) or (direction == "max" and measured > threshold):
                breaches.append(name)
                metric_breaches[name] += 1

        if breaches:
            observed_breach_sample_count += 1
        has_required = (
            all(name in metrics for name in required_metrics)
            if required_metrics else any(name in metrics and thresholds[name] is not None for name in METRIC_RULES)
        )
        if not has_required:
            sample_status_counts["insufficient_metrics"] += 1
            if required_metrics:
                incomplete_required_count += 1
            continue

        eligible_count += 1
        if breaches:
            breached_eligible_count += 1
            sample_status_counts["threshold_breach"] += 1
        else:
            passing_count += 1
            sample_status_counts["within_thresholds"] += 1

    metric_summary = {}
    for name, rule in METRIC_RULES.items():
        values = metric_values[name]
        count = len(values)
        metric_summary[name] = {
            "sample_count": count,
            "coverage_pct": round(count / total * 100, 2) if total else None,
            "minimum": round(min(values), 2) if values else None,
            "median": round(statistics.median(values), 2) if values else None,
            "p95": _percentile(values, 0.95),
            "maximum": round(max(values), 2) if values else None,
            "threshold": thresholds[name],
            "direction": rule["direction"],
            "breach_count": metric_breaches[name],
            "breach_rate_pct": round(metric_breaches[name] / count * 100, 2) if count else None,
        }

    attainment = round(passing_count / eligible_count * 100, 2) if eligible_count else None
    if not eligible_count:
        status = "insufficient_evidence"
    elif breached_eligible_count:
        status = "threshold_breaches"
    else:
        status = "within_thresholds"

    return {
        "status": status,
        "sample_count": total,
        "eligible_slo_sample_count": eligible_count,
        "passing_slo_sample_count": passing_count,
        "breached_slo_sample_count": breached_eligible_count,
        "incomplete_required_sample_count": incomplete_required_count,
        "samples_with_observed_breaches": observed_breach_sample_count,
        "sla_attainment_pct": attainment,
        "sample_status_counts": {
            "within_thresholds": sample_status_counts["within_thresholds"],
            "threshold_breach": sample_status_counts["threshold_breach"],
            "insufficient_metrics": sample_status_counts["insufficient_metrics"],
        },
        "metric_summary": metric_summary,
        "evidence_source_counts": dict(sorted(source_counts.items())),
        "earliest_observation_at": earliest.isoformat().replace("+00:00", "Z") if earliest else None,
        "latest_observation_at": latest.isoformat().replace("+00:00", "Z") if latest else None,
    }


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    samples_value = payload.get("samples")
    if not isinstance(samples_value, list) or not 1 <= len(samples_value) <= MAX_SAMPLES:
        raise ValueError(f"samples must contain 1 to {MAX_SAMPLES} records")
    if len(str(payload).encode("utf-8")) > MAX_INPUT_BYTES:
        raise ValueError("payload exceeds the 1 MiB feature input limit")

    thresholds = _thresholds(payload.get("thresholds"))
    required_metrics = _required_metrics(payload.get("required_metrics"), thresholds)
    max_age_days = payload.get("max_age_days", 7)
    if isinstance(max_age_days, bool) or not isinstance(max_age_days, int) or not 1 <= max_age_days <= MAX_AGE_DAYS:
        raise ValueError(f"max_age_days must be an integer from 1 to {MAX_AGE_DAYS}")
    as_of = _timestamp(payload["as_of"], "as_of") if payload.get("as_of") is not None else datetime.now(timezone.utc)
    cutoff = as_of - timedelta(days=max_age_days)
    latest_allowed = as_of + timedelta(seconds=MAX_FUTURE_SKEW_SECONDS)

    seen_sample_ids = set()
    seen_clients = set()
    fresh_by_client = defaultdict(list)
    fresh_by_site = defaultdict(list)
    stale_count = 0
    for index, value in enumerate(samples_value):
        sample = _normalise_sample(value, index)
        if sample["sample_id"] in seen_sample_ids:
            raise ValueError("sample_id values must be unique")
        seen_sample_ids.add(sample["sample_id"])
        if sample["observed_at"] > latest_allowed:
            raise ValueError(f"samples[{index}].observed_at is too far in the future")
        client_key = (sample["site_id"], sample["client_ref"])
        seen_clients.add(client_key)
        if len(seen_clients) > MAX_CLIENTS:
            raise ValueError(f"samples must contain no more than {MAX_CLIENTS} distinct site/client pairs")
        if sample["observed_at"] < cutoff:
            stale_count += 1
            continue
        fresh_by_client[client_key].append(sample)
        fresh_by_site[sample["site_id"]].append(sample)

    fresh_samples = [sample for group in fresh_by_client.values() for sample in group]
    alias_map = {
        key: f"client-{index:04d}"
        for index, key in enumerate(sorted(fresh_by_client), start=1)
    }
    clients = []
    for key in sorted(fresh_by_client):
        summary = _summarise(fresh_by_client[key], thresholds, required_metrics)
        clients.append({
            "site_id": key[0],
            "client_ref": alias_map[key],
            **summary,
        })

    sites = []
    for site_id in sorted(fresh_by_site):
        site_samples = fresh_by_site[site_id]
        site_summary = _summarise(site_samples, thresholds, required_metrics)
        sites.append({
            "site_id": site_id,
            "client_count": len({(item["site_id"], item["client_ref"]) for item in site_samples}),
            **site_summary,
        })

    overall = _summarise(fresh_samples, thresholds, required_metrics)
    return {
        "status": overall["status"] if fresh_samples else "insufficient_evidence",
        "as_of": as_of.isoformat().replace("+00:00", "Z"),
        "freshness_window_days": max_age_days,
        "observed_sample_count": len(samples_value),
        "fresh_sample_count": len(fresh_samples),
        "stale_sample_count": stale_count,
        "distinct_client_count_in_input": len(seen_clients),
        "reported_client_count": len(clients),
        "reported_site_count": len(sites),
        "required_metrics": required_metrics,
        "thresholds": thresholds,
        "summary": overall,
        "sites": sites,
        "clients": clients[:MAX_DETAIL_CLIENTS],
        "client_details_truncated": len(clients) > MAX_DETAIL_CLIENTS,
        "note": (
            "Only fresh, timestamped sample records with the selected required metrics enter the SLO denominator. "
            "When required_metrics is omitted, a sample is eligible when it contains at least one metric with an "
            "active threshold. Other measured metrics are still reported and can identify observed breaches, but "
            "samples missing required metrics are excluded from SLA attainment, not counted as passes. Statistics "
            "are sample-weighted, not duration-weighted or application-specific. Evidence-source labels are "
            "caller-declared and not cryptographically attested. Client references are replaced with aliases local "
            "to this report. No samples are persisted and no network configuration is changed."
        ),
    }


FEATURE = {
    "id": "F292",
    "slug": "client_experience_slo_evaluator",
    "name": "Client experience SLO evaluator",
    "category": "Client QoS",
    "description": (
        "Aggregate fresh timestamped per-client Wi-Fi measurements against configurable signal, SNR, retry, "
        "airtime, loss, latency, jitter and optional throughput thresholds; report coverage and SLO attainment "
        "without counting missing required telemetry as a pass."
    ),
    "parameters": {
        "samples": "1-10000 timestamped sample records with site ID, pseudonymous client reference, evidence source and supplied metric values",
        "required_metrics": "Optional metric names that must be present before a sample enters the SLO denominator",
        "thresholds": "Optional metric thresholds; defaults are documented in the result and throughput is unscored unless min throughput is supplied",
        "as_of": "Optional timezone-aware assessment timestamp for deterministic reports; defaults to server UTC time",
        "max_age_days": "Optional freshness window from 1 to 30 days; defaults to 7",
    },
    "run": run,
}
