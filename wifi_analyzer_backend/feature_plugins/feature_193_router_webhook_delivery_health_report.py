"""F193: bounded multi-subscription webhook delivery reliability analytics."""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from statistics import median
from typing import Any

STATUSES = ("pending", "sending", "retry_wait", "delivered", "dead_letter", "cancelled")
SUBSCRIPTION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
SITE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
ERROR_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def _timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone offset")
    return parsed.astimezone(timezone.utc)


def _count(value: Any, field: str, *, minimum: int = 0, maximum: int = 1_000_000) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{field} must be an integer from {minimum} to {maximum}")
    return value


def _percent(numerator: int, denominator: int) -> float | None:
    return round((numerator / denominator) * 100, 2) if denominator else None


def run(payload: dict) -> dict:
    """Summarise bounded queue metadata without returning payloads or endpoint details."""
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    now = _timestamp(payload.get("now"), "now")
    window_days = _count(payload.get("window_days"), "window_days", minimum=1, maximum=90)
    deliveries = payload.get("deliveries")
    if not isinstance(deliveries, list) or len(deliveries) > 5000:
        raise ValueError("deliveries must be a list containing no more than 5000 records")

    start = now - timedelta(days=window_days)
    counts = {status: 0 for status in STATUSES}
    by_subscription: dict[str, dict] = {}
    by_site: dict[str, dict] = {}
    failure_codes = Counter()
    response_statuses = Counter()
    latencies: list[float] = []
    retry_delivery_count = 0
    retry_attempt_count = 0
    total_events = 0
    unscoped_delivery_count = 0

    for index, item in enumerate(deliveries):
        if not isinstance(item, dict):
            raise ValueError(f"deliveries[{index}] must be an object")
        subscription_id = item.get("subscription_id")
        if not isinstance(subscription_id, str) or not SUBSCRIPTION_ID.fullmatch(subscription_id):
            raise ValueError(f"deliveries[{index}].subscription_id is invalid")
        status = item.get("status")
        if status not in STATUSES:
            raise ValueError(f"deliveries[{index}].status is invalid")

        created_at = _timestamp(item.get("created_at"), f"deliveries[{index}].created_at")
        if created_at < start or created_at > now:
            raise ValueError(f"deliveries[{index}].created_at is outside the selected reporting window")

        event_count = _count(item.get("event_count"), f"deliveries[{index}].event_count", maximum=500)
        attempts = _count(item.get("attempts"), f"deliveries[{index}].attempts", maximum=20)
        max_attempts = _count(item.get("max_attempts"), f"deliveries[{index}].max_attempts", minimum=1, maximum=20)
        if attempts > max_attempts:
            raise ValueError(f"deliveries[{index}].attempts exceeds max_attempts")
        raw_site_ids = item.get("site_ids")
        if not isinstance(raw_site_ids, list) or len(raw_site_ids) > 128:
            raise ValueError(f"deliveries[{index}].site_ids must be a bounded list")
        site_ids = []
        for site_id in raw_site_ids:
            if not isinstance(site_id, str) or not SITE_ID.fullmatch(site_id):
                raise ValueError(f"deliveries[{index}].site_ids contains an invalid site identifier")
            site_ids.append(site_id)
        if len(site_ids) != len(set(site_ids)):
            raise ValueError(f"deliveries[{index}].site_ids must be unique")
        unscoped = item.get("has_unscoped_events")
        if not isinstance(unscoped, bool):
            raise ValueError(f"deliveries[{index}].has_unscoped_events must be a boolean")
        if unscoped:
            unscoped_delivery_count += 1

        updated_at = _timestamp(item.get("updated_at"), f"deliveries[{index}].updated_at")
        delivered_at_raw = item.get("delivered_at")
        delivered_at = _timestamp(delivered_at_raw, f"deliveries[{index}].delivered_at") if delivered_at_raw else None
        if delivered_at is not None:
            if status != "delivered" or delivered_at < created_at or delivered_at > now:
                raise ValueError(f"deliveries[{index}].delivered_at is inconsistent with delivery state")
            latencies.append(max(0.0, (delivered_at - created_at).total_seconds()))

        response_status = item.get("response_status")
        if response_status is not None:
            _count(response_status, f"deliveries[{index}].response_status", minimum=100, maximum=599)
            response_statuses[str(response_status)] += 1
        error_code = item.get("last_error_code")
        if error_code is not None:
            if not isinstance(error_code, str) or not ERROR_CODE.fullmatch(error_code):
                raise ValueError(f"deliveries[{index}].last_error_code is invalid")
            failure_codes[error_code] += 1

        counts[status] += 1
        total_events += event_count
        retries = max(0, attempts - 1)
        retry_attempt_count += retries
        if retries:
            retry_delivery_count += 1

        subscription = by_subscription.setdefault(subscription_id, {
            "subscription_id": subscription_id,
            "delivery_count": 0,
            "event_count": 0,
            "delivered_count": 0,
            "dead_letter_count": 0,
            "retry_delivery_count": 0,
        })
        subscription["delivery_count"] += 1
        subscription["event_count"] += event_count
        if status == "delivered":
            subscription["delivered_count"] += 1
        if status == "dead_letter":
            subscription["dead_letter_count"] += 1
        if retries:
            subscription["retry_delivery_count"] += 1

        for site_id in site_ids:
            site = by_site.setdefault(site_id, {
                "site_id": site_id,
                "delivery_count": 0,
                "event_count": 0,
                "delivered_count": 0,
                "dead_letter_count": 0,
            })
            site["delivery_count"] += 1
            site["event_count"] += event_count
            if status == "delivered":
                site["delivered_count"] += 1
            if status == "dead_letter":
                site["dead_letter_count"] += 1

    delivered = counts["delivered"]
    dead_letter = counts["dead_letter"]
    settled = delivered + dead_letter
    failed = counts["retry_wait"] + dead_letter
    latency_avg = round(sum(latencies) / len(latencies), 2) if latencies else None
    latency_median = round(median(latencies), 2) if latencies else None
    recommendations = []
    if dead_letter:
        recommendations.append("Review dead-letter deliveries and verify receiver availability, TLS and endpoint allowlists.")
    if counts["retry_wait"]:
        recommendations.append("Inspect retry-wait deliveries and recent safe error codes before increasing worker capacity.")
    if counts["pending"]:
        recommendations.append("Check that the webhook dispatcher worker is enabled and sharing the API state volume.")
    if retry_delivery_count:
        recommendations.append("Review delivery retries; repeated transient failures can indicate endpoint or network instability.")
    if not deliveries:
        recommendations.append("No delivery records were created in this reporting window; generate a test event to establish a baseline.")

    return {
        "feature": "F193",
        "status": "analyzed",
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "window": {
            "days": window_days,
            "start": start.isoformat().replace("+00:00", "Z"),
            "end": now.isoformat().replace("+00:00", "Z"),
        },
        "summary": {
            "total_deliveries": len(deliveries),
            "total_events": total_events,
            "counts_by_status": counts,
            "settled_count": settled,
            "success_rate_pct": _percent(delivered, settled),
            "failure_rate_pct": _percent(dead_letter, settled),
            "retry_delivery_count": retry_delivery_count,
            "retry_attempt_count": retry_attempt_count,
            "retry_delivery_rate_pct": _percent(retry_delivery_count, len(deliveries)),
            "failed_or_waiting_count": failed,
            "unscoped_delivery_count": unscoped_delivery_count,
            "average_delivery_latency_seconds": latency_avg,
            "median_delivery_latency_seconds": latency_median,
            "response_statuses": dict(sorted(response_statuses.items())),
        },
        "by_subscription": sorted(
            by_subscription.values(),
            key=lambda item: item["subscription_id"],
        ),
        "by_site": sorted(by_site.values(), key=lambda item: item["site_id"]),
        "failure_codes": [
            {"code": code, "count": count}
            for code, count in sorted(failure_codes.items(), key=lambda entry: (-entry[1], entry[0]))
        ],
        "recommendations": recommendations,
        "note": (
            "This report uses bounded queue metadata only. It does not inspect or expose signed payloads, "
            "request metadata, endpoint URLs, HMAC keys, remote response bodies or raw exception text. "
            "Rates use terminal delivered/dead-letter outcomes; active deliveries are not counted as settled."
        ),
    }


FEATURE = {
    "id": "F193",
    "slug": "router_webhook_delivery_health_report",
    "name": "Webhook delivery reliability report",
    "category": "Router operations",
    "description": (
        "Summarise durable multi-subscription webhook delivery reliability, retries, latency, safe failure codes "
        "and per-site/per-subscription health using metadata-only records."
    ),
    "parameters": {
        "now": "timezone-aware analysis timestamp",
        "window_days": "reporting window from 1 to 90 days",
        "deliveries": "up to 5000 sanitized webhook delivery metadata records",
    },
    "run": run,
}
