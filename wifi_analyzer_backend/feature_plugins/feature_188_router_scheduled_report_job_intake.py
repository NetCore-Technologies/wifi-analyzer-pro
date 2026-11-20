"""Normalize a scheduled occurrence and hash-validated report into a durable job request."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

MAX_BUNDLE_BYTES = 512 * 1024
MAX_ATTEMPTS = 10
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
BUNDLE_FIELDS = {
    "schema_version", "report_id", "title", "generated_at", "period", "filters",
    "summary", "sites", "sections", "findings", "note", "content_hash",
}


def _id(value: object, field: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError(f"{field} must be a 1 to 64 character identifier")
    return value


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


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    try:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError("scheduled job input must contain JSON-compatible finite values") from error
    if len(encoded.encode("utf-8")) > MAX_BUNDLE_BYTES + 65536:
        raise ValueError("scheduled job input exceeds the supported byte limit")

    schedule_id = _id(payload.get("schedule_id"), "schedule_id")
    occurrence_id = payload.get("occurrence_id")
    if not isinstance(occurrence_id, str) or not SHA256.fullmatch(occurrence_id):
        raise ValueError("occurrence_id must be the 64-character SHA-256 key from the schedule planner")
    scheduled_at = _timestamp(payload.get("scheduled_at"), "scheduled_at")
    report_bundle = payload.get("report_bundle")
    if not isinstance(report_bundle, dict):
        raise ValueError("report_bundle must be a report bundle object")
    if report_bundle.get("schema_version") != "1.0":
        raise ValueError("report_bundle.schema_version must be 1.0")
    report_id = _id(report_bundle.get("report_id"), "report_bundle.report_id")
    if any(key not in BUNDLE_FIELDS for key in report_bundle):
        unknown = sorted(key for key in report_bundle if key not in BUNDLE_FIELDS)
        raise ValueError(f"report_bundle contains unsupported fields: {', '.join(unknown[:5])}")
    digest = report_bundle.get("content_hash")
    if not isinstance(digest, str) or not SHA256.fullmatch(digest):
        raise ValueError("report_bundle.content_hash must be a 64-character SHA-256 digest")
    body = {key: value for key, value in report_bundle.items() if key != "content_hash"}
    canonical = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if hashlib.sha256(canonical.encode("utf-8")).hexdigest() != digest:
        raise ValueError("report_bundle.content_hash does not match its content")
    bundle_json = json.dumps(report_bundle, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if len(bundle_json.encode("utf-8")) > MAX_BUNDLE_BYTES:
        raise ValueError(f"report_bundle exceeds the {MAX_BUNDLE_BYTES}-byte storage limit")
    max_attempts = payload.get("max_attempts", 5)
    if isinstance(max_attempts, bool) or not isinstance(max_attempts, int) or not 1 <= max_attempts <= MAX_ATTEMPTS:
        raise ValueError(f"max_attempts must be an integer from 1 to {MAX_ATTEMPTS}")

    job_key = hashlib.sha256(
        json.dumps([schedule_id, occurrence_id, report_id], separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    payload_hash = hashlib.sha256(bundle_json.encode("utf-8")).hexdigest()
    return {
        "status": "prepared",
        "schedule_id": schedule_id,
        "occurrence_id": occurrence_id,
        "report_id": report_id,
        "scheduled_at": scheduled_at.isoformat(),
        "job_key": job_key,
        "payload_hash": payload_hash,
        "max_attempts": max_attempts,
        "report_bundle": report_bundle,
        "note": (
            "This is a durable job request, not an executing worker. Enqueue it through the authenticated "
            "report-job API; workers must claim a lease before processing, keep the lease renewed, complete "
            "only with the active lease ID, and use the job key as an idempotency key for downstream delivery."
        ),
    }


FEATURE = {
    "id": "F188",
    "slug": "router_scheduled_report_job_intake",
    "name": "Scheduled router report job intake",
    "category": "Router operations",
    "description": (
        "Validate F184 occurrence IDs and F182 report bundle hashes, derive stable report-job idempotency "
        "keys, and prepare a bounded payload for the durable SQLite worker queue."
    ),
    "parameters": {
        "schedule_id": "schedule identifier from the schedule planner",
        "occurrence_id": "64-character occurrence ID from F184",
        "scheduled_at": "timezone-aware occurrence timestamp",
        "report_bundle": "hash-validated F182 report bundle",
        "max_attempts": "1 to 10 worker attempts",
    },
    "run": run,
}
