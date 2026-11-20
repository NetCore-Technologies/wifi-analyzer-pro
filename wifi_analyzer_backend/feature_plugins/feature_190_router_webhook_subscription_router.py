"""Route normalized router events into deterministic, bounded webhook subscription batches.

The router performs no network requests and never stores signing secrets. It emits plans for
the F185 HMAC envelope builder and F187 egress verifier to consume in a separate worker.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlsplit

MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_SUBSCRIPTIONS = 100
MAX_EVENTS = 5000
MAX_BATCHES_TOTAL = 1000
MAX_BATCHES_PER_SUBSCRIPTION = 100
MAX_EVENTS_PER_BATCH = 500
MAX_ATTRIBUTES = 16
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
EVENT_TYPE = re.compile(r"^[a-z][a-z0-9_.-]{0,79}$")
HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
SEVERITY_RANK = {"critical": 0, "warning": 1, "info": 2}
ATTRIBUTE_KEYS = {
    "observed", "threshold", "resource_type", "resource_id", "report_id",
    "previous_status", "current_status", "source_id", "content_hash",
    "critical_count", "warning_count", "info_count", "finding_count",
    "changed_count", "added_count", "removed_count",
}


def _id(value: object, field: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError(f"{field} must be a 1 to 64 character identifier")
    return value


def _timestamp(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone offset")
    return parsed.astimezone(timezone.utc).isoformat()


def _hostname(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ValueError(f"{field} must be a fully-qualified DNS hostname")
    candidate = value.rstrip(".").lower()
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise ValueError(f"{field} must be a valid IDNA DNS hostname") from error
    if not candidate or len(candidate) > 253 or "." not in candidate:
        raise ValueError(f"{field} must be a fully-qualified DNS hostname")
    if any(not HOST_LABEL.fullmatch(label) for label in candidate.split(".")):
        raise ValueError(f"{field} is not a valid DNS hostname")
    try:
        import ipaddress
        ipaddress.ip_address(candidate)
    except ValueError:
        return candidate
    raise ValueError(f"{field} must be a DNS hostname, not an IP address")


def _endpoint(value: object, raw_hosts: object, field: str) -> tuple[str, list[str]]:
    if not isinstance(raw_hosts, list) or not 1 <= len(raw_hosts) <= 50:
        raise ValueError(f"{field}.allowed_hosts must contain from 1 to 50 DNS hostnames")
    hosts = [_hostname(item, f"{field}.allowed_hosts[{index}]") for index, item in enumerate(raw_hosts)]
    if len(hosts) != len(set(hosts)):
        raise ValueError(f"{field}.allowed_hosts entries must be unique")
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError(f"{field}.endpoint must be an HTTPS URL of at most 2048 characters")
    if any(ord(char) < 32 or ord(char) == 127 or char == "\\" for char in value):
        raise ValueError(f"{field}.endpoint contains invalid control characters or backslashes")
    if "?" in value or "#" in value:
        raise ValueError(f"{field}.endpoint must not contain a query string or fragment")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise ValueError(f"{field}.endpoint must be a valid HTTPS URL") from error
    if parsed.scheme.lower() != "https" or not parsed.netloc or hostname is None:
        raise ValueError(f"{field}.endpoint must use HTTPS and contain a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"{field}.endpoint must not contain embedded credentials")
    if port not in (None, 443):
        raise ValueError(f"{field}.endpoint must use HTTPS port 443")
    host = _hostname(hostname, f"{field}.endpoint.hostname")
    if host not in hosts:
        raise ValueError(f"{field}.endpoint hostname is not in its exact host allowlist")
    path = parsed.path or "/"
    if not path.startswith("/") or path.startswith("//"):
        raise ValueError(f"{field}.endpoint path must be absolute")
    return f"https://{host}{path}", sorted(hosts)


def _subscription(raw: object, index: int) -> dict:
    field = f"subscriptions[{index}]"
    if not isinstance(raw, dict):
        raise ValueError(f"{field} must be an object")
    subscription_id = _id(raw.get("subscription_id"), f"{field}.subscription_id")
    enabled = raw.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ValueError(f"{field}.enabled must be a boolean")
    event_types = raw.get("event_types")
    if not isinstance(event_types, list) or not 1 <= len(event_types) <= 128:
        raise ValueError(f"{field}.event_types must contain from 1 to 128 event types")
    normalized_types = []
    for item in event_types:
        if item != "*" and (not isinstance(item, str) or not EVENT_TYPE.fullmatch(item)):
            raise ValueError(f"{field}.event_types entries must be lowercase event types or '*'")
        if item not in normalized_types:
            normalized_types.append(item)
    minimum = raw.get("minimum_severity", "warning")
    if not isinstance(minimum, str) or minimum not in SEVERITY_RANK:
        raise ValueError(f"{field}.minimum_severity must be critical, warning or info")
    sites = raw.get("site_allowlist", [])
    if not isinstance(sites, list) or len(sites) > 128:
        raise ValueError(f"{field}.site_allowlist must be a bounded list")
    site_ids = [_id(value, f"{field}.site_allowlist entry") for value in sites]
    if len(site_ids) != len(set(site_ids)):
        raise ValueError(f"{field}.site_allowlist entries must be unique")
    endpoint, allowed_hosts = _endpoint(
        raw.get("endpoint"), raw.get("allowed_hosts"), field
    )
    key_id = _id(raw.get("key_id"), f"{field}.key_id")
    batch_size = raw.get("maximum_events_per_batch", 100)
    if isinstance(batch_size, bool) or not isinstance(batch_size, int) or not 1 <= batch_size <= MAX_EVENTS_PER_BATCH:
        raise ValueError(f"{field}.maximum_events_per_batch must be an integer from 1 to {MAX_EVENTS_PER_BATCH}")
    max_batches = raw.get("maximum_batches", MAX_BATCHES_PER_SUBSCRIPTION)
    if isinstance(max_batches, bool) or not isinstance(max_batches, int) or not 1 <= max_batches <= MAX_BATCHES_PER_SUBSCRIPTION:
        raise ValueError(f"{field}.maximum_batches must be an integer from 1 to {MAX_BATCHES_PER_SUBSCRIPTION}")
    return {
        "subscription_id": subscription_id,
        "enabled": enabled,
        "event_types": normalized_types,
        "minimum_severity": minimum,
        "site_allowlist": sorted(site_ids),
        "endpoint": endpoint,
        "allowed_hosts": allowed_hosts,
        "key_id": key_id,
        "maximum_events_per_batch": batch_size,
        "maximum_batches": max_batches,
    }


def _attribute(value: object, field: str):
    if value is None or isinstance(value, (str, bool, int)):
        if isinstance(value, str) and len(value) > 256:
            raise ValueError(f"{field} exceeds the 256-character limit")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{field} must be finite")
        return value
    raise ValueError(f"{field} must be a JSON scalar")


def _event(raw: object, index: int) -> dict:
    field = f"events[{index}]"
    if not isinstance(raw, dict):
        raise ValueError(f"{field} must be an object")
    event_id = raw.get("event_id")
    if not isinstance(event_id, str) or not re.fullmatch(r"[0-9a-f]{64}", event_id):
        raise ValueError(f"{field}.event_id must be a 64-character lowercase SHA-256 ID")
    event_type = raw.get("event_type")
    if not isinstance(event_type, str) or not EVENT_TYPE.fullmatch(event_type):
        raise ValueError(f"{field}.event_type must be a lowercase event type")
    severity = raw.get("severity")
    if not isinstance(severity, str) or severity not in SEVERITY_RANK:
        raise ValueError(f"{field}.severity must be critical, warning or info")
    occurred_at = _timestamp(raw.get("occurred_at"), f"{field}.occurred_at")
    site_id = raw.get("site_id")
    router_id = raw.get("router_id")
    if site_id is not None:
        site_id = _id(site_id, f"{field}.site_id")
    if router_id is not None:
        router_id = _id(router_id, f"{field}.router_id")
    summary = raw.get("summary")
    if not isinstance(summary, str) or not summary.strip() or len(summary) > 256:
        raise ValueError(f"{field}.summary must be a non-empty string of at most 256 characters")
    if any(ord(char) < 32 and char not in "\t\n" for char in summary):
        raise ValueError(f"{field}.summary contains invalid control characters")
    raw_attributes = raw.get("attributes", {})
    if not isinstance(raw_attributes, dict) or len(raw_attributes) > MAX_ATTRIBUTES:
        raise ValueError(f"{field}.attributes must be an object with no more than {MAX_ATTRIBUTES} fields")
    attributes = {}
    for key, value in raw_attributes.items():
        if not isinstance(key, str) or key not in ATTRIBUTE_KEYS:
            continue
        attributes[key] = _attribute(value, f"{field}.attributes.{key}")
    return {
        "event_id": event_id,
        "event_type": event_type,
        "severity": severity,
        "occurred_at": occurred_at,
        "site_id": site_id,
        "router_id": router_id,
        "summary": summary.strip(),
        "attributes": dict(sorted(attributes.items())),
    }


def _canonical_event(event: dict) -> str:
    return json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _batch_id(subscription_id: str, events: list[dict]) -> str:
    material = json.dumps(
        [subscription_id, [item["event_id"] for item in events]],
        ensure_ascii=False, separators=(",", ":"),
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    try:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError("subscription routing input must contain JSON-compatible finite values") from error
    if len(encoded.encode("utf-8")) > MAX_INPUT_BYTES:
        raise ValueError(f"subscription routing input exceeds the {MAX_INPUT_BYTES}-byte input limit")
    raw_subscriptions = payload.get("subscriptions")
    if not isinstance(raw_subscriptions, list) or not 1 <= len(raw_subscriptions) <= MAX_SUBSCRIPTIONS:
        raise ValueError(f"subscriptions must contain from 1 to {MAX_SUBSCRIPTIONS} records")
    subscriptions = [_subscription(item, index) for index, item in enumerate(raw_subscriptions)]
    subscription_ids = [item["subscription_id"] for item in subscriptions]
    if len(subscription_ids) != len(set(subscription_ids)):
        raise ValueError("subscription_id values must be unique")

    raw_events = payload.get("events")
    if not isinstance(raw_events, list) or len(raw_events) > MAX_EVENTS:
        raise ValueError(f"events must be a list containing no more than {MAX_EVENTS} records")
    events = {}
    for index, raw in enumerate(raw_events):
        event = _event(raw, index)
        previous = events.get(event["event_id"])
        if previous is not None and _canonical_event(previous) != _canonical_event(event):
            raise ValueError("duplicate event_id values must contain identical normalized event contents")
        events[event["event_id"]] = event
    normalized_events = sorted(events.values(), key=lambda item: item["event_id"])

    plans = []
    subscription_summaries = []
    matched_by_event = Counter()
    disabled_count = 0
    filtered_event_count = 0
    truncated_events = 0
    for subscription in sorted(subscriptions, key=lambda item: item["subscription_id"]):
        sid = subscription["subscription_id"]
        if not subscription["enabled"]:
            disabled_count += 1
            subscription_summaries.append({
                "subscription_id": sid,
                "enabled": False,
                "matched_event_count": 0,
                "batch_count": 0,
                "truncated_event_count": 0,
            })
            continue
        wanted_types = set(subscription["event_types"])
        site_scope = set(subscription["site_allowlist"])
        matched = []
        for event in normalized_events:
            if "*" not in wanted_types and event["event_type"] not in wanted_types:
                continue
            if SEVERITY_RANK[event["severity"]] > SEVERITY_RANK[subscription["minimum_severity"]]:
                continue
            if site_scope and event["site_id"] not in site_scope:
                continue
            matched.append(event)
            matched_by_event[event["event_id"]] += 1
        batch_size = subscription["maximum_events_per_batch"]
        max_batches = subscription["maximum_batches"]
        allowed_count = min(len(matched), batch_size * max_batches)
        selected = matched[:allowed_count]
        dropped = len(matched) - allowed_count
        truncated_events += dropped
        filtered_event_count += len(normalized_events) - len(matched)
        sub_batches = []
        for start in range(0, len(selected), batch_size):
            batch_events = selected[start:start + batch_size]
            batch_id = _batch_id(sid, batch_events)
            sub_batches.append({
                "batch_id": batch_id,
                "subscription_id": sid,
                "endpoint": subscription["endpoint"],
                "allowed_hosts": subscription["allowed_hosts"],
                "key_id": subscription["key_id"],
                "event_count": len(batch_events),
                "events": batch_events,
                "severity_counts": {
                    severity: sum(item["severity"] == severity for item in batch_events)
                    for severity in ("critical", "warning", "info")
                },
            })
        plans.extend(sub_batches)
        subscription_summaries.append({
            "subscription_id": sid,
            "enabled": True,
            "matched_event_count": len(matched),
            "batch_count": len(sub_batches),
            "truncated_event_count": dropped,
        })
    if len(plans) > MAX_BATCHES_TOTAL:
        raise ValueError(f"subscription routing generated more than {MAX_BATCHES_TOTAL} batches")
    matched_event_count = sum(bool(value) for value in matched_by_event.values())
    unmatched_event_count = len(normalized_events) - matched_event_count
    # Subscriptions and events are already normalized into deterministic order.
    # Preserve chunk order here so delivery batches never reorder event chronology.
    return {
        "status": "planned",
        "summary": {
            "subscription_count": len(subscriptions),
            "enabled_subscription_count": len(subscriptions) - disabled_count,
            "disabled_subscription_count": disabled_count,
            "input_event_count": len(raw_events),
            "unique_event_count": len(normalized_events),
            "matched_event_count": matched_event_count,
            "unmatched_event_count": unmatched_event_count,
            "subscription_event_match_count": sum(matched_by_event.values()),
            "filtered_event_count": filtered_event_count,
            "truncated_event_count": truncated_events,
            "batch_count": len(plans),
        },
        "subscriptions": subscription_summaries,
        "batches": plans,
        "note": (
            "This is a local routing plan only. It does not sign or send batches. Pass each batch to the F185 "
            "HMAC envelope builder, then require fresh F187 DNS/TLS egress evidence before a worker transmits. "
            "Signing secrets are intentionally not accepted or returned by this feature."
        ),
    }


FEATURE = {
    "id": "F190",
    "slug": "router_webhook_subscription_router",
    "name": "Router webhook subscription router",
    "category": "Router operations",
    "description": (
        "Route validated router events to enabled webhook subscriptions using event-type, severity and site "
        "scopes; deduplicate events, split them into deterministic idempotent batches and omit signing secrets."
    ),
    "parameters": {
        "subscriptions": "1 to 100 HTTPS subscriptions with exact host allowlists",
        "events": "up to 5000 normalized event records",
    },
    "run": run,
}
