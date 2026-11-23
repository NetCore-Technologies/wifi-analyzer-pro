"""Build allow-listed, HMAC-signed webhook request envelopes without sending them."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import math
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit, urlunsplit

MAX_INPUT_BYTES = 1024 * 1024
MAX_EVENTS = 500
MAX_ALLOWED_HOSTS = 50
MAX_ATTRIBUTES = 16
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
SITE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
EVENT_TYPE = re.compile(r"^[a-z][a-z0-9_.-]{0,79}$")
HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
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


def _site_identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not SITE_IDENTIFIER.fullmatch(value):
        raise ValueError(f"{field} must be a 1 to 128 character site identifier")
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


def _hostname(value: str, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a DNS hostname")
    candidate = value.rstrip(".").lower()
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise ValueError(f"{field} is not a valid IDNA hostname") from error
    if len(candidate) > 253 or "." not in candidate or any(
        not HOST_LABEL.fullmatch(label) for label in candidate.split(".")
    ):
        raise ValueError(f"{field} must be a fully-qualified DNS hostname")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return candidate
    raise ValueError(f"{field} must be a DNS hostname, not an IP address")


def _endpoint(value: object, allowed_hosts: set[str]) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError("endpoint must be an HTTPS URL of at most 2048 characters")
    if any(ord(ch) < 32 or ord(ch) == 127 or ch == "\\" for ch in value):
        raise ValueError("endpoint contains invalid control characters or backslashes")
    if "?" in value or "#" in value:
        raise ValueError("endpoint must not contain a query string or fragment")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise ValueError("endpoint must be a valid HTTPS URL") from error
    if parsed.scheme.lower() != "https":
        raise ValueError("endpoint must use HTTPS")
    if not parsed.netloc or hostname is None:
        raise ValueError("endpoint must contain a DNS hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("endpoint must not contain embedded credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("endpoint must not contain a query string or fragment")
    if port not in (None, 443):
        raise ValueError("endpoint must use the standard HTTPS port 443")
    host = _hostname(hostname, "endpoint.hostname")
    if host not in allowed_hosts:
        raise ValueError("endpoint hostname is not present in the exact host allowlist")
    path = parsed.path or "/"
    if not path.startswith("/") or path.startswith("//"):
        raise ValueError("endpoint path must be an absolute path")
    return urlunsplit(("https", host, path, "", ""))


def _allowed_hosts(value: object) -> set[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_ALLOWED_HOSTS:
        raise ValueError(f"allowed_hosts must contain from 1 to {MAX_ALLOWED_HOSTS} DNS hostnames")
    hosts = [_hostname(item, f"allowed_hosts[{index}]") for index, item in enumerate(value)]
    if len(hosts) != len(set(hosts)):
        raise ValueError("allowed_hosts entries must be unique")
    return set(hosts)


def _attribute(value: object, field: str):
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{field} must be finite")
        return value
    if isinstance(value, str) and len(value) <= 256:
        if any(ord(ch) < 32 and ch not in "\t\n" for ch in value):
            raise ValueError(f"{field} contains invalid control characters")
        return value
    raise ValueError(f"{field} must be a JSON scalar of at most 256 characters")


def _event(value: object, index: int) -> dict:
    field = f"events[{index}]"
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    event_id = _id(value.get("event_id"), f"{field}.event_id")
    event_type = value.get("event_type")
    if not isinstance(event_type, str) or not EVENT_TYPE.fullmatch(event_type):
        raise ValueError(f"{field}.event_type must be a lowercase event type")
    severity = value.get("severity")
    if not isinstance(severity, str) or severity not in {"critical", "warning", "info"}:
        raise ValueError(f"{field}.severity must be critical, warning or info")
    occurred_at = _timestamp(value.get("occurred_at"), f"{field}.occurred_at")
    site_id = value.get("site_id")
    if site_id is not None:
        site_id = _site_identifier(site_id, f"{field}.site_id")
    router_id = value.get("router_id")
    if router_id is not None:
        router_id = _id(router_id, f"{field}.router_id")
    summary = value.get("summary")
    if not isinstance(summary, str) or not summary.strip() or len(summary) > 256:
        raise ValueError(f"{field}.summary must be a non-empty string of at most 256 characters")
    if any(ord(ch) < 32 and ch not in "\t\n" for ch in summary):
        raise ValueError(f"{field}.summary contains invalid control characters")
    raw_attributes = value.get("attributes", {})
    if not isinstance(raw_attributes, dict) or len(raw_attributes) > MAX_ATTRIBUTES:
        raise ValueError(f"{field}.attributes must be an object with no more than {MAX_ATTRIBUTES} fields")
    attributes = {}
    for key, item in raw_attributes.items():
        if not isinstance(key, str) or key not in ATTRIBUTE_KEYS:
            continue
        attributes[key] = _attribute(item, f"{field}.attributes.{key}")
    return {
        "event_id": event_id,
        "event_type": event_type,
        "severity": severity,
        "occurred_at": occurred_at.isoformat(),
        "site_id": site_id,
        "router_id": router_id,
        "summary": summary.strip(),
        "attributes": dict(sorted(attributes.items())),
    }


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    try:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError("webhook input must contain JSON-compatible finite values") from error
    if len(encoded.encode("utf-8")) > MAX_INPUT_BYTES:
        raise ValueError(f"webhook input exceeds the {MAX_INPUT_BYTES}-byte input limit")

    now = _timestamp(payload.get("now"), "now")
    batch_id = _id(payload.get("batch_id"), "batch_id")
    key_id = _id(payload.get("key_id"), "key_id")
    secret = payload.get("signing_secret")
    if not isinstance(secret, str) or len(secret.encode("utf-8")) < 32 or len(secret.encode("utf-8")) > 4096:
        raise ValueError("signing_secret must contain from 32 to 4096 UTF-8 bytes")
    allowed_hosts = _allowed_hosts(payload.get("allowed_hosts"))
    endpoint = _endpoint(payload.get("endpoint"), allowed_hosts)

    raw_events = payload.get("events")
    if not isinstance(raw_events, list) or not 1 <= len(raw_events) <= MAX_EVENTS:
        raise ValueError(f"events must contain from 1 to {MAX_EVENTS} records")
    events = [_event(item, index) for index, item in enumerate(raw_events)]
    event_ids = [item["event_id"] for item in events]
    if len(event_ids) != len(set(event_ids)):
        raise ValueError("event_id values must be unique within a webhook batch")
    events.sort(key=lambda item: item["event_id"])

    future_count = sum(
        datetime.fromisoformat(item["occurred_at"]) > now + timedelta(minutes=5)
        for item in events
    )
    if future_count:
        raise ValueError("event occurred_at must not be more than five minutes in the future")

    body_object = {
        "schema_version": "1.0",
        "batch_id": batch_id,
        "key_id": key_id,
        "created_at": now.isoformat(),
        "events": events,
    }
    body = json.dumps(body_object, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    timestamp = str(int(now.timestamp()))
    signature_material = timestamp.encode("ascii") + b"." + body.encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), signature_material, hashlib.sha256).hexdigest()
    return {
        "status": "prepared",
        "delivery": {
            "method": "POST",
            "endpoint": endpoint,
            "body": body,
            "headers": {
                "Content-Type": "application/json",
                "X-WiFiAnalyzer-Key-Id": key_id,
                "X-WiFiAnalyzer-Timestamp": timestamp,
                "X-WiFiAnalyzer-Signature": f"v1={signature}",
                "Idempotency-Key": batch_id,
            },
        },
        "summary": {
            "batch_id": batch_id,
            "event_count": len(events),
            "critical_count": sum(item["severity"] == "critical" for item in events),
            "warning_count": sum(item["severity"] == "warning" for item in events),
            "info_count": sum(item["severity"] == "info" for item in events),
            "endpoint_host": urlsplit(endpoint).hostname,
            "key_id": key_id,
        },
        "note": (
            "This feature prepares a signed request but does not transmit it or persist the signing secret. "
            "The downstream dispatcher must use an approved egress policy, resolve and reject private, loopback, "
            "link-local and non-routable addresses at connection time, revalidate DNS results, refuse redirects, "
            "enforce timeouts and mark batch_id idempotently. The secret belongs in a dedicated secret store."
        ),
    }


FEATURE = {
    "id": "F185",
    "slug": "router_webhook_envelope_builder",
    "name": "Allow-listed signed router webhook envelope builder",
    "category": "Router operations",
    "description": (
        "Create canonical event batches signed with HMAC-SHA256 for exact allow-listed HTTPS hostnames, "
        "with key IDs, timestamps and idempotency keys; produce an envelope without sending it."
    ),
    "parameters": {
        "now": "timezone-aware signing timestamp",
        "batch_id": "stable caller-provided delivery idempotency key",
        "endpoint": "HTTPS endpoint on an exact allow-listed DNS hostname",
        "allowed_hosts": "1 to 50 exact DNS hostnames",
        "key_id": "identifier for an externally managed signing secret",
        "signing_secret": "32 to 4096 UTF-8 bytes, never returned",
        "events": "1 to 500 normalized router events",
    },
    "run": run,
}
