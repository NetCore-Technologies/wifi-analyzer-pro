"""Prepare independent, egress-approved signed deliveries for multiple webhook subscriptions.

This feature is deliberately a planner: it performs no DNS lookups, socket operations,
or HTTP requests. Each subscription batch must carry matching fresh connection evidence
and an externally-managed signing key before an HMAC envelope is prepared.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from .feature_185_router_webhook_envelope_builder import run as build_envelope
from .feature_187_router_webhook_egress_policy_verifier import run as verify_egress
from .feature_190_router_webhook_subscription_router import run as route_subscriptions

MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_SUBSCRIPTIONS = 100
MAX_SIGNING_KEYS = 100
MAX_EVIDENCE_RECORDS = 100
MAX_DELIVERIES = 500
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")


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


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError(f"{field} must be a 1 to 64 character identifier")
    return value


def _signing_keys(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or len(value) > MAX_SIGNING_KEYS:
        raise ValueError(f"signing_keys must be an object with no more than {MAX_SIGNING_KEYS} entries")
    result = {}
    for raw_key, secret in value.items():
        key_id = _identifier(raw_key, "signing_keys key ID")
        if not isinstance(secret, str) or not 32 <= len(secret.encode("utf-8")) <= 4096:
            raise ValueError(f"signing_keys.{key_id} must contain from 32 to 4096 UTF-8 bytes")
        result[key_id] = secret
    return result


def _evidence_map(value: object) -> dict[str, dict]:
    if not isinstance(value, list) or len(value) > MAX_EVIDENCE_RECORDS:
        raise ValueError(f"egress_evidence must be a list with no more than {MAX_EVIDENCE_RECORDS} records")
    result = {}
    for index, item in enumerate(value):
        field = f"egress_evidence[{index}]"
        if not isinstance(item, dict):
            raise ValueError(f"{field} must be an object")
        subscription_id = _identifier(item.get("subscription_id"), f"{field}.subscription_id")
        if subscription_id in result:
            raise ValueError("egress_evidence must contain no more than one record per subscription")
        result[subscription_id] = {
            key: child for key, child in item.items() if key != "subscription_id"
        }
    return result


def _egress_summary(verified: dict) -> dict:
    return {
        "approved": bool(verified.get("approved")),
        "hostname": verified.get("hostname"),
        "connected_peer_ip": verified.get("connected_peer_ip"),
        "connected_port": verified.get("connected_port"),
        "tls_version": verified.get("tls_version"),
        "dns_resolution_age_seconds": verified.get("dns_resolution_age_seconds"),
        "reasons": list(verified.get("reasons", [])),
    }


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    try:
        encoded = json.dumps(
            payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError("orchestration input must contain JSON-compatible finite values") from error
    if len(encoded) > MAX_INPUT_BYTES:
        raise ValueError(f"orchestration input exceeds the {MAX_INPUT_BYTES}-byte input limit")

    now = _timestamp(payload.get("now"), "now")
    subscriptions = payload.get("subscriptions")
    if not isinstance(subscriptions, list) or not 1 <= len(subscriptions) <= MAX_SUBSCRIPTIONS:
        raise ValueError(f"subscriptions must contain from 1 to {MAX_SUBSCRIPTIONS} records")
    signing_keys = _signing_keys(payload.get("signing_keys"))
    egress_by_subscription = _evidence_map(payload.get("egress_evidence", []))

    # F190 owns canonical subscription matching, deduplication and stable batch IDs.
    plan = route_subscriptions({
        "subscriptions": subscriptions,
        "events": payload.get("events"),
    })
    batches = plan["batches"]
    if len(batches) > MAX_DELIVERIES:
        raise ValueError(f"orchestration generated more than {MAX_DELIVERIES} deliveries")

    prepared = []
    blocked = []
    subscription_ids = {item["subscription_id"] for item in plan["subscriptions"]}
    if any(item not in subscription_ids for item in egress_by_subscription):
        raise ValueError("egress_evidence references an unknown subscription")

    for batch in batches:
        subscription_id = batch["subscription_id"]
        endpoint = batch["endpoint"]
        allowed_hosts = batch["allowed_hosts"]
        batch_id = batch["batch_id"]
        reasons = []
        verified = None

        signing_secret = signing_keys.get(batch["key_id"])
        if signing_secret is None:
            reasons.append("signing_key_missing")

        evidence = egress_by_subscription.get(subscription_id)
        if evidence is None:
            reasons.append("egress_evidence_missing")
        else:
            evidence_endpoint = evidence.get("endpoint")
            evidence_hosts = evidence.get("allowed_hosts")
            if evidence_endpoint != endpoint:
                reasons.append("egress_endpoint_mismatch")
            if (
                not isinstance(evidence_hosts, list)
                or any(not isinstance(host, str) for host in evidence_hosts)
                or sorted(evidence_hosts) != sorted(allowed_hosts)
            ):
                reasons.append("egress_allowlist_mismatch")
            try:
                connected_at = _timestamp(evidence.get("connected_at"), "egress_evidence.connected_at")
                evidence_age = (now - connected_at).total_seconds()
                if evidence_age > 60:
                    reasons.append("egress_evidence_stale")
                elif evidence_age < -30:
                    reasons.append("egress_evidence_from_future")
            except ValueError:
                reasons.append("egress_evidence_invalid_timestamp")

            if not any(reason.startswith("egress_") for reason in reasons):
                try:
                    verified = verify_egress(evidence)
                except (TypeError, ValueError):
                    reasons.append("egress_evidence_invalid")
                else:
                    if not verified.get("approved"):
                        reasons.extend(
                            f"egress_policy:{reason}"
                            for reason in verified.get("reasons", [])
                        )

        if reasons:
            blocked.append({
                "subscription_id": subscription_id,
                "batch_id": batch_id,
                "event_count": batch["event_count"],
                "status": "blocked",
                "reasons": sorted(set(reasons)),
                "egress": _egress_summary(verified) if verified else None,
            })
            continue

        try:
            envelope = build_envelope({
                "now": now.isoformat(),
                "batch_id": batch_id,
                "key_id": batch["key_id"],
                "signing_secret": signing_secret,
                "endpoint": endpoint,
                "allowed_hosts": allowed_hosts,
                "events": batch["events"],
            })
        except (TypeError, ValueError):
            blocked.append({
                "subscription_id": subscription_id,
                "batch_id": batch_id,
                "event_count": batch["event_count"],
                "status": "blocked",
                "reasons": ["signed_envelope_validation_failed"],
                "egress": _egress_summary(verified) if verified else None,
            })
            continue

        delivery = envelope["delivery"]
        prepared.append({
            "subscription_id": subscription_id,
            "batch_id": batch_id,
            "key_id": batch["key_id"],
            "event_count": batch["event_count"],
            "status": "prepared",
            "endpoint": delivery["endpoint"],
            "headers": delivery["headers"],
            "body": delivery["body"],
            "egress": _egress_summary(verified),
        })

    prepared.sort(key=lambda item: (item["subscription_id"], item["batch_id"]))
    blocked.sort(key=lambda item: (item["subscription_id"], item["batch_id"]))
    prepared_count = len(prepared)
    blocked_count = len(blocked)
    if prepared_count and blocked_count:
        status = "partially_prepared"
    elif prepared_count:
        status = "prepared"
    elif blocked_count:
        status = "blocked"
    else:
        status = "empty"

    return {
        "status": status,
        "summary": {
            "subscription_count": len(subscriptions),
            "planned_batch_count": len(batches),
            "prepared_delivery_count": prepared_count,
            "blocked_delivery_count": blocked_count,
            "event_delivery_count": sum(item["event_count"] for item in prepared),
        },
        "routing_summary": plan["summary"],
        "subscriptions": plan["subscriptions"],
        "prepared_deliveries": prepared,
        "blocked_deliveries": blocked,
        "note": (
            "This feature prepares independent HMAC-signed deliveries for each subscription only when a matching "
            "signing key and fresh approved DNS/TLS evidence are supplied. It performs no DNS lookups, socket "
            "operations or HTTP requests and never returns signing secrets. A dispatcher must re-resolve, pin the "
            "actual peer IP, verify TLS and re-run the F187 egress policy immediately before every network attempt; "
            "prepared deliveries are not proof of later connectivity."
        ),
    }


FEATURE = {
    "id": "F192",
    "slug": "router_webhook_delivery_orchestrator",
    "name": "Multi-subscription webhook delivery orchestrator",
    "category": "Router operations",
    "description": (
        "Coordinate F190 subscription routing, F185 per-batch HMAC signing and F187 endpoint-specific DNS/TLS "
        "evidence; prepare independent deliveries or explain why each batch is blocked, without sending traffic "
        "or exposing signing secrets."
    ),
    "parameters": {
        "now": "timezone-aware orchestration timestamp",
        "subscriptions": "1 to 100 F190 subscription definitions",
        "events": "normalized events accepted by F190",
        "signing_keys": "key_id-to-secret mapping held outside persistent event storage",
        "egress_evidence": "at most one matching F187 DNS/TLS evidence record per subscription",
    },
    "run": run,
}
