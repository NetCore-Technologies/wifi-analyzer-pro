"""Prepare a leased report job for safe webhook delivery without sending network traffic."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import datetime, timezone

from .feature_185_router_webhook_envelope_builder import run as build_webhook_envelope
from .feature_187_router_webhook_egress_policy_verifier import run as verify_webhook_egress


MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_FINDING_EVENTS = 499
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
EVENT_CODE = re.compile(r"^[a-z][a-z0-9_.-]{0,79}$")
SEVERITY_RANK = {"critical": 0, "warning": 1, "info": 2}


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


def _verify_report_bundle(bundle: object, job: dict) -> dict:
    if not isinstance(bundle, dict) or bundle.get("schema_version") != "1.0":
        raise ValueError("claimed_job.report_bundle must be a version 1.0 report bundle")
    report_id = _id(bundle.get("report_id"), "claimed_job.report_bundle.report_id")
    if report_id != job["report_id"]:
        raise ValueError("claimed_job report_id does not match report bundle")
    content_hash = bundle.get("content_hash")
    if not isinstance(content_hash, str) or not SHA256.fullmatch(content_hash):
        raise ValueError("claimed_job.report_bundle.content_hash must be a SHA-256 digest")
    body = {key: value for key, value in bundle.items() if key != "content_hash"}
    try:
        canonical_body = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        canonical_bundle = json.dumps(bundle, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError("claimed_job.report_bundle must contain JSON-compatible finite values") from error
    expected = hashlib.sha256(canonical_body.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(expected, content_hash):
        raise ValueError("claimed_job.report_bundle content hash is invalid")
    payload_hash = hashlib.sha256(canonical_bundle.encode("utf-8")).hexdigest()
    if payload_hash != job["payload_hash"]:
        raise ValueError("claimed_job payload_hash does not match its report bundle")
    return bundle


def _event_id(job_key: str, suffix: str) -> str:
    return hashlib.sha256(f"{job_key}:{suffix}".encode("utf-8")).hexdigest()


def _finding_event(finding: dict, job: dict, occurred_at: str, index: int) -> dict:
    code = finding.get("code")
    severity = finding.get("severity")
    if not isinstance(code, str) or not EVENT_CODE.fullmatch(code):
        raise ValueError(f"report finding {index} has an invalid code")
    if not isinstance(severity, str) or severity not in SEVERITY_RANK:
        raise ValueError(f"report finding {index} has an invalid severity")
    site_id = finding.get("site_id")
    router_id = finding.get("router_id")
    if site_id is not None:
        site_id = _id(site_id, f"report finding {index}.site_id")
    if router_id is not None:
        router_id = _id(router_id, f"report finding {index}.router_id")
    resource_type = finding.get("resource_type")
    resource_id = finding.get("resource_id")
    if resource_type is not None and (not isinstance(resource_type, str) or len(resource_type) > 64):
        raise ValueError(f"report finding {index}.resource_type is invalid")
    if resource_id is not None and (not isinstance(resource_id, str) or len(resource_id) > 128):
        raise ValueError(f"report finding {index}.resource_id is invalid")
    source_id = finding.get("source_id")
    if not isinstance(source_id, str) or not IDENTIFIER.fullmatch(source_id):
        raise ValueError(f"report finding {index}.source_id is invalid")
    attributes = {
        "report_id": job["report_id"],
        "content_hash": job["report_bundle"]["content_hash"],
        "source_id": source_id,
    }
    if resource_type:
        attributes["resource_type"] = resource_type
    if resource_id:
        attributes["resource_id"] = resource_id
    details = finding.get("details", {})
    if isinstance(details, dict):
        for key in ("observed", "threshold"):
            value = details.get(key)
            if value is None or isinstance(value, (str, int, float, bool)):
                attributes[key] = value
    return {
        "event_id": _event_id(job["job_key"], f"finding:{index}:{finding.get('finding_id', 'unknown')}"),
        "event_type": "report.finding",
        "severity": severity,
        "occurred_at": occurred_at,
        "site_id": site_id,
        "router_id": router_id,
        "summary": f"{severity} router finding: {code}",
        "attributes": attributes,
    }


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    try:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError("delivery input must contain JSON-compatible finite values") from error
    if len(encoded.encode("utf-8")) > MAX_INPUT_BYTES:
        raise ValueError(f"delivery input exceeds the {MAX_INPUT_BYTES}-byte input limit")

    now = _timestamp(payload.get("now"), "now")
    job = payload.get("claimed_job")
    if not isinstance(job, dict):
        raise ValueError("claimed_job must be an object returned by the report-job claim API")
    if job.get("status") != "leased":
        raise ValueError("claimed_job must be in the leased state")
    job_id = job.get("id")
    if isinstance(job_id, bool) or not isinstance(job_id, int) or job_id < 1:
        raise ValueError("claimed_job.id must be a positive integer")
    schedule_id = _id(job.get("schedule_id"), "claimed_job.schedule_id")
    occurrence_id = job.get("occurrence_id")
    if not isinstance(occurrence_id, str) or not SHA256.fullmatch(occurrence_id):
        raise ValueError("claimed_job.occurrence_id must be a SHA-256 key")
    report_id = _id(job.get("report_id"), "claimed_job.report_id")
    job_key = job.get("job_key")
    if not isinstance(job_key, str) or not SHA256.fullmatch(job_key):
        raise ValueError("claimed_job.job_key must be a SHA-256 key")
    expected_job_key = hashlib.sha256(
        json.dumps([schedule_id, occurrence_id, report_id], separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if not hmac.compare_digest(job_key, expected_job_key):
        raise ValueError("claimed_job.job_key does not match its schedule occurrence")
    lease_id = job.get("lease_id")
    if not isinstance(lease_id, str) or not re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", lease_id
    ):
        raise ValueError("claimed_job.lease_id must be a canonical UUID")
    lease_owner = _id(job.get("lease_owner"), "claimed_job.lease_owner")
    lease_expires = _timestamp(job.get("lease_expires_at"), "claimed_job.lease_expires_at")
    if lease_expires <= now:
        raise ValueError("claimed_job worker lease has expired")
    payload_hash = job.get("payload_hash")
    if not isinstance(payload_hash, str) or not SHA256.fullmatch(payload_hash):
        raise ValueError("claimed_job.payload_hash must be a SHA-256 digest")
    bundle = _verify_report_bundle(job.get("report_bundle"), {
        "report_id": report_id,
        "payload_hash": payload_hash,
    })
    generated_at = _timestamp(bundle.get("generated_at"), "report_bundle.generated_at")
    if generated_at > now:
        raise ValueError("report_bundle.generated_at must not be in the future")

    event_mode = payload.get("event_mode", "summary")
    if not isinstance(event_mode, str) or event_mode not in {"summary", "summary_and_findings"}:
        raise ValueError("event_mode must be summary or summary_and_findings")
    maximum_findings = payload.get("maximum_finding_events", 100)
    if isinstance(maximum_findings, bool) or not isinstance(maximum_findings, int) or not 1 <= maximum_findings <= MAX_FINDING_EVENTS:
        raise ValueError(f"maximum_finding_events must be an integer from 1 to {MAX_FINDING_EVENTS}")

    summary = bundle.get("summary", {})
    if not isinstance(summary, dict):
        raise ValueError("report_bundle.summary must be an object")
    critical_count = summary.get("critical_count", 0)
    warning_count = summary.get("warning_count", 0)
    info_count = summary.get("info_count", 0)
    finding_count = summary.get("finding_count", 0)
    for field, value in (
        ("critical_count", critical_count), ("warning_count", warning_count),
        ("info_count", info_count), ("finding_count", finding_count),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"report_bundle.summary.{field} must be a non-negative integer")
    severity = (
        "critical" if critical_count else "warning" if warning_count else "info"
    )
    events = [{
        "event_id": _event_id(job_key, "report.generated"),
        "event_type": "report.generated",
        "severity": severity,
        "occurred_at": generated_at.isoformat(),
        "site_id": None,
        "router_id": None,
        "summary": (
            f"Scheduled router report {report_id} generated: {finding_count} findings "
            f"({critical_count} critical, {warning_count} warning, {info_count} info)"
        ),
        "attributes": {
            "report_id": report_id,
            "content_hash": bundle["content_hash"],
            "critical_count": critical_count,
            "warning_count": warning_count,
            "info_count": info_count,
            "finding_count": finding_count,
        },
    }]
    included_findings = 0
    truncated_findings = False
    if event_mode == "summary_and_findings":
        findings = bundle.get("findings", [])
        if not isinstance(findings, list):
            raise ValueError("report_bundle.findings must be a list")
        selected = findings[:maximum_findings]
        truncated_findings = len(findings) > len(selected)
        for index, finding in enumerate(selected):
            if not isinstance(finding, dict):
                raise ValueError(f"report_bundle.findings[{index}] must be an object")
            events.append(_finding_event(finding, {
                "job_key": job_key,
                "report_id": report_id,
                "report_bundle": bundle,
            }, generated_at.isoformat(), index))
        included_findings = len(selected)
    if len(events) > 500:
        raise ValueError("prepared webhook batch exceeds 500 events")

    webhook = payload.get("webhook")
    evidence = payload.get("egress_evidence")
    if not isinstance(webhook, dict) or not isinstance(evidence, dict):
        raise ValueError("webhook and egress_evidence must be objects")
    egress_payload = {
        "endpoint": webhook.get("endpoint"),
        "allowed_hosts": webhook.get("allowed_hosts"),
        **{
            key: evidence.get(key)
            for key in (
                "resolution_at", "connected_at", "resolved_addresses", "peer_ip",
                "connected_port", "tls_version", "tls_verified",
                "hostname_verified", "redirect_location",
            )
        },
    }
    egress = verify_webhook_egress(egress_payload)
    common = {
        "job": {
            "id": job_id,
            "schedule_id": schedule_id,
            "occurrence_id": occurrence_id,
            "report_id": report_id,
            "job_key": job_key,
            "lease_id": lease_id,
            "lease_owner": lease_owner,
            "lease_expires_at": lease_expires.isoformat(),
        },
        "egress": {
            "approved": egress["approved"],
            "status": egress["status"],
            "hostname": egress["hostname"],
            "connected_peer_ip": egress["connected_peer_ip"],
            "connected_port": egress["connected_port"],
            "dns_resolution_age_seconds": egress["dns_resolution_age_seconds"],
            "reasons": egress["reasons"],
            "connection_policy": egress["connection_policy"],
        },
        "summary": {
            "event_count": len(events),
            "finding_event_count": included_findings,
            "finding_events_truncated": truncated_findings,
            "report_id": report_id,
            "content_hash": bundle["content_hash"],
        },
    }
    if not egress["approved"]:
        return {
            "status": "blocked",
            **common,
            "delivery": None,
            "note": "Egress evidence was not approved. No signed delivery envelope was created or transmitted.",
        }

    signed = build_webhook_envelope({
        "now": now.isoformat(),
        "batch_id": job_key,
        "key_id": webhook.get("key_id"),
        "signing_secret": webhook.get("signing_secret"),
        "endpoint": webhook.get("endpoint"),
        "allowed_hosts": webhook.get("allowed_hosts"),
        "events": events,
    })
    return {
        "status": "ready",
        **common,
        "delivery": signed["delivery"],
        "note": (
            "A signed request has been prepared against verified public DNS/TLS evidence and the active job lease. "
            "No network request was made. The worker must send only to the pinned peer IP, retain the validated "
            "DNS hostname for TLS verification, refuse redirects, enforce timeouts, use the batch idempotency key, "
            "and complete/fail the job only while its lease remains active."
        ),
    }


FEATURE = {
    "id": "F189",
    "slug": "router_scheduled_report_delivery_package",
    "name": "Scheduled report webhook delivery package builder",
    "category": "Router operations",
    "description": (
        "Combine a valid leased F188 report job, F182 report hash, F187 DNS/TLS egress evidence and F185 HMAC "
        "envelopes into a ready-or-blocked delivery package without sending network traffic."
    ),
    "parameters": {
        "now": "timezone-aware worker time",
        "claimed_job": "leased job returned by the authenticated report-job claim API",
        "webhook": "endpoint, exact allowed_hosts, key_id and externally managed signing_secret",
        "egress_evidence": "fresh DNS, exact peer IP, TLS and redirect evidence for F187",
        "event_mode": "summary or summary_and_findings",
        "maximum_finding_events": "1 to 499",
    },
    "run": run,
}
