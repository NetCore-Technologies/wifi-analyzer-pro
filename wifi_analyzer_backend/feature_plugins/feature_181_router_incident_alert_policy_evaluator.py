"""Evaluate local router incident policies against normalized findings.

Pure, deterministic evaluator. It emits alert candidates only: it does not schedule work,
persist acknowledgement state, send notifications/webhooks, or change router devices.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone

MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_POLICIES = 100
MAX_FINDINGS = 20000
MAX_PREVIOUS_ALERTS = 20000
MAX_ALERTS_PER_POLICY = 1000
MAX_SAMPLES = 5
SEVERITY_RANK = {"critical": 0, "warning": 1, "info": 2}
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
CODE = re.compile(r"^[a-z][a-z0-9_.-]{0,79}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


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


def _id(value: object, field: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError(f"{field} must be a 1 to 64 character identifier")
    return value


def _text(value: object, field: str, limit: int = 128) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > limit:
        raise ValueError(f"{field} must be a string of at most {limit} characters")
    result = "".join(ch for ch in value.strip() if ord(ch) >= 32 and ord(ch) != 127)
    return result or None


def _scalar(value: object, field: str):
    if value is None or isinstance(value, (str, bool, int)):
        if isinstance(value, str) and len(value) > 256:
            raise ValueError(f"{field} exceeds the 256-character limit")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{field} must be finite")
        return value
    raise ValueError(f"{field} must be a JSON scalar")


def _list_of_strings(value: object, field: str, allowed: set[str] | None = None, maximum: int = 64) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError(f"{field} must be a list containing no more than {maximum} values")
    result, seen = [], set()
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item or len(item) > 64:
            raise ValueError(f"{field}[{index}] must be a non-empty string of at most 64 characters")
        if allowed is not None and item not in allowed:
            raise ValueError(f"{field}[{index}] is not supported")
        if item not in seen:
            result.append(item)
            seen.add(item)
    return result


def _policy(raw: object, index: int) -> dict:
    field = f"policies[{index}]"
    if not isinstance(raw, dict):
        raise ValueError(f"{field} must be an object")
    policy_id = _id(raw.get("policy_id"), f"{field}.policy_id")
    match_codes = raw.get("match_codes")
    if not isinstance(match_codes, list) or not 1 <= len(match_codes) <= 128:
        raise ValueError(f"{field}.match_codes must contain from 1 to 128 codes")
    codes, seen = [], set()
    for code in match_codes:
        if code != "*" and (not isinstance(code, str) or not CODE.fullmatch(code)):
            raise ValueError(f"{field}.match_codes must contain valid lowercase finding codes or '*'")
        if code not in seen:
            codes.append(code)
            seen.add(code)
    enabled = raw.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ValueError(f"{field}.enabled must be a boolean")
    minimum = raw.get("minimum_severity", "warning")
    if minimum not in SEVERITY_RANK:
        raise ValueError(f"{field}.minimum_severity must be critical, warning or info")
    override = raw.get("severity_override")
    if override is not None and override not in SEVERITY_RANK:
        raise ValueError(f"{field}.severity_override must be critical, warning or info")
    group_by = raw.get("group_by", "router")
    if group_by not in {"site", "router", "resource"}:
        raise ValueError(f"{field}.group_by must be site, router or resource")
    minimum_occurrences = raw.get("minimum_occurrences", 1)
    if isinstance(minimum_occurrences, bool) or not isinstance(minimum_occurrences, int) or not 1 <= minimum_occurrences <= MAX_FINDINGS:
        raise ValueError(f"{field}.minimum_occurrences must be an integer from 1 to {MAX_FINDINGS}")
    maximum_alerts = raw.get("maximum_alerts", 100)
    if isinstance(maximum_alerts, bool) or not isinstance(maximum_alerts, int) or not 1 <= maximum_alerts <= MAX_ALERTS_PER_POLICY:
        raise ValueError(f"{field}.maximum_alerts must be an integer from 1 to {MAX_ALERTS_PER_POLICY}")
    return {
        "policy_id": policy_id,
        "match_codes": codes,
        "enabled": enabled,
        "minimum_severity": minimum,
        "severity_override": override,
        "group_by": group_by,
        "minimum_occurrences": minimum_occurrences,
        "maximum_alerts": maximum_alerts,
        "site_allowlist": _list_of_strings(raw.get("site_allowlist"), f"{field}.site_allowlist"),
        "adapter_allowlist": _list_of_strings(
            raw.get("adapter_allowlist"), f"{field}.adapter_allowlist",
            {"openwrt", "unifi", "mikrotik"},
        ),
    }


def _finding(raw: object, index: int) -> dict:
    field = f"findings[{index}]"
    if not isinstance(raw, dict):
        raise ValueError(f"{field} must be an object")
    site_id = _id(raw.get("site_id", "unassigned"), f"{field}.site_id")
    router_id = raw.get("router_id")
    if router_id is None and isinstance(raw.get("router_ids"), list) and len(raw["router_ids"]) == 1:
        router_id = raw["router_ids"][0]
    if router_id is not None:
        router_id = _id(router_id, f"{field}.router_id")
    code = raw.get("code")
    if not isinstance(code, str) or not CODE.fullmatch(code):
        raise ValueError(f"{field}.code must be a valid lowercase finding code")
    severity = raw.get("severity")
    if severity not in SEVERITY_RANK:
        raise ValueError(f"{field}.severity must be critical, warning or info")
    adapter = raw.get("adapter_id")
    if adapter is not None and (not isinstance(adapter, str) or adapter not in {"openwrt", "unifi", "mikrotik"}):
        raise ValueError(f"{field}.adapter_id is not supported")
    return {
        "site_id": site_id,
        "router_id": router_id,
        "adapter_id": adapter,
        "code": code,
        "severity": severity,
        "resource_type": _text(raw.get("resource_type"), f"{field}.resource_type", 64),
        "resource_id": _text(raw.get("resource_id", raw.get("client_mac")), f"{field}.resource_id"),
        "observed": _scalar(raw.get("observed"), f"{field}.observed"),
        "threshold": _scalar(raw.get("threshold"), f"{field}.threshold"),
    }


def _previous(raw: object, index: int) -> dict:
    field = f"previous_alerts[{index}]"
    if not isinstance(raw, dict):
        raise ValueError(f"{field} must be an object")
    key = raw.get("alert_key")
    if not isinstance(key, str) or not SHA256.fullmatch(key):
        raise ValueError(f"{field}.alert_key must be a 64-character lowercase SHA-256 key")
    status = raw.get("status", "active")
    if status not in {"new", "active", "ongoing", "acknowledged"}:
        raise ValueError(f"{field}.status must be new, active, ongoing or acknowledged")
    severity = raw.get("severity", "warning")
    if severity not in SEVERITY_RANK:
        raise ValueError(f"{field}.severity must be critical, warning or info")
    count = raw.get("occurrence_count", 1)
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise ValueError(f"{field}.occurrence_count must be a positive integer")
    router_id = raw.get("router_id")
    if router_id is not None:
        router_id = _id(router_id, f"{field}.router_id")
    return {
        "alert_key": key,
        "status": status,
        "first_seen_at": _timestamp(raw.get("first_seen_at"), f"{field}.first_seen_at"),
        "last_seen_at": _timestamp(raw.get("last_seen_at", raw.get("first_seen_at")), f"{field}.last_seen_at"),
        "occurrence_count": count,
        "rule_id": _id(raw.get("rule_id", raw.get("policy_id")), f"{field}.rule_id"),
        "site_id": _id(raw.get("site_id", "unassigned"), f"{field}.site_id"),
        "router_id": router_id,
        "resource_type": _text(raw.get("resource_type"), f"{field}.resource_type", 64),
        "resource_id": _text(raw.get("resource_id"), f"{field}.resource_id"),
        "severity": severity,
    }


def _identity(policy: dict, finding: dict) -> tuple:
    if policy["group_by"] == "site":
        return finding["site_id"], None, None, None
    if policy["group_by"] == "router":
        return finding["site_id"], finding["router_id"], None, None
    return finding["site_id"], finding["router_id"], finding["resource_type"], finding["resource_id"]


def _key(policy_id: str, identity: tuple) -> str:
    material = json.dumps([policy_id, *identity], ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    try:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError("alert input must contain JSON-compatible finite values") from error
    if len(encoded.encode("utf-8")) > MAX_INPUT_BYTES:
        raise ValueError(f"alert input exceeds the {MAX_INPUT_BYTES}-byte input limit")
    generated_at = _timestamp(payload.get("generated_at"), "generated_at")

    raw_policies = payload.get("policies")
    if not isinstance(raw_policies, list) or not 1 <= len(raw_policies) <= MAX_POLICIES:
        raise ValueError(f"policies must contain from 1 to {MAX_POLICIES} policy records")
    policies = [_policy(item, index) for index, item in enumerate(raw_policies)]
    if len({item["policy_id"] for item in policies}) != len(policies):
        raise ValueError("policy_id values must be unique")

    raw_findings = payload.get("findings", [])
    if not isinstance(raw_findings, list) or len(raw_findings) > MAX_FINDINGS:
        raise ValueError(f"findings must be a list containing no more than {MAX_FINDINGS} records")
    findings = [_finding(item, index) for index, item in enumerate(raw_findings)]

    raw_previous = payload.get("previous_alerts", [])
    if not isinstance(raw_previous, list) or len(raw_previous) > MAX_PREVIOUS_ALERTS:
        raise ValueError(f"previous_alerts must be a list containing no more than {MAX_PREVIOUS_ALERTS} records")
    previous = [_previous(item, index) for index, item in enumerate(raw_previous)]
    previous_by_key = {item["alert_key"]: item for item in previous}
    if len(previous_by_key) != len(previous):
        raise ValueError("previous_alerts must not contain duplicate alert keys")

    alerts, resolved, suppressed = [], [], []
    active_keys = set()
    policy_summaries = []
    matched_total = 0
    enabled_count = 0

    for policy in policies:
        if not policy["enabled"]:
            policy_summaries.append({
                "policy_id": policy["policy_id"], "enabled": False,
                "matched_finding_count": 0, "alert_count": 0, "suppressed_group_count": 0,
            })
            continue
        enabled_count += 1
        matches = defaultdict(list)
        codes = set(policy["match_codes"])
        for finding in findings:
            if "*" not in codes and finding["code"] not in codes:
                continue
            if SEVERITY_RANK[finding["severity"]] > SEVERITY_RANK[policy["minimum_severity"]]:
                continue
            if policy["site_allowlist"] and finding["site_id"] not in policy["site_allowlist"]:
                continue
            if policy["adapter_allowlist"] and finding["adapter_id"] not in policy["adapter_allowlist"]:
                continue
            matches[_identity(policy, finding)].append(finding)
        matched_total += sum(len(values) for values in matches.values())

        policy_alerts, policy_suppressed = [], []
        for identity, group in sorted(
            matches.items(),
            key=lambda pair: tuple("" if part is None else str(part) for part in pair[0]),
        ):
            unique = {}
            for item in group:
                event = (
                    item["site_id"], item["router_id"], item["adapter_id"], item["code"],
                    item["resource_type"], item["resource_id"], item["observed"], item["threshold"],
                )
                unique[json.dumps(event, ensure_ascii=False, separators=(",", ":"))] = item
            events = list(unique.values())
            if len(events) < policy["minimum_occurrences"]:
                policy_suppressed.append({
                    "policy_id": policy["policy_id"], "site_id": identity[0],
                    "router_id": identity[1], "observed_occurrences": len(events),
                    "required_occurrences": policy["minimum_occurrences"],
                    "reason": "below_minimum_occurrences",
                })
                continue
            alert_key = _key(policy["policy_id"], identity)
            active_keys.add(alert_key)
            prior = previous_by_key.get(alert_key)
            severity = policy["severity_override"] or min(
                (item["severity"] for item in events), key=lambda value: SEVERITY_RANK[value]
            )
            codes_in_group = sorted({item["code"] for item in events})
            adapters = sorted({item["adapter_id"] for item in events if item["adapter_id"]})
            policy_alerts.append({
                "alert_key": alert_key,
                "policy_id": policy["policy_id"],
                "rule_id": policy["policy_id"],
                "status": (
                    "acknowledged" if prior and prior["status"] == "acknowledged"
                    else "ongoing" if prior else "new"
                ),
                "severity": severity,
                "site_id": identity[0],
                "router_id": identity[1],
                "resource_type": identity[2],
                "resource_id": identity[3],
                "source_codes": codes_in_group,
                "adapter_ids": adapters,
                "occurrence_count": (prior["occurrence_count"] if prior else 0) + len(events),
                "current_occurrence_count": len(events),
                "first_seen_at": prior["first_seen_at"] if prior else generated_at,
                "last_seen_at": generated_at,
                "sample_evidence": [{
                    "code": item["code"], "severity": item["severity"],
                    "adapter_id": item["adapter_id"], "resource_type": item["resource_type"],
                    "resource_id": item["resource_id"], "observed": item["observed"],
                    "threshold": item["threshold"],
                } for item in events[:MAX_SAMPLES]],
                "samples_truncated": len(events) > MAX_SAMPLES,
            })
        policy_alerts.sort(key=lambda item: (
            SEVERITY_RANK[item["severity"]], item["site_id"], item["router_id"] or "",
            item["resource_type"] or "", item["resource_id"] or "",
        ))
        alerts.extend(policy_alerts[:policy["maximum_alerts"]])
        for item in policy_alerts[policy["maximum_alerts"]:]:
            policy_suppressed.append({
                "policy_id": policy["policy_id"], "site_id": item["site_id"],
                "router_id": item["router_id"], "reason": "maximum_alerts_per_policy",
            })
        suppressed.extend(policy_suppressed)
        policy_summaries.append({
            "policy_id": policy["policy_id"], "enabled": True,
            "matched_finding_count": sum(len(values) for values in matches.values()),
            "alert_count": min(len(policy_alerts), policy["maximum_alerts"]),
            "suppressed_group_count": len(policy_suppressed),
        })

    for key, prior in previous_by_key.items():
        if key not in active_keys:
            resolved.append({
                "alert_key": key, "policy_id": prior["rule_id"], "rule_id": prior["rule_id"],
                "status": "resolved", "severity": prior["severity"],
                "site_id": prior["site_id"], "router_id": prior["router_id"],
                "resource_type": prior["resource_type"], "resource_id": prior["resource_id"],
                "first_seen_at": prior["first_seen_at"], "last_seen_at": prior["last_seen_at"],
                "resolved_at": generated_at, "occurrence_count": prior["occurrence_count"],
            })

    alerts.sort(key=lambda item: (
        SEVERITY_RANK[item["severity"]], item["site_id"], item["policy_id"], item["alert_key"]
    ))
    resolved.sort(key=lambda item: (item["site_id"], item["policy_id"], item["alert_key"]))
    counts = Counter(item["status"] for item in alerts)
    return {
        "status": "evaluated",
        "generated_at": generated_at,
        "summary": {
            "policy_count": len(policies),
            "enabled_policy_count": enabled_count,
            "finding_count": len(findings),
            "matched_finding_count": matched_total,
            "new_alert_count": counts["new"],
            "ongoing_alert_count": counts["ongoing"],
            "acknowledged_alert_count": counts["acknowledged"],
            "resolved_alert_count": len(resolved),
            "suppressed_group_count": len(suppressed),
            "critical_alert_count": sum(item["severity"] == "critical" for item in alerts),
            "warning_alert_count": sum(item["severity"] == "warning" for item in alerts),
            "info_alert_count": sum(item["severity"] == "info" for item in alerts),
        },
        "policies": policy_summaries,
        "alerts": alerts,
        "resolved_alerts": resolved,
        "suppressed": suppressed[:1000],
        "details_truncated": len(suppressed) > 1000,
        "note": (
            "This output contains local alert candidates only. It does not send notifications, invoke webhooks, "
            "persist acknowledgement state, or prove that a reported condition is a root cause. Supply the "
            "returned alert keys, statuses and timestamps as previous_alerts on the next evaluation to retain lifecycle state."
        ),
    }


FEATURE = {
    "id": "F181",
    "slug": "router_incident_alert_policy_evaluator",
    "name": "Router incident alert policy evaluator",
    "category": "Router operations",
    "description": (
        "Apply scoped severity/code/occurrence policies to normalized router audit findings and create "
        "deterministic new, ongoing, acknowledged or resolved alert candidates with stable deduplication keys."
    ),
    "parameters": {
        "generated_at": "timezone-aware evaluation timestamp",
        "policies": "1 to 100 local alert policies",
        "findings": "normalized finding records from router audits",
        "previous_alerts": "optional previous evaluator output used to retain lifecycle state",
    },
    "run": run,
}
