"""Compare two validated router audit report bundles."""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone

MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_FINDINGS = 20000
MAX_DETAILS = 4000
MAX_SECTIONS = 64
MAX_SITES = 128
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
CODE = re.compile(r"^[a-z][a-z0-9_.-]{0,79}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
FINDING_ID = re.compile(r"^[0-9a-f]{24}$")
SEVERITY_RANK = {"critical": 0, "warning": 1, "info": 2}
DETAIL_KEYS = {
    "observed", "threshold", "overlap_type", "ip_version", "vlan_id",
    "from_ap_id", "to_ap_id", "elapsed_seconds", "status", "health_score",
    "age_seconds", "target", "gateway", "routing_table", "section",
    "occurrence_count",
}


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


def _id(value: object, field: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError(f"{field} must be a 1 to 64 character identifier")
    return value


def _bounded_text(value: object, field: str, maximum: int = 256) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > maximum:
        raise ValueError(f"{field} must be a string of at most {maximum} characters")
    result = "".join(ch for ch in value.strip() if ord(ch) >= 32 and ord(ch) != 127)
    return result or None


def _safe_scalar(value: object, field: str):
    if value is None or isinstance(value, (str, bool, int)):
        if isinstance(value, str) and len(value) > 256:
            raise ValueError(f"{field} exceeds the 256-character limit")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{field} must be finite")
        return value
    raise ValueError(f"{field} must be a JSON scalar")


def _safe_details(value: object, field: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    result = {}
    for key, item in value.items():
        if key not in DETAIL_KEYS:
            continue
        result[key] = _safe_scalar(item, f"{field}.{key}")
    return result


def _summary(value: object, field: str) -> dict:
    if not isinstance(value, dict) or len(value) > 64:
        raise ValueError(f"{field} must be an object with at most 64 fields")
    result = {}
    for key, item in value.items():
        if not isinstance(key, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", key):
            continue
        result[key] = _safe_scalar(item, f"{field}.{key}")
    return result


def _finding(value: object, index: int, field: str) -> dict:
    name = f"{field}[{index}]"
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    finding_id = value.get("finding_id")
    if not isinstance(finding_id, str) or not FINDING_ID.fullmatch(finding_id):
        raise ValueError(f"{name}.finding_id must be a 24-character lowercase hexadecimal ID")
    source_id = _id(value.get("source_id"), f"{name}.source_id")
    source_type = value.get("source_type")
    if not isinstance(source_type, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", source_type):
        raise ValueError(f"{name}.source_type is invalid")
    code = value.get("code")
    if not isinstance(code, str) or not CODE.fullmatch(code):
        raise ValueError(f"{name}.code is invalid")
    severity = value.get("severity")
    if not isinstance(severity, str) or severity not in SEVERITY_RANK:
        raise ValueError(f"{name}.severity must be critical, warning or info")
    site_id = _id(value.get("site_id"), f"{name}.site_id")
    router_id = value.get("router_id")
    if router_id is not None:
        router_id = _id(router_id, f"{name}.router_id")
    resource_type = _bounded_text(value.get("resource_type"), f"{name}.resource_type", 64)
    resource_id = _bounded_text(value.get("resource_id"), f"{name}.resource_id", 128)
    details = _safe_details(value.get("details", {}), f"{name}.details")
    return {
        "finding_id": finding_id,
        "source_id": source_id,
        "source_type": source_type,
        "code": code,
        "severity": severity,
        "site_id": site_id,
        "router_id": router_id,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "details": details,
    }


def _section(value: object, index: int, field: str) -> dict:
    name = f"{field}[{index}]"
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    source_id = _id(value.get("source_id"), f"{name}.source_id")
    source_type = value.get("source_type")
    if not isinstance(source_type, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", source_type):
        raise ValueError(f"{name}.source_type is invalid")
    status = value.get("status")
    if not isinstance(status, str) or len(status) > 48:
        raise ValueError(f"{name}.status must be a string of at most 48 characters")
    summary = _summary(value.get("summary", {}), f"{name}.summary")
    return {"source_id": source_id, "source_type": source_type, "status": status, "summary": summary}


def _site(value: object, index: int, field: str) -> dict:
    name = f"{field}[{index}]"
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    site_id = _id(value.get("site_id"), f"{name}.site_id")
    counts = {}
    for key in ("finding_count", "critical_count", "warning_count", "info_count"):
        item = value.get(key, 0)
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise ValueError(f"{name}.{key} must be a non-negative integer")
        counts[key] = item
    source_types = value.get("source_types", [])
    if not isinstance(source_types, list) or len(source_types) > MAX_SECTIONS:
        raise ValueError(f"{name}.source_types must be a bounded list")
    safe_types = []
    for item in source_types:
        if not isinstance(item, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", item):
            raise ValueError(f"{name}.source_types contains an invalid source type")
        if item not in safe_types:
            safe_types.append(item)
    return {"site_id": site_id, **counts, "source_types": sorted(safe_types)}


def _validate_bundle(value: object, field: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be a report bundle object")
    if value.get("schema_version") != "1.0":
        raise ValueError(f"{field}.schema_version must be 1.0")
    report_id = _id(value.get("report_id"), f"{field}.report_id")
    content_hash = value.get("content_hash")
    if not isinstance(content_hash, str) or not SHA256.fullmatch(content_hash):
        raise ValueError(f"{field}.content_hash must be a 64-character lowercase SHA-256 digest")
    body = {key: item for key, item in value.items() if key != "content_hash"}
    try:
        canonical = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field} contains values that cannot be hashed") from error
    actual_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if actual_hash != content_hash:
        raise ValueError(f"{field}.content_hash does not match its report content")

    generated_at = _timestamp(value.get("generated_at"), f"{field}.generated_at")
    sections_raw = value.get("sections", [])
    sites_raw = value.get("sites", [])
    findings_raw = value.get("findings", [])
    if not isinstance(sections_raw, list) or len(sections_raw) > MAX_SECTIONS:
        raise ValueError(f"{field}.sections must contain no more than {MAX_SECTIONS} entries")
    if not isinstance(sites_raw, list) or len(sites_raw) > MAX_SITES:
        raise ValueError(f"{field}.sites must contain no more than {MAX_SITES} entries")
    if not isinstance(findings_raw, list) or len(findings_raw) > MAX_FINDINGS:
        raise ValueError(f"{field}.findings must contain no more than {MAX_FINDINGS} entries")

    sections = [_section(item, index, f"{field}.sections") for index, item in enumerate(sections_raw)]
    sites = [_site(item, index, f"{field}.sites") for index, item in enumerate(sites_raw)]
    findings = [_finding(item, index, f"{field}.findings") for index, item in enumerate(findings_raw)]
    if len({item["source_id"] for item in sections}) != len(sections):
        raise ValueError(f"{field}.sections must have unique source IDs")
    if len({item["site_id"] for item in sites}) != len(sites):
        raise ValueError(f"{field}.sites must have unique site IDs")
    report_title = _bounded_text(value.get("title", "Router audit report"), f"{field}.title", 120)
    return {
        "report_id": report_id,
        "title": report_title,
        "generated_at": generated_at.isoformat(),
        "content_hash": content_hash,
        "sections": sections,
        "sites": sites,
        "findings": findings,
    }


def _base_identity(item: dict) -> tuple:
    return (
        item["source_id"], item["source_type"], item["code"], item["site_id"],
        item["router_id"], item["resource_type"], item["resource_id"],
    )


def _event_value(item: dict) -> str:
    return json.dumps(
        {"severity": item["severity"], "details": item["details"]},
        ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    )


def _finding_diff(before: dict, after: dict) -> dict:
    identity = {
        "source_id": after["source_id"],
        "source_type": after["source_type"],
        "code": after["code"],
        "site_id": after["site_id"],
        "router_id": after["router_id"],
        "resource_type": after["resource_type"],
        "resource_id": after["resource_id"],
    }
    changed_fields = []
    for key in ("severity", "details"):
        if before[key] != after[key]:
            changed_fields.append(key)
    return {
        **identity,
        "previous_finding_id": before["finding_id"],
        "current_finding_id": after["finding_id"],
        "previous": {"severity": before["severity"], "details": before["details"]},
        "current": {"severity": after["severity"], "details": after["details"]},
        "changed_fields": changed_fields,
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
    previous = _validate_bundle(payload.get("previous"), "previous")
    current = _validate_bundle(payload.get("current"), "current")
    if datetime.fromisoformat(previous["generated_at"]) > datetime.fromisoformat(current["generated_at"]):
        raise ValueError("previous report generated_at must not be after current report generated_at")

    max_details = payload.get("maximum_details", 1000)
    if isinstance(max_details, bool) or not isinstance(max_details, int) or not 1 <= max_details <= MAX_DETAILS:
        raise ValueError(f"maximum_details must be an integer from 1 to {MAX_DETAILS}")
    include_details = payload.get("include_details", True)
    if not isinstance(include_details, bool):
        raise ValueError("include_details must be a boolean")
    source_allowlist = payload.get("source_allowlist", [])
    if not isinstance(source_allowlist, list) or len(source_allowlist) > MAX_SECTIONS:
        raise ValueError(f"source_allowlist must be a list of at most {MAX_SECTIONS} source IDs")
    safe_source_ids = [_id(value, "source_allowlist entry") for value in source_allowlist]
    if len(safe_source_ids) != len(set(safe_source_ids)):
        raise ValueError("source_allowlist entries must be unique")
    allowed_sources = set(safe_source_ids)

    def filtered(items):
        return [item for item in items if not allowed_sources or item["source_id"] in allowed_sources]

    previous_findings = filtered(previous["findings"])
    current_findings = filtered(current["findings"])
    before_groups = defaultdict(list)
    after_groups = defaultdict(list)
    for item in previous_findings:
        before_groups[_base_identity(item)].append(item)
    for item in current_findings:
        after_groups[_base_identity(item)].append(item)

    unchanged = []
    changed = []
    added = []
    removed = []
    all_identities = sorted(set(before_groups) | set(after_groups), key=lambda key: tuple("" if value is None else str(value) for value in key))
    for identity in all_identities:
        before = before_groups.get(identity, [])
        after = after_groups.get(identity, [])
        before_by_value = defaultdict(list)
        after_by_value = defaultdict(list)
        for item in before:
            before_by_value[_event_value(item)].append(item)
        for item in after:
            after_by_value[_event_value(item)].append(item)
        for value in set(before_by_value) | set(after_by_value):
            left = before_by_value.get(value, [])
            right = after_by_value.get(value, [])
            matched = min(len(left), len(right))
            unchanged.extend((left[index], right[index]) for index in range(matched))
            del left[:matched]
            del right[:matched]
        remaining_before = [item for values in before_by_value.values() for item in values]
        remaining_after = [item for values in after_by_value.values() for item in values]
        remaining_before.sort(key=lambda item: (SEVERITY_RANK[item["severity"]], item["finding_id"]))
        remaining_after.sort(key=lambda item: (SEVERITY_RANK[item["severity"]], item["finding_id"]))
        pairs = min(len(remaining_before), len(remaining_after))
        for index in range(pairs):
            changed.append(_finding_diff(remaining_before[index], remaining_after[index]))
        removed.extend(remaining_before[pairs:])
        added.extend(remaining_after[pairs:])

    before_sections = {item["source_id"]: item for item in previous["sections"] if not allowed_sources or item["source_id"] in allowed_sources}
    after_sections = {item["source_id"]: item for item in current["sections"] if not allowed_sources or item["source_id"] in allowed_sources}
    section_added, section_removed, section_changed = [], [], []
    for source_id in sorted(set(before_sections) | set(after_sections)):
        left, right = before_sections.get(source_id), after_sections.get(source_id)
        if left is None:
            section_added.append({"source_id": source_id, "current": right})
        elif right is None:
            section_removed.append({"source_id": source_id, "previous": left})
        elif left != right:
            summary_changes = {}
            for key in sorted(set(left["summary"]) | set(right["summary"])):
                old, new = left["summary"].get(key), right["summary"].get(key)
                if old != new:
                    summary_changes[key] = {"previous": old, "current": new}
            section_changed.append({
                "source_id": source_id,
                "status_changed": left["status"] != right["status"],
                "previous_status": left["status"],
                "current_status": right["status"],
                "summary_changes": summary_changes,
            })

    def filtered_site_summaries(items):
        groups = defaultdict(list)
        for item in items:
            groups[item["site_id"]].append(item)
        summaries = {}
        for site_id, site_findings in groups.items():
            counts = Counter(item["severity"] for item in site_findings)
            summaries[site_id] = {
                "site_id": site_id,
                "finding_count": len(site_findings),
                "critical_count": counts["critical"],
                "warning_count": counts["warning"],
                "info_count": counts["info"],
                "source_types": sorted({item["source_type"] for item in site_findings}),
            }
        return summaries

    before_sites = filtered_site_summaries(previous_findings)
    after_sites = filtered_site_summaries(current_findings)
    site_changes = []
    for site_id in sorted(set(before_sites) | set(after_sites)):
        left, right = before_sites.get(site_id), after_sites.get(site_id)
        if left == right:
            continue
        deltas = {}
        for key in ("finding_count", "critical_count", "warning_count", "info_count"):
            old = left[key] if left else 0
            new = right[key] if right else 0
            if old != new:
                deltas[key] = {"previous": old, "current": new, "delta": new - old}
        site_changes.append({
            "site_id": site_id,
            "status": "added" if left is None else "removed" if right is None else "changed",
            "count_changes": deltas,
            "source_types_changed": bool(left and right and left["source_types"] != right["source_types"]),
        })

    changed.sort(key=lambda item: (
        item["site_id"], item["source_id"], item["code"], item["router_id"] or "",
        item["resource_id"] or "",
    ))
    added.sort(key=lambda item: (item["site_id"], item["source_id"], item["code"], item["finding_id"]))
    removed.sort(key=lambda item: (item["site_id"], item["source_id"], item["code"], item["finding_id"]))

    before_summary = Counter(item["severity"] for item in previous_findings)
    after_summary = Counter(item["severity"] for item in current_findings)
    summary_delta = {
        severity: after_summary[severity] - before_summary[severity]
        for severity in ("critical", "warning", "info")
    }
    details_count = len(changed) + len(added) + len(removed)
    remaining_details = max_details
    output_changed = changed[:remaining_details] if include_details else []
    remaining_details -= len(output_changed)
    output_added = added[:remaining_details] if include_details else []
    remaining_details -= len(output_added)
    output_removed = removed[:remaining_details] if include_details else []
    return {
        "status": "compared",
        "previous_report": {
            "report_id": previous["report_id"],
            "title": previous["title"],
            "generated_at": previous["generated_at"],
            "content_hash": previous["content_hash"],
        },
        "current_report": {
            "report_id": current["report_id"],
            "title": current["title"],
            "generated_at": current["generated_at"],
            "content_hash": current["content_hash"],
        },
        "filters": {"source_allowlist": safe_source_ids, "include_details": include_details, "maximum_details": max_details},
        "summary": {
            "previous_finding_count": len(previous_findings),
            "current_finding_count": len(current_findings),
            "unchanged_count": len(unchanged),
            "changed_count": len(changed),
            "added_count": len(added),
            "removed_count": len(removed),
            "critical_delta": summary_delta["critical"],
            "warning_delta": summary_delta["warning"],
            "info_delta": summary_delta["info"],
            "section_added_count": len(section_added),
            "section_removed_count": len(section_removed),
            "section_changed_count": len(section_changed),
            "site_changed_count": len(site_changes),
            "details_count": min(details_count, max_details) if include_details else 0,
            "details_truncated": include_details and details_count > max_details,
        },
        "sections": {
            "added": section_added,
            "removed": section_removed,
            "changed": section_changed,
        },
        "site_changes": site_changes,
        "findings": {
            "changed": output_changed,
            "added": output_added,
            "removed": output_removed,
        },
        "note": (
            "Only hash-validated report bundles and allow-listed finding fields are compared. Added/removed "
            "events may reflect collection coverage or source changes; this comparison does not prove root cause."
        ),
    }


FEATURE = {
    "id": "F183",
    "slug": "router_audit_report_comparator",
    "name": "Router audit report comparator",
    "category": "Router operations",
    "description": (
        "Validate and compare versioned F182 report bundles, matching findings by source/site/router/resource "
        "identity and reporting unchanged, changed, added and removed findings plus section/site deltas."
    ),
    "parameters": {
        "previous": "previous F182 report bundle with a matching SHA-256 content hash",
        "current": "current F182 report bundle with a matching SHA-256 content hash",
        "source_allowlist": "optional list of source IDs to compare",
        "maximum_details": "maximum returned comparison details",
        "include_details": "whether to include changed/added/removed records",
    },
    "run": run,
}
