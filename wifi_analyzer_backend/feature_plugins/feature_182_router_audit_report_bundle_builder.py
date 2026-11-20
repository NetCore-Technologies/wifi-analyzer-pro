"""Build bounded, versioned and credential-free router audit report bundles."""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone

MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_SOURCES = 64
MAX_FINDINGS = 20000
MAX_OUTPUT_DETAILS = 2000
MAX_SUMMARY_FIELDS = 64
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
CODE = re.compile(r"^[a-z][a-z0-9_.-]{0,79}$")
SEVERITIES = {"critical", "warning", "info"}
SOURCE_TYPES = {
    "router_snapshot_drift_report",
    "router_fleet_health_audit",
    "router_subnet_overlap_audit",
    "router_client_roaming_audit",
    "router_route_table_audit",
    "router_vlan_segmentation_audit",
    "router_gateway_redundancy_audit",
    "router_incident_alert_policy_evaluator",
}
SOURCE_TITLES = {
    "router_snapshot_drift_report": "Router snapshot drift",
    "router_fleet_health_audit": "Router fleet health",
    "router_subnet_overlap_audit": "Subnet overlap",
    "router_client_roaming_audit": "Client roaming",
    "router_route_table_audit": "Route-table review",
    "router_vlan_segmentation_audit": "VLAN segmentation",
    "router_gateway_redundancy_audit": "Gateway redundancy",
    "router_incident_alert_policy_evaluator": "Incident alert evaluation",
}


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


def _identifier(value: object, field: str) -> str:
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


def _number(value: object, field: str) -> int | float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"{field} must be a finite number")
    return value


def _summary(value: object, field: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    result = {}
    for key, item in list(value.items())[:MAX_SUMMARY_FIELDS]:
        if not isinstance(key, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", key):
            continue
        if item is None or isinstance(item, (str, bool)):
            if isinstance(item, str) and len(item) <= 128:
                result[key] = item
        elif isinstance(item, (int, float)) and not isinstance(item, bool) and math.isfinite(item):
            result[key] = item
    return result


def _site(value: object, field: str) -> str:
    if value is None:
        return "unassigned"
    return _identifier(value, field)


def _router(value: object, field: str) -> str | None:
    if value is None:
        return None
    return _identifier(value, field)


def _source(value: object, index: int) -> dict:
    field = f"sources[{index}]"
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    source_type = value.get("source_type")
    if not isinstance(source_type, str) or source_type not in SOURCE_TYPES:
        raise ValueError(f"{field}.source_type must be one of the supported router audit types")
    source_id = _identifier(value.get("source_id"), f"{field}.source_id")
    result = value.get("result", value.get("audit"))
    if not isinstance(result, dict):
        raise ValueError(f"{field}.result must be an audit result object")
    source_status = result.get("status", "unknown")
    if not isinstance(source_status, str) or len(source_status) > 48:
        raise ValueError(f"{field}.result.status must be a string of at most 48 characters")
    summary = _summary(result.get("summary", {}), f"{field}.result.summary")
    return {
        "source_type": source_type,
        "source_id": source_id,
        "source_status": source_status,
        "summary": summary,
        "result": result,
    }


def _finding(code: str, severity: str, source: dict, site_id: str, router_id=None,
             resource_type=None, resource_id=None, details=None) -> dict:
    if not isinstance(code, str) or not CODE.fullmatch(code):
        raise ValueError("normalized report finding code is invalid")
    if severity not in SEVERITIES:
        raise ValueError("normalized report finding severity is invalid")
    return {
        "finding_id": hashlib.sha256(
            json.dumps(
                [source["source_id"], code, site_id, router_id, resource_type, resource_id, details],
                ensure_ascii=False, separators=(",", ":"), sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()[:24],
        "source_id": source["source_id"],
        "source_type": source["source_type"],
        "category": SOURCE_TITLES[source["source_type"]],
        "code": code,
        "severity": severity,
        "site_id": site_id,
        "router_id": router_id,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "details": details or {},
    }


def _collect_findings(source: dict, site_allowlist: set[str], include_details: bool) -> list[dict]:
    kind = source["source_type"]
    result = source["result"]
    findings = []

    def add(code, severity, raw, site_field="site_id", router_field="router_id",
            resource_type=None, resource_field="resource_id", details=None):
        if not isinstance(raw, dict):
            return
        site = _site(raw.get(site_field), f"{kind}.{site_field}")
        if site_allowlist and site not in site_allowlist:
            return
        router = _router(raw.get(router_field), f"{kind}.{router_field}")
        resource = _bounded_text(raw.get(resource_field), f"{kind}.{resource_field}", 128)
        safe_details = {}
        if include_details and isinstance(details, dict):
            for key, value in details.items():
                if key in {"observed", "threshold", "overlap_type", "ip_version", "vlan_id",
                           "from_ap_id", "to_ap_id", "elapsed_seconds", "status",
                           "health_score", "age_seconds", "target", "gateway",
                           "routing_table"}:
                    safe = _scalar(value, f"{kind}.details.{key}")
                    safe_details[key] = safe
        findings.append(_finding(
            code, severity, source, site, router, resource_type, resource, safe_details
        ))

    if kind == "router_fleet_health_audit":
        routers = result.get("routers", [])
        if not isinstance(routers, list):
            raise ValueError("router_fleet_health_audit.routers must be a list")
        for router in routers:
            if not isinstance(router, dict):
                continue
            items = router.get("findings", [])
            if not isinstance(items, list):
                raise ValueError("router_fleet_health_audit.router.findings must be a list")
            for item in items:
                if isinstance(item, dict):
                    add(item.get("code"), item.get("severity"), {
                        **item, "site_id": router.get("site_id"), "router_id": router.get("router_id")
                    }, resource_type=item.get("resource_type"), details=item)
    elif kind == "router_subnet_overlap_audit":
        for item in result.get("overlaps", []):
            add(item.get("code"), "warning", item, resource_type="subnet_overlap",
                resource_field=None, details={
                    "overlap_type": item.get("overlap_type"),
                    "ip_version": item.get("left", {}).get("ip_version") if isinstance(item.get("left"), dict) else None,
                })
    elif kind == "router_client_roaming_audit":
        for item in result.get("weak_signal_observations", []):
            add(item.get("code"), item.get("severity"), item, resource_type="client",
                resource_field="client_mac", details=item)
        for item in result.get("handoffs", []):
            add("client.ap_handoff", "info", item, resource_type="client",
                resource_field="client_mac", details=item)
        for item in result.get("multi_ap_windows", []):
            add("client.multi_ap_observation", "info", item, resource_type="client",
                resource_field="client_mac", details=item)
    elif kind in {"router_route_table_audit", "router_gateway_redundancy_audit"}:
        if kind == "router_route_table_audit":
            for router in result.get("routers", []):
                if not isinstance(router, dict):
                    continue
                for item in router.get("findings", []):
                    if isinstance(item, dict):
                        add(item.get("code"), item.get("severity"), {
                            **item, "site_id": router.get("site_id"), "router_id": router.get("router_id")
                        }, resource_type="route", details=item.get("route", item))
        else:
            for item in result.get("findings", []):
                if isinstance(item, dict):
                    add(item.get("code"), item.get("severity"), item,
                        resource_type="gateway", resource_field=None, details=item)
    elif kind == "router_vlan_segmentation_audit":
        for item in result.get("findings", []):
            if isinstance(item, dict):
                add(item.get("code"), item.get("severity"), item,
                    resource_type="vlan", resource_field="resource", details=item)
    elif kind == "router_incident_alert_policy_evaluator":
        for item in result.get("alerts", []):
            if isinstance(item, dict):
                add("incident.alert_active", item.get("severity"), item,
                    resource_type=item.get("resource_type"), details=item)
        for item in result.get("resolved_alerts", []):
            if isinstance(item, dict):
                add("incident.alert_resolved", "info", item,
                    resource_type=item.get("resource_type"), details=item)
    elif kind == "router_snapshot_drift_report":
        changes = result.get("changes", {})
        if isinstance(changes, dict):
            for section, diff in changes.items():
                if not isinstance(diff, dict):
                    continue
                changed_count = diff.get("changed_count", 0)
                added_count = diff.get("added_count", 0)
                removed_count = diff.get("removed_count", 0)
                for code, count in (
                    ("inventory.record_changed", changed_count),
                    ("inventory.record_added", added_count),
                    ("inventory.record_removed", removed_count),
                ):
                    if isinstance(count, int) and not isinstance(count, bool) and count > 0:
                        site = _site(result.get("site_id"), f"{kind}.site_id")
                        if site_allowlist and site not in site_allowlist:
                            continue
                        details = {"section": section, "occurrence_count": count} if include_details else {}
                        findings.append(_finding(code, "info", source, site, None, section, None, details))
        metadata = result.get("metadata_changes", {})
        if isinstance(metadata, dict):
            count = sum(len(value) for value in metadata.values() if isinstance(value, list))
            if count:
                site = "unassigned"
                if not site_allowlist or site in site_allowlist:
                    findings.append(_finding(
                        "inventory.metadata_changed", "info", source, site, None, "metadata", None,
                        {"occurrence_count": count} if include_details else {},
                    ))
    return findings


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    try:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError("report input must contain JSON-compatible finite values") from error
    if len(encoded.encode("utf-8")) > MAX_INPUT_BYTES:
        raise ValueError(f"report input exceeds the {MAX_INPUT_BYTES}-byte input limit")

    report_id = _identifier(payload.get("report_id"), "report_id")
    title = _bounded_text(payload.get("title", "Router audit report"), "title", 120)
    if not title:
        raise ValueError("title must not be empty")
    generated_at = _timestamp(payload.get("generated_at"), "generated_at")
    period_start = payload.get("period_start")
    period_end = payload.get("period_end")
    if period_start is not None:
        period_start = _timestamp(period_start, "period_start")
    if period_end is not None:
        period_end = _timestamp(period_end, "period_end")
    if period_start and period_end and datetime.fromisoformat(period_start) > datetime.fromisoformat(period_end):
        raise ValueError("period_start must not be after period_end")

    raw_sources = payload.get("sources")
    if not isinstance(raw_sources, list) or not 1 <= len(raw_sources) <= MAX_SOURCES:
        raise ValueError(f"sources must contain from 1 to {MAX_SOURCES} audit results")
    sources = [_source(value, index) for index, value in enumerate(raw_sources)]
    if len({item["source_id"] for item in sources}) != len(sources):
        raise ValueError("source_id values must be unique")
    site_allowlist = set(_list_of_sites(payload.get("site_allowlist")))
    include_details = payload.get("include_details", True)
    if not isinstance(include_details, bool):
        raise ValueError("include_details must be a boolean")
    max_findings = payload.get("maximum_findings", 500)
    if isinstance(max_findings, bool) or not isinstance(max_findings, int) or not 1 <= max_findings <= MAX_OUTPUT_DETAILS:
        raise ValueError(f"maximum_findings must be an integer from 1 to {MAX_OUTPUT_DETAILS}")

    sections = []
    all_findings = []
    for source in sources:
        summary = source["summary"]
        safe_findings = _collect_findings(source, site_allowlist, include_details)
        all_findings.extend(safe_findings)
        sections.append({
            "source_id": source["source_id"],
            "source_type": source["source_type"],
            "title": SOURCE_TITLES[source["source_type"]],
            "status": source["source_status"],
            "summary": summary,
            "finding_count": len(safe_findings),
            "findings_truncated": False,
        })
    if len(all_findings) > MAX_FINDINGS:
        raise ValueError(f"combined report finding count exceeds {MAX_FINDINGS}")
    all_findings.sort(key=lambda item: (
        {"critical": 0, "warning": 1, "info": 2}[item["severity"]],
        item["site_id"], item["source_type"], item["code"], item["finding_id"],
    ))
    for section in sections:
        source_findings = [item for item in all_findings if item["source_id"] == section["source_id"]]
        section["findings_truncated"] = len(source_findings) > max_findings
        section["finding_count"] = len(source_findings)

    severity_counts = Counter(item["severity"] for item in all_findings)
    site_groups = defaultdict(list)
    for item in all_findings:
        site_groups[item["site_id"]].append(item)
    sites = []
    for site_id, items in sorted(site_groups.items()):
        counts = Counter(item["severity"] for item in items)
        sites.append({
            "site_id": site_id,
            "finding_count": len(items),
            "critical_count": counts["critical"],
            "warning_count": counts["warning"],
            "info_count": counts["info"],
            "source_types": sorted({item["source_type"] for item in items}),
        })

    body = {
        "schema_version": "1.0",
        "report_id": report_id,
        "title": title,
        "generated_at": generated_at,
        "period": {"start": period_start, "end": period_end},
        "filters": {
            "site_allowlist": sorted(site_allowlist),
            "include_details": include_details,
            "maximum_findings": max_findings,
        },
        "summary": {
            "source_count": len(sources),
            "site_count": len(sites),
            "finding_count": len(all_findings),
            "critical_count": severity_counts["critical"],
            "warning_count": severity_counts["warning"],
            "info_count": severity_counts["info"],
            "detail_count": min(len(all_findings), max_findings),
            "details_truncated": len(all_findings) > max_findings,
        },
        "sites": sites,
        "sections": sections,
        "findings": all_findings[:max_findings] if include_details else [],
        "note": (
            "This bundle contains allow-listed summaries and normalized finding evidence only. Raw snapshots, "
            "credentials, unknown fields, and untrusted source messages are not copied. Findings retain the "
            "limitations of their source audits and do not prove root cause or live reachability."
        ),
    }
    canonical = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    content_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return {**body, "content_hash": content_hash}


def _list_of_sites(value: object) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 128:
        raise ValueError("site_allowlist must be a list containing no more than 128 site IDs")
    result = []
    for item in value:
        result.append(_identifier(item, "site_allowlist entry"))
    if len(result) != len(set(result)):
        raise ValueError("site_allowlist entries must be unique")
    return result


FEATURE = {
    "id": "F182",
    "slug": "router_audit_report_bundle_builder",
    "name": "Router audit report bundle builder",
    "category": "Router operations",
    "description": (
        "Combine normalized router audit outputs into a versioned, site-filterable, credential-free JSON report "
        "with severity rollups, compact findings and a deterministic SHA-256 content hash."
    ),
    "parameters": {
        "report_id": "stable report identifier",
        "title": "human-readable report title",
        "generated_at": "timezone-aware report timestamp",
        "sources": "1 to 64 F174-F181 audit result records",
        "site_allowlist": "optional list of site IDs to include",
        "include_details": "whether to include compact allow-listed finding details",
        "maximum_findings": "maximum returned finding details from 1 to 2000",
    },
    "run": run,
}
