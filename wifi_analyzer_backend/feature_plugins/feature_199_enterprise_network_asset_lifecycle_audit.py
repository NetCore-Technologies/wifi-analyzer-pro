"""F199: bounded asset support, patch and lifecycle-risk assessment."""
from __future__ import annotations
from datetime import datetime, timezone
from .enterprise_security_common import records, identifier, boolean, enum, bounded_int, finding, summarize

MAX_ASSETS = 2048
SUPPORT = {"supported", "end-of-support", "end-of-life", "unknown"}
CRITICALITY = {"critical", "high", "medium", "low", "unknown"}

def _timestamp(value, field):
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
    assets = records(payload, "assets", MAX_ASSETS)
    as_of = _timestamp(payload.get("as_of"), "as_of")
    findings = []
    for index, asset in enumerate(assets):
        aid = identifier(asset.get("asset_id"), f"assets[{index}].asset_id")
        identifier(asset.get("site_id", "unassigned"), f"assets[{index}].site_id")
        criticality = enum(asset.get("criticality"), f"assets[{index}].criticality", CRITICALITY)
        support = enum(asset.get("support_state"), f"assets[{index}].support_state", SUPPORT)
        exposed = boolean(asset.get("internet_exposed"), f"assets[{index}].internet_exposed")
        if support == "end-of-life":
            finding(findings, aid, "ASSET_END_OF_LIFE", "critical", "violation",
                    "The asset is recorded as end-of-life and no longer supported by its vendor.",
                    "Replace the asset or isolate it under a formally approved compensating-control plan.")
        elif support == "end-of-support":
            severity = "critical" if criticality in {"critical", "high"} or exposed is True else "high"
            finding(findings, aid, "ASSET_END_OF_SUPPORT", severity, "violation",
                    "The asset is recorded as end-of-support.",
                    "Upgrade or replace the asset; restrict management and network reachability until retirement.")
        elif support == "unknown":
            finding(findings, aid, "ASSET_SUPPORT_STATE_UNKNOWN", "medium", "missing",
                    "Vendor support lifecycle state was not supplied.",
                    "Verify vendor support status and record the published end-of-support date.")
        patch_date = asset.get("last_security_update")
        if patch_date is None:
            finding(findings, aid, "ASSET_PATCH_CURRENCY_UNKNOWN", "medium", "missing",
                    "Last security update date was not supplied.",
                    "Import the last successful security update date from the asset management source.")
        else:
            patched = _timestamp(patch_date, f"assets[{index}].last_security_update")
            age_days = (as_of - patched).total_seconds() / 86400
            if age_days < -1:
                finding(findings, aid, "ASSET_PATCH_DATE_IN_FUTURE", "medium", "violation",
                        "The supplied security update date is more than one day in the future.",
                        "Correct time synchronisation and reconcile the patch inventory source.")
            elif age_days > 180:
                severity = "critical" if criticality == "critical" else ("high" if criticality == "high" else "medium")
                finding(findings, aid, "ASSET_PATCH_STALE", severity, "violation",
                        "The asset's last recorded security update is more than 180 days old.",
                        "Apply current security updates or document a time-bound exception and compensating controls.")
            elif age_days > 90:
                finding(findings, aid, "ASSET_PATCH_AGING", "low", "violation",
                        "The asset's last recorded security update is more than 90 days old.",
                        "Review the patch cadence and schedule the next approved security update.")
        if exposed is None:
            finding(findings, aid, "ASSET_EXPOSURE_UNKNOWN", "low", "missing",
                    "Internet exposure state was not supplied.",
                    "Verify the asset's reachable interfaces and external exposure through approved inventory.")
        elif exposed and support in {"end-of-life", "end-of-support"}:
            finding(findings, aid, "UNSUPPORTED_ASSET_INTERNET_EXPOSED", "critical", "violation",
                    "An unsupported asset is recorded as internet exposed.",
                    "Immediately remove public reachability or replace the unsupported asset.")
        for key, severity in (("critical_vulnerability_count", "critical"), ("high_vulnerability_count", "high")):
            observed_count = asset.get(key)
            if observed_count is None:
                finding(findings, aid, f"ASSET_{severity.upper()}_VULNERABILITY_COUNT_UNKNOWN", "medium", "missing",
                        f"The inventory did not supply a {severity} severity vulnerability count.",
                        "Import a recent, scope-defined vulnerability assessment; do not assume an omitted count is zero.")
                continue
            count = bounded_int(observed_count, f"assets[{index}].{key}", 0, 100000)
            if count:
                finding(findings, aid, f"ASSET_{severity.upper()}_VULNERABILITIES", severity, "violation",
                        f"The inventory reports {count} {severity} severity vulnerabilities.",
                        "Prioritise remediation using vendor advisories, exploitability, asset exposure and compensating controls.")
    return summarize("F199", "Security", len(assets), findings, {"as_of": as_of.isoformat().replace("+00:00", "Z")})

FEATURE = {
    "id": "F199", "slug": "enterprise_network_asset_lifecycle_audit",
    "name": "Enterprise network asset lifecycle audit", "category": "Security",
    "description": "Assess supplied network asset inventory for vendor support lifecycle, stale security updates, confirmed exposure and reported high/critical vulnerability counts. Never invents CVEs or queries outside vulnerability feeds.",
    "parameters": {"as_of": "timezone-aware ISO-8601 assessment timestamp", "assets": "up to 2048 asset records with support state, criticality, patch and exposure evidence"},
    "run": run,
}
