"""F200: deterministic consolidated enterprise network security evidence report."""
from __future__ import annotations
import hashlib
import json
from .enterprise_security_common import records, identifier, SEVERITIES

EXPECTED = {f"F{number}" for number in range(194, 200)}
SUMMARY_FIELDS = {
    "F194": ("profile_count", "violation_count", "evidence_gap_count"),
    "F195": ("record_count", "confirmed_violation_count", "evidence_gap_count"),
    "F196": ("record_count", "confirmed_violation_count", "evidence_gap_count"),
    "F197": ("record_count", "confirmed_violation_count", "evidence_gap_count"),
    "F198": ("record_count", "confirmed_violation_count", "evidence_gap_count"),
    "F199": ("record_count", "confirmed_violation_count", "evidence_gap_count"),
}

def run(payload: dict) -> dict:
    reports = records(payload, "reports", 6)
    if not reports:
        raise ValueError("reports must contain at least one F194-F199 audit result")
    report_id = identifier(payload.get("report_id", "enterprise-security-review"), "report_id")
    seen = set()
    normalized = []
    findings = []
    severity_totals = {severity: 0 for severity in SEVERITIES}
    record_total = violation_total = gap_total = 0
    for index, report in enumerate(reports):
        feature = report.get("feature")
        if not isinstance(feature, str) or feature not in EXPECTED:
            raise ValueError(f"reports[{index}].feature must be an F194-F199 result")
        if feature in seen:
            raise ValueError(f"duplicate report for {feature}")
        seen.add(feature)
        summary = report.get("summary")
        if not isinstance(summary, dict):
            raise ValueError(f"reports[{index}].summary must be an object")
        fields = SUMMARY_FIELDS[feature]
        values = {}
        for field in fields:
            value = summary.get(field)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"reports[{index}].summary.{field} must be a non-negative integer")
            values[field] = value
        record_count = values[fields[0]]
        violations = values[fields[1]]
        gaps = values[fields[2]]
        if violations + gaps > 100000:
            raise ValueError(f"reports[{index}] finding counts exceed the supported limit")
        record_total += record_count
        violation_total += violations
        gap_total += gaps
        severity_counts = summary.get("findings_by_severity", {})
        if feature != "F194" and not isinstance(severity_counts, dict):
            raise ValueError(f"reports[{index}].summary.findings_by_severity must be an object")
        clean_severity = {}
        for severity in SEVERITIES:
            count = severity_counts.get(severity, 0) if isinstance(severity_counts, dict) else 0
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise ValueError(f"reports[{index}].summary.findings_by_severity.{severity} must be a non-negative integer")
            clean_severity[severity] = count
            severity_totals[severity] += count
        raw_findings = report.get("findings", [])
        if not isinstance(raw_findings, list) or len(raw_findings) > 20000:
            raise ValueError(f"reports[{index}].findings must be a list of at most 20000 records")
        safe_findings = []
        for finding_index, item in enumerate(raw_findings):
            if not isinstance(item, dict):
                raise ValueError(f"reports[{index}].findings[{finding_index}] must be an object")
            code = item.get("code")
            severity = item.get("severity")
            evidence_state = item.get("evidence_state")
            if not isinstance(code, str) or not code.isascii() or not code.replace("_", "").isalnum() or len(code) > 80:
                raise ValueError(f"reports[{index}].findings[{finding_index}].code is invalid")
            if severity not in SEVERITIES or evidence_state not in {"violation", "missing", "observed"}:
                raise ValueError(f"reports[{index}].findings[{finding_index}] has invalid severity or evidence state")
            safe = {"feature": feature, "code": code, "severity": severity, "evidence_state": evidence_state}
            safe_findings.append(safe)
            findings.append(safe)
        normalized.append({
            "feature": feature, "status": str(report.get("status", "unknown"))[:24],
            "record_count": record_count, "violation_count": violations,
            "evidence_gap_count": gaps, "findings_by_severity": clean_severity,
            "finding_record_count": len(safe_findings),
        })
    normalized.sort(key=lambda item: item["feature"])
    findings.sort(key=lambda item: (SEVERITIES.index(item["severity"]), item["feature"], item["code"], item["evidence_state"]))
    report = {
        "schema_version": "1.0",
        "report_id": report_id,
        "included_features": [item["feature"] for item in normalized],
        "summary": {
            "audit_count": len(normalized), "record_count": record_total,
            "confirmed_violation_count": violation_total, "evidence_gap_count": gap_total,
            "findings_by_severity": severity_totals,
            "assessment_state": "evidence_incomplete" if gap_total else ("findings_present" if violation_total else "no_reported_violations"),
        },
        "audits": normalized,
        "findings": findings[:5000],
        "truncated_findings": max(0, len(findings) - 5000),
        "note": "This report aggregates supplied F194-F199 evidence only. It does not independently verify source data, replace device validation, or certify compliance. Raw descriptions, hostnames, addresses, SSIDs, secrets and source payloads are intentionally excluded.",
    }
    canonical = json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)
    report["sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return report

FEATURE = {
    "id": "F200", "slug": "enterprise_network_security_evidence_report",
    "name": "Enterprise network security evidence report", "category": "Security",
    "description": "Combine F194-F199 WLAN, switch, firewall, DHCP/DNS, VPN and asset lifecycle audits into a deterministic, privacy-minimised report with evidence gaps, severity rollups and a SHA-256 integrity digest.",
    "parameters": {"report_id": "optional stable 1-64 character report identifier", "reports": "one to six F194-F199 audit result objects"},
    "run": run,
}
