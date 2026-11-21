"""Shared bounded validation and evidence accounting for F195-F200."""
from __future__ import annotations
import re
from collections import Counter

IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
SEVERITIES = ("critical", "high", "medium", "low", "info")
WEIGHTS = {"critical": 40, "high": 20, "medium": 8, "low": 2, "info": 0}

def records(payload, field, maximum):
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    values = payload.get(field)
    if not isinstance(values, list) or len(values) > maximum:
        raise ValueError(f"{field} must be a list containing no more than {maximum} records")
    if any(not isinstance(value, dict) for value in values):
        raise ValueError(f"{field} entries must be objects")
    return values

def identifier(value, field):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value.strip()):
        raise ValueError(f"{field} must be a 1 to 64 character identifier")
    return value.strip()

def boolean(value, field):
    if value is None:
        return None
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be a boolean when supplied")
    return value

def enum(value, field, allowed, default="unknown"):
    if value is None:
        return default
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    cleaned = value.strip().lower()
    if cleaned not in allowed:
        raise ValueError(f"{field} must be one of {sorted(allowed)}")
    return cleaned

def bounded_int(value, field, minimum, maximum, default=None):
    if value is None and default is not None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{field} must be an integer from {minimum} to {maximum}")
    return value

def finding(findings, record_id, code, severity, state, description, recommendation):
    findings.append({
        "record_id": record_id, "code": code, "severity": severity,
        "evidence_state": state, "description": description,
        "recommendation": recommendation,
    })

def summarize(feature, category, record_count, findings, extra=None):
    counts = Counter(item["severity"] for item in findings)
    violations = sum(item["evidence_state"] == "violation" for item in findings)
    gaps = sum(item["evidence_state"] == "missing" for item in findings)
    affected = {item["record_id"] for item in findings if item["evidence_state"] == "missing"}
    risk = None if gaps else min(100, sum(WEIGHTS[item["severity"]] for item in findings))
    result = {
        "feature": feature,
        "status": "empty" if record_count == 0 else ("partial" if gaps else "audited"),
        "summary": {
            "record_count": record_count,
            "assessed_record_count": max(0, record_count - len(affected)),
            "finding_count": len(findings),
            "confirmed_violation_count": violations,
            "evidence_gap_count": gaps,
            "findings_by_severity": {key: counts.get(key, 0) for key in SEVERITIES},
            "observed_risk_score": risk,
        },
        "findings": sorted(findings, key=lambda item: (
            SEVERITIES.index(item["severity"]), item["record_id"], item["code"]
        )),
        "note": "This is an offline assessment of supplied evidence, not a live configuration check or compliance certification. Unknown evidence is never treated as a pass.",
    }
    if extra:
        result.update(extra)
    return result
