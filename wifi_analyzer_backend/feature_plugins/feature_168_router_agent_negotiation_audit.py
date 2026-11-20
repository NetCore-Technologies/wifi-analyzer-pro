"""Validate and package a bounded adapter capability-negotiation audit record."""
from __future__ import annotations

import re


_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.-]{0,79}$")
_VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


def _strings(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or len(value) > 64:
        raise ValueError(f"{field} must be a bounded list")
    if any(not isinstance(item, str) or not _IDENTIFIER.fullmatch(item) for item in value):
        raise ValueError(f"{field} contains an invalid identifier")
    if len(value) != len(set(value)):
        raise ValueError(f"{field} must contain unique values")
    return sorted(value)


def _rejections(value: object, field: str, identity_key: str) -> list[dict]:
    if not isinstance(value, list) or len(value) > 64:
        raise ValueError(f"{field} must be a bounded list")
    result = []
    seen = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {identity_key, "reason"}:
            raise ValueError(f"{field} contains an invalid rejection")
        identity = item[identity_key]
        reason = item["reason"]
        if not isinstance(identity, str) or not _IDENTIFIER.fullmatch(identity):
            raise ValueError(f"{field} contains an invalid identifier")
        if not isinstance(reason, str) or not _IDENTIFIER.fullmatch(reason):
            raise ValueError(f"{field} contains an invalid reason")
        if identity in seen:
            raise ValueError(f"{field} contains duplicate identifiers")
        seen.add(identity)
        result.append({identity_key: identity, "reason": reason})
    return sorted(result, key=lambda item: item[identity_key])


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    agent_id = payload.get("agent_id")
    if not isinstance(agent_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}", agent_id):
        raise ValueError("agent_id must be a 1 to 64 character identifier")
    adapter_id = payload.get("adapter_id")
    if not isinstance(adapter_id, str) or not _IDENTIFIER.fullmatch(adapter_id):
        raise ValueError("adapter_id is invalid")
    agent_version = payload.get("agent_version")
    adapter_version = payload.get("adapter_version")
    schema_version = payload.get("capability_schema_version")
    for field, value in (("agent_version", agent_version), ("adapter_version", adapter_version)):
        if not isinstance(value, str) or not _VERSION.fullmatch(value):
            raise ValueError(f"{field} must use numeric major.minor.patch version syntax")
    if not isinstance(schema_version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+", schema_version):
        raise ValueError("capability_schema_version must use major.minor syntax")
    if payload.get("permission") != "read":
        raise ValueError("Router agent negotiation must remain read-only")

    advertised = _strings(payload.get("advertised_capabilities"), "advertised_capabilities")
    requested = _strings(payload.get("requested_capabilities"), "requested_capabilities")
    negotiated = _strings(payload.get("negotiated_capabilities"), "negotiated_capabilities")
    rejected = _rejections(payload.get("rejected_capabilities"), "rejected_capabilities", "capability")
    requested_permissions = _strings(payload.get("requested_permissions"), "requested_permissions")
    negotiated_permissions = _strings(payload.get("negotiated_permissions"), "negotiated_permissions")
    rejected_permissions = _rejections(payload.get("rejected_permissions"), "rejected_permissions", "permission")
    if requested_permissions != ["read"] or negotiated_permissions != ["read"] or rejected_permissions:
        raise ValueError("Only the read permission may be requested and negotiated")
    if not set(negotiated).issubset(set(requested) & set(advertised)):
        raise ValueError("Negotiated capabilities must have been both requested and advertised")
    if set(negotiated) & {item["capability"] for item in rejected}:
        raise ValueError("A capability cannot be both negotiated and rejected")
    return {
        "agent_id": agent_id,
        "adapter_id": adapter_id,
        "agent_version": agent_version,
        "adapter_version": adapter_version,
        "capability_schema_version": schema_version,
        "advertised_capabilities": advertised,
        "requested_capabilities": requested,
        "negotiated_capabilities": negotiated,
        "rejected_capabilities": rejected,
        "requested_permissions": requested_permissions,
        "negotiated_permissions": negotiated_permissions,
        "rejected_permissions": rejected_permissions,
        "permission": "read",
    }


FEATURE = {
    "id": "F168",
    "slug": "router_agent_negotiation_audit",
    "name": "Router agent negotiation audit",
    "category": "Router integrations",
    "description": "Validate a versioned least-privilege adapter negotiation record for bounded, append-only persistence alongside agent enrolment.",
    "parameters": {
        "agent_id": "string",
        "adapter_id": "string",
        "agent_version": "major.minor.patch",
        "adapter_version": "major.minor.patch",
        "capability_schema_version": "major.minor",
        "advertised_capabilities": "string[]",
        "requested_capabilities": "string[]",
        "negotiated_capabilities": "string[]",
        "rejected_capabilities": "object[]",
        "requested_permissions": "read[]",
        "negotiated_permissions": "read[]",
        "rejected_permissions": "object[]",
    },
    "run": run,
}
