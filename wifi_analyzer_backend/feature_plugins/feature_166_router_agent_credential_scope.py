"""Validate a least-privilege read-only scope before issuing an agent credential."""
from __future__ import annotations

import re

from ..router_adapters.registry import negotiate

_AGENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    agent_id = payload.get("agent_id")
    if not isinstance(agent_id, str) or not _AGENT_ID.fullmatch(agent_id):
        raise ValueError("agent_id must be a 1 to 64 character identifier")
    permissions = payload.get("requested_permissions", ["read"])
    if permissions != ["read"]:
        raise ValueError("Router agents can only be enrolled with the read permission")
    requested = payload.get("requested_capabilities")
    advertised = payload.get("advertised_capabilities", requested)
    if not isinstance(requested, list) or not requested:
        raise ValueError("requested_capabilities must contain at least one capability")
    if not isinstance(advertised, list):
        raise ValueError("advertised_capabilities must be a list")
    result = negotiate({
        "adapter_id": payload.get("adapter_id"),
        "agent_version": payload.get("agent_version"),
        "advertised_capabilities": advertised,
        "requested_capabilities": requested,
        "requested_permissions": permissions,
    })
    if not result.get("compatible"):
        rejected = result.get("rejected_capabilities", [])
        names = [item.get("capability", "unknown") for item in rejected]
        raise ValueError(
            "Requested agent scope is not fully supported: "
            + (", ".join(names) or result.get("status", "incompatible"))
        )
    return {
        "agent_id": agent_id,
        "adapter_id": result["adapter"]["adapter_id"],
        "agent_version": result["agent_version"],
        "allowed_capabilities": result["negotiated_capabilities"],
        "advertised_capabilities": sorted(advertised),
        "requested_capabilities": sorted(requested),
        "negotiated_capabilities": result["negotiated_capabilities"],
        "rejected_capabilities": result["rejected_capabilities"],
        "requested_permissions": permissions,
        "negotiated_permissions": result["negotiated_permissions"],
        "rejected_permissions": result["rejected_permissions"],
        "permission": "read",
        "adapter_version": result["adapter"]["adapter_version"],
        "capability_schema_version": result["adapter"]["capability_schema_version"],
    }


FEATURE = {
    "id": "F166",
    "slug": "router_agent_credential_scope",
    "name": "Router agent credential scope",
    "category": "Router integrations",
    "description": "Validate an OpenWrt agent identity and negotiate a least-privilege read-only capability scope before creating or rotating an agent credential.",
    "parameters": {
        "agent_id": "string",
        "adapter_id": "string",
        "agent_version": "major.minor.patch",
        "advertised_capabilities": "string[]",
        "requested_capabilities": "string[]",
        "requested_permissions": "read[]",
    },
    "run": run,
}
