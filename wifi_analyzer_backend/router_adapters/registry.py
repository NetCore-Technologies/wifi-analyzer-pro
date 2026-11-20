"""Versioned, read-only router adapter manifests and capability negotiation."""
from __future__ import annotations

import re


_VERSION_PATTERN = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_CAPABILITY_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,79}$")
_PERMISSION_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,39}$")

_ADAPTERS = {
    "openwrt": {
        "adapter_id": "openwrt",
        "display_name": "OpenWrt read-only agent",
        "platform_family": "OpenWrt",
        "adapter_version": "0.1.0",
        "minimum_agent_version": "1.0.0",
        "capability_schema_version": "1.0",
        "transport": "local_agent",
        "read_only": True,
        "supported_permissions": ["read"],
        "capabilities": [
            "system.board",
            "system.health",
            "network.interfaces",
            "network.routes",
            "wireless.radios",
            "wireless.scan_results",
            "wireless.associations",
            "wireless.statistics",
            "inventory.snapshot",
        ],
        "notes": (
            "Capability negotiation only. It does not connect to a router, execute shell commands, "
            "change configuration, or collect credentials."
        ),
    },
    "unifi": {
        "adapter_id": "unifi",
        "display_name": "UniFi Network controller export",
        "platform_family": "Ubiquiti UniFi",
        "adapter_version": "0.1.0",
        "minimum_agent_version": "1.0.0",
        "capability_schema_version": "1.0",
        "transport": "controller_export",
        "read_only": True,
        "supported_permissions": ["read"],
        "capabilities": [
            "controller.devices",
            "controller.networks",
            "wireless.radios",
            "wireless.associations",
            "inventory.snapshot",
        ],
        "notes": (
            "Offline import of caller-supplied UniFi Network export data. It does not open a controller "
            "session, request credentials, or change network configuration."
        ),
    },
    "mikrotik": {
        "adapter_id": "mikrotik",
        "display_name": "MikroTik RouterOS export",
        "platform_family": "MikroTik RouterOS",
        "adapter_version": "0.1.0",
        "minimum_agent_version": "1.0.0",
        "capability_schema_version": "1.0",
        "transport": "controller_export",
        "read_only": True,
        "supported_permissions": ["read"],
        "capabilities": [
            "system.board",
            "system.health",
            "network.interfaces",
            "network.addresses",
            "network.vlans",
            "network.dhcp_leases",
            "wireless.radios",
            "wireless.associations",
            "inventory.snapshot",
        ],
        "notes": (
            "Offline import of caller-supplied RouterOS export data. This manifest does not establish "
            "a RouterOS session, execute scripts, request credentials, or permit configuration writes."
        ),
    },
}


def list_manifests() -> list[dict]:
    """Return defensive copies of installed adapter manifests."""
    return [
        {**manifest, "capabilities": list(manifest["capabilities"]),
         "supported_permissions": list(manifest["supported_permissions"])}
        for _, manifest in sorted(_ADAPTERS.items())
    ]


def _version_tuple(value: object, field: str) -> tuple[int, int, int]:
    if not isinstance(value, str) or not _VERSION_PATTERN.fullmatch(value):
        raise ValueError(f"{field} must use numeric major.minor.patch version syntax")
    return tuple(int(part) for part in value.split("."))


def _name_list(value: object, field: str, pattern: re.Pattern, maximum: int = 64) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError(f"{field} must be a list containing no more than {maximum} values")
    result = []
    seen = set()
    for item in value:
        if not isinstance(item, str) or not pattern.fullmatch(item):
            raise ValueError(f"Each {field} entry must be a valid lowercase identifier")
        if item in seen:
            raise ValueError(f"{field} entries must be unique")
        seen.add(item)
        result.append(item)
    return result


def negotiate(payload: dict) -> dict:
    """Intersect agent-advertised and operator-requested capabilities with a local manifest."""
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    adapter_id = payload.get("adapter_id")
    if not isinstance(adapter_id, str) or not adapter_id.strip() or len(adapter_id) > 64:
        raise ValueError("adapter_id must contain 1 to 64 characters")
    adapter_id = adapter_id.strip().lower()
    agent_version = payload.get("agent_version")
    agent_tuple = _version_tuple(agent_version, "agent_version")
    advertised = _name_list(
        payload.get("advertised_capabilities", []),
        "advertised_capabilities",
        _CAPABILITY_PATTERN,
    )
    requested = _name_list(
        payload.get("requested_capabilities", []),
        "requested_capabilities",
        _CAPABILITY_PATTERN,
    )
    permissions = _name_list(
        payload.get("requested_permissions", ["read"]),
        "requested_permissions",
        _PERMISSION_PATTERN,
        maximum=16,
    )

    manifest = _ADAPTERS.get(adapter_id)
    if manifest is None:
        return {
            "status": "unsupported_adapter",
            "compatible": False,
            "adapter_id": adapter_id,
            "agent_version": agent_version,
            "negotiated_capabilities": [],
            "rejected_capabilities": [
                {"capability": item, "reason": "adapter_not_installed"}
                for item in requested
            ],
            "negotiated_permissions": [],
            "rejected_permissions": [
                {"permission": item, "reason": "adapter_not_installed"}
                for item in permissions
            ],
        }

    minimum = _version_tuple(manifest["minimum_agent_version"], "manifest.minimum_agent_version")
    version_compatible = agent_tuple >= minimum
    supported = set(manifest["capabilities"])
    advertised_set = set(advertised)
    negotiated = sorted(
        set(requested) & advertised_set & supported
    ) if version_compatible else []

    rejected_capabilities = []
    for capability in sorted(set(requested)):
        if not version_compatible:
            reason = "agent_version_below_minimum"
        elif capability not in supported:
            reason = "not_supported_by_adapter"
        elif capability not in advertised_set:
            reason = "not_advertised_by_agent"
        else:
            continue
        rejected_capabilities.append({"capability": capability, "reason": reason})

    supported_permissions = set(manifest["supported_permissions"])
    negotiated_permissions = sorted(set(permissions) & supported_permissions) if version_compatible else []
    rejected_permissions = []
    for permission in sorted(set(permissions)):
        if not version_compatible:
            reason = "agent_version_below_minimum"
        elif permission not in supported_permissions:
            reason = "adapter_is_read_only"
        else:
            continue
        rejected_permissions.append({"permission": permission, "reason": reason})

    if not version_compatible:
        status = "version_incompatible"
    elif rejected_capabilities or rejected_permissions:
        status = "partial"
    else:
        status = "compatible"

    return {
        "status": status,
        "compatible": status == "compatible",
        "adapter": {
            "adapter_id": manifest["adapter_id"],
            "display_name": manifest["display_name"],
            "adapter_version": manifest["adapter_version"],
            "minimum_agent_version": manifest["minimum_agent_version"],
            "capability_schema_version": manifest["capability_schema_version"],
            "read_only": manifest["read_only"],
        },
        "agent_version": agent_version,
        "negotiated_capabilities": negotiated,
        "rejected_capabilities": rejected_capabilities,
        "negotiated_permissions": negotiated_permissions,
        "rejected_permissions": rejected_permissions,
        "advertised_but_unsupported": sorted(advertised_set - supported),
        "note": (
            "Negotiation is a local contract check only. It does not authenticate a remote agent or establish "
            "a network session; all currently registered adapters expose read-only capabilities."
        ),
    }
