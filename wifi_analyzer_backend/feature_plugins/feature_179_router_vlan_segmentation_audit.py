"""Audit VLAN segmentation consistency across normalized UniFi and MikroTik snapshots."""
from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone

MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_ROUTERS = 64
MAX_NETWORKS = 1024
MAX_VLANS = 1024
MAX_TOTAL_SEGMENTS = 4096
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}


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


def _record_list(snapshot: dict, field: str, adapter: str, maximum: int) -> list[dict]:
    values = snapshot.get(field, [])
    if not isinstance(values, list) or len(values) > maximum:
        raise ValueError(f"{adapter}.{field} must be a list containing no more than {maximum} records")
    if any(not isinstance(item, dict) for item in values):
        raise ValueError(f"{adapter}.{field} entries must be objects")
    return values


def _snapshot_entry(value: object, index: int) -> dict:
    field = f"snapshots[{index}]"
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    snapshot = value.get("snapshot", value)
    if not isinstance(snapshot, dict):
        raise ValueError(f"{field}.snapshot must be an object")
    adapter = snapshot.get("adapter_id", value.get("adapter_id"))
    if not isinstance(adapter, str) or adapter not in {"unifi", "mikrotik"}:
        raise ValueError(f"{field} must contain a normalized UniFi or MikroTik snapshot")
    router_id = (
        value.get("router_id") or value.get("agent_id") or value.get("id")
        or snapshot.get("router_id") or snapshot.get("agent_id")
    )
    if router_id is None and adapter == "unifi":
        controller = snapshot.get("controller", {})
        if isinstance(controller, dict):
            router_id = controller.get("hostname")
    if router_id is None and adapter == "mikrotik":
        router = snapshot.get("router", {})
        if isinstance(router, dict):
            router_id = router.get("serial_number")
    return {
        "router_id": _identifier(router_id, f"{field}.router_id"),
        "site_id": _identifier(value.get("site_id", "unassigned"), f"{field}.site_id"),
        "adapter_id": adapter,
        "captured_at": _timestamp(value.get("captured_at", snapshot.get("captured_at")), f"{field}.captured_at"),
        "snapshot": snapshot,
    }


def _vlan_id(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 4094:
        raise ValueError(f"{field} must be an integer from 1 to 4094")
    return value


def _name(value: object, field: str, required: bool = False) -> str | None:
    if value is None:
        if required:
            raise ValueError(f"{field} is required")
        return None
    if not isinstance(value, str) or len(value.strip()) > 128:
        raise ValueError(f"{field} must be a string of at most 128 characters")
    result = value.strip()
    if required and not result:
        raise ValueError(f"{field} is required")
    return result or None


def _subnet(value: object, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a valid CIDR network")
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError as error:
        raise ValueError(f"{field} must be a valid CIDR network") from error


def _segments(entry: dict) -> tuple[list[dict], list[dict]]:
    snapshot = entry["snapshot"]
    adapter = entry["adapter_id"]
    segments = []
    preliminary_findings = []
    if adapter == "unifi":
        networks = _record_list(snapshot, "networks", adapter, MAX_NETWORKS)
        for index, network in enumerate(networks):
            field = f"unifi.networks[{index}]"
            name = _name(network.get("name"), f"{field}.name")
            vlan_enabled = network.get("vlan_enabled")
            if vlan_enabled is not None and not isinstance(vlan_enabled, bool):
                raise ValueError(f"{field}.vlan_enabled must be a boolean")
            raw_vlan = network.get("vlan_id")
            if vlan_enabled is False:
                if raw_vlan is not None:
                    preliminary_findings.append({
                        "severity": "warning",
                        "code": "vlan.disabled_with_id",
                        "site_id": entry["site_id"],
                        "router_id": entry["router_id"],
                        "resource": name,
                        "message": "The normalized network marks VLAN tagging disabled but still contains a VLAN ID.",
                    })
                continue
            if raw_vlan is None:
                if vlan_enabled is True:
                    preliminary_findings.append({
                        "severity": "warning",
                        "code": "vlan.enabled_without_id",
                        "site_id": entry["site_id"],
                        "router_id": entry["router_id"],
                        "resource": name,
                        "message": "VLAN tagging is enabled but no VLAN ID is available in this snapshot.",
                    })
                continue
            vlan_id = _vlan_id(raw_vlan, f"{field}.vlan_id")
            segments.append({
                "site_id": entry["site_id"],
                "router_id": entry["router_id"],
                "adapter_id": adapter,
                "vlan_id": vlan_id,
                "name": name,
                "parent_interface": None,
                "subnet": _subnet(network.get("ip_subnet"), f"{field}.ip_subnet"),
                "operational": network.get("enabled") if isinstance(network.get("enabled"), bool) else None,
                "source": "unifi_network",
            })
    else:
        vlans = _record_list(snapshot, "vlans", adapter, MAX_VLANS)
        addresses = _record_list(snapshot, "addresses", adapter, 2048)
        subnet_by_interface = {}
        for index, address in enumerate(addresses):
            interface = address.get("interface")
            if interface is None:
                continue
            if not isinstance(interface, str) or not interface or len(interface) > 64:
                raise ValueError(f"mikrotik.addresses[{index}].interface is invalid")
            network = address.get("network")
            if network is None:
                ip = address.get("address")
                prefix = address.get("prefix_length")
                if not isinstance(ip, str) or isinstance(prefix, bool) or not isinstance(prefix, int):
                    raise ValueError(f"mikrotik.addresses[{index}] must contain a normalized network")
                network = f"{ip}/{prefix}"
            parsed = _subnet(network, f"mikrotik.addresses[{index}].network")
            if parsed is not None:
                subnet_by_interface.setdefault(interface, set()).add(parsed)

        seen = set()
        for index, vlan in enumerate(vlans):
            field = f"mikrotik.vlans[{index}]"
            name = _name(vlan.get("name"), f"{field}.name", required=True)
            parent = _name(vlan.get("interface"), f"{field}.interface", required=True)
            vlan_id = _vlan_id(vlan.get("vlan_id"), f"{field}.vlan_id")
            identity = (name, parent, vlan_id)
            if identity in seen:
                raise ValueError("MikroTik VLAN interface identities must be unique")
            seen.add(identity)
            known = vlan.get("interface_known")
            if known is not None and not isinstance(known, bool):
                raise ValueError(f"{field}.interface_known must be a boolean")
            running = vlan.get("running")
            if running is not None and not isinstance(running, bool):
                raise ValueError(f"{field}.running must be a boolean")
            subnets = sorted(subnet_by_interface.get(name, set()))
            subnet_value = subnets[0] if len(subnets) == 1 else None
            if len(subnets) > 1:
                preliminary_findings.append({
                    "severity": "warning",
                    "code": "vlan.multiple_subnets_on_interface",
                    "site_id": entry["site_id"],
                    "router_id": entry["router_id"],
                    "vlan_id": vlan_id,
                    "resource": name,
                    "subnets": subnets,
                    "message": "More than one distinct IP subnet is assigned to this VLAN interface.",
                })
            if known is False:
                preliminary_findings.append({
                    "severity": "warning",
                    "code": "vlan.parent_interface_unknown",
                    "site_id": entry["site_id"],
                    "router_id": entry["router_id"],
                    "vlan_id": vlan_id,
                    "resource": name,
                    "message": "The normalized VLAN parent interface is not present in the interface inventory.",
                })
            if running is False:
                preliminary_findings.append({
                    "severity": "warning",
                    "code": "vlan.interface_down",
                    "site_id": entry["site_id"],
                    "router_id": entry["router_id"],
                    "vlan_id": vlan_id,
                    "resource": name,
                    "message": "The VLAN interface is reported down.",
                })
            segments.append({
                "site_id": entry["site_id"],
                "router_id": entry["router_id"],
                "adapter_id": adapter,
                "vlan_id": vlan_id,
                "name": name,
                "parent_interface": parent,
                "subnet": subnet_value,
                "operational": running,
                "source": "mikrotik_vlan",
            })
    return segments, preliminary_findings


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    try:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError("VLAN audit input must contain JSON-compatible finite values") from error
    if len(encoded.encode("utf-8")) > MAX_INPUT_BYTES:
        raise ValueError(f"VLAN audit input exceeds the {MAX_INPUT_BYTES}-byte input limit")
    raw_snapshots = payload.get("snapshots")
    if not isinstance(raw_snapshots, list) or not 1 <= len(raw_snapshots) <= MAX_ROUTERS:
        raise ValueError(f"snapshots must contain from 1 to {MAX_ROUTERS} router records")
    entries = [_snapshot_entry(value, index) for index, value in enumerate(raw_snapshots)]
    identities = [(item["site_id"], item["router_id"]) for item in entries]
    if len(identities) != len(set(identities)):
        raise ValueError("router identities must be unique within each site")

    segments = []
    findings = []
    by_site_vlan = defaultdict(list)
    for entry in entries:
        values, local_findings = _segments(entry)
        segments.extend(values)
        if len(segments) > MAX_TOTAL_SEGMENTS:
            raise ValueError(f"combined VLAN inventory may contain no more than {MAX_TOTAL_SEGMENTS} segments")
        findings.extend(local_findings)
        for segment in values:
            by_site_vlan[(segment["site_id"], segment["vlan_id"])].append(segment)

    for (site_id, vlan_id), group in sorted(by_site_vlan.items()):
        router_ids = sorted({item["router_id"] for item in group})
        subnet_values = sorted({item["subnet"] for item in group if item["subnet"] is not None})
        name_values = sorted({item["name"].casefold() for item in group if item["name"]})
        if len(subnet_values) > 1:
            findings.append({
                "severity": "warning",
                "code": "vlan.subnet_mismatch",
                "site_id": site_id,
                "vlan_id": vlan_id,
                "router_ids": router_ids,
                "subnets": subnet_values,
                "message": "The same VLAN ID is associated with different IP subnets across routers in this site.",
            })
        if len(name_values) > 1:
            findings.append({
                "severity": "info",
                "code": "vlan.name_mismatch",
                "site_id": site_id,
                "vlan_id": vlan_id,
                "router_ids": router_ids,
                "names": sorted({item["name"] for item in group if item["name"]}),
                "message": "The same VLAN ID has different network/interface names across routers.",
            })
        by_router = Counter(item["router_id"] for item in group)
        for router_id, count in by_router.items():
            if count > 1:
                findings.append({
                    "severity": "warning",
                    "code": "vlan.duplicate_id_on_router",
                    "site_id": site_id,
                    "router_id": router_id,
                    "vlan_id": vlan_id,
                    "segment_count": count,
                    "message": "This router reports multiple VLAN segments with the same VLAN ID; review parent bridges and isolation intent.",
                })

    findings.sort(key=lambda item: (
        SEVERITY_ORDER[item["severity"]],
        item["site_id"],
        item["vlan_id"] if isinstance(item.get("vlan_id"), int) else 0,
        item["code"],
    ))
    site_ids = sorted({entry["site_id"] for entry in entries})
    sites = []
    for site_id in site_ids:
        site_segments = [item for item in segments if item["site_id"] == site_id]
        site_findings = [item for item in findings if item["site_id"] == site_id]
        sites.append({
            "site_id": site_id,
            "router_count": len({item["router_id"] for item in entries if item["site_id"] == site_id}),
            "segment_count": len(site_segments),
            "vlan_id_count": len({item["vlan_id"] for item in site_segments}),
            "finding_count": len(site_findings),
        })
    counts = Counter(item["severity"] for item in findings)
    return {
        "status": "audited" if segments else "no_vlan_evidence",
        "summary": {
            "router_count": len(entries),
            "site_count": len(site_ids),
            "segment_count": len(segments),
            "vlan_id_count": len({(item["site_id"], item["vlan_id"]) for item in segments}),
            "finding_count": len(findings),
            "critical_count": counts["critical"],
            "warning_count": counts["warning"],
            "info_count": counts["info"],
        },
        "sites": sites,
        "segments": segments[:4000],
        "findings": findings[:400],
        "details_truncated": len(findings) > 400,
        "note": (
            "VLAN IDs are compared within a site; matching IDs across different sites are intentionally isolated. "
            "Different names or subnets may be intentional across VRFs, bridges or isolated segments. Findings "
            "are review evidence, not proof of a segmentation breach."
        ),
    }


FEATURE = {
    "id": "F179",
    "slug": "router_vlan_segmentation_audit",
    "name": "Multi-vendor VLAN segmentation audit",
    "category": "Router integrations",
    "description": (
        "Compare normalized UniFi network profiles and MikroTik VLAN interfaces within each site; "
        "identify inconsistent subnets/names, duplicate IDs, unknown parent interfaces and down VLAN interfaces."
    ),
    "parameters": {
        "snapshots": "1 to 64 normalized UniFi or MikroTik snapshots with router_id and site_id",
    },
    "run": run,
}
