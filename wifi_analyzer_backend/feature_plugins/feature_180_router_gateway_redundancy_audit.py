"""Compare configured default-gateway candidates across routers within each site.

This is an inventory audit, not a failover test. It reads normalized OpenWrt/MikroTik
route snapshots and never probes gateways, changes routes or claims path availability.
"""
from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone

MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_ROUTERS = 64
MAX_ROUTES_PER_ROUTER = 2048
MAX_DEFAULT_GROUPS = 512
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


def _snapshot_entry(value: object, index: int) -> dict:
    field = f"snapshots[{index}]"
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    snapshot = value.get("snapshot", value)
    if not isinstance(snapshot, dict):
        raise ValueError(f"{field}.snapshot must be an object")
    adapter = snapshot.get("adapter_id", value.get("adapter_id"))
    if not isinstance(adapter, str) or adapter not in {"openwrt", "mikrotik"}:
        raise ValueError(f"{field} must contain a normalized OpenWrt or MikroTik snapshot")
    router_id = (
        value.get("router_id") or value.get("agent_id") or value.get("id")
        or snapshot.get("router_id") or snapshot.get("agent_id")
    )
    if router_id is None and adapter == "mikrotik":
        router = snapshot.get("router", {})
        if isinstance(router, dict):
            router_id = router.get("serial_number")
    return {
        "router_id": _identifier(router_id, f"{field}.router_id"),
        "site_id": _identifier(value.get("site_id", "unassigned"), f"{field}.site_id"),
        "adapter_id": adapter,
        "captured_at": _timestamp(
            value.get("captured_at", snapshot.get("captured_at")),
            f"{field}.captured_at",
        ),
        "snapshot": snapshot,
    }


def _list(snapshot: dict, field: str, adapter: str, maximum: int) -> list[dict]:
    values = snapshot.get(field, [])
    if not isinstance(values, list) or len(values) > maximum:
        raise ValueError(f"{adapter}.{field} must be a list containing no more than {maximum} records")
    if any(not isinstance(item, dict) for item in values):
        raise ValueError(f"{adapter}.{field} entries must be objects")
    return values


def _route_records(entry: dict) -> list[dict]:
    adapter = entry["adapter_id"]
    snapshot = entry["snapshot"]
    raw_routes = _list(snapshot, "routes", adapter, MAX_ROUTES_PER_ROUTER)
    result = []
    for index, raw in enumerate(raw_routes):
        field = f"{adapter}.routes[{index}]"
        target_value = raw.get("target")
        if not isinstance(target_value, str):
            raise ValueError(f"{field}.target must be an IP network")
        try:
            target = ipaddress.ip_network(target_value.strip(), strict=False)
        except ValueError as error:
            raise ValueError(f"{field}.target must be a valid IP network") from error
        gateway_value = raw.get("gateway")
        gateway = None
        if gateway_value is not None:
            if not isinstance(gateway_value, str):
                raise ValueError(f"{field}.gateway must be an IP address")
            try:
                gateway = ipaddress.ip_address(gateway_value.strip())
            except ValueError as error:
                raise ValueError(f"{field}.gateway must be a valid IP address") from error
            if gateway.version != target.version:
                raise ValueError(f"{field}.gateway IP version must match target")

        interface = raw.get("gateway_interface")
        if interface is None and adapter == "openwrt":
            interface = raw.get("device")
        if interface is not None and (
            not isinstance(interface, str) or not interface or len(interface) > 64
        ):
            raise ValueError(f"{field}.gateway_interface is invalid")
        table = raw.get("routing_table", "main")
        if not isinstance(table, str) or not table or len(table) > 64:
            raise ValueError(f"{field}.routing_table must be a string of at most 64 characters")
        active = raw.get("active")
        disabled = raw.get("disabled")
        blackhole = raw.get("blackhole", False)
        if active is not None and not isinstance(active, bool):
            raise ValueError(f"{field}.active must be a boolean")
        if disabled is not None and not isinstance(disabled, bool):
            raise ValueError(f"{field}.disabled must be a boolean")
        if not isinstance(blackhole, bool):
            raise ValueError(f"{field}.blackhole must be a boolean")
        distance = raw.get("distance", raw.get("metric"))
        if distance is not None and (
            isinstance(distance, bool) or not isinstance(distance, int) or not 0 <= distance <= 65535
        ):
            raise ValueError(f"{field}.distance or metric is outside the supported range")
        result.append({
            "site_id": entry["site_id"],
            "router_id": entry["router_id"],
            "adapter_id": adapter,
            "target": str(target),
            "ip_version": target.version,
            "gateway": str(gateway) if gateway is not None else None,
            "gateway_interface": interface,
            "routing_table": table,
            "distance": distance,
            "active": active,
            "disabled": disabled,
            "blackhole": blackhole,
        })
    return result


def _path_identity(route: dict) -> tuple | None:
    gateway = route["gateway"]
    if gateway is None:
        return None
    address = ipaddress.ip_address(gateway)
    interface = route["gateway_interface"] if address.is_link_local else None
    return str(address), interface


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    try:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError("gateway audit input must contain JSON-compatible finite values") from error
    if len(encoded.encode("utf-8")) > MAX_INPUT_BYTES:
        raise ValueError(f"gateway audit input exceeds the {MAX_INPUT_BYTES}-byte input limit")
    raw_snapshots = payload.get("snapshots")
    if not isinstance(raw_snapshots, list) or not 1 <= len(raw_snapshots) <= MAX_ROUTERS:
        raise ValueError(f"snapshots must contain from 1 to {MAX_ROUTERS} router records")
    entries = [_snapshot_entry(value, index) for index, value in enumerate(raw_snapshots)]
    router_keys = [(item["site_id"], item["router_id"]) for item in entries]
    if len(router_keys) != len(set(router_keys)):
        raise ValueError("router identities must be unique within each site")

    by_site_family_table = defaultdict(list)
    router_summaries = []
    for entry in entries:
        routes = _route_records(entry)
        defaults = [
            route for route in routes
            if ipaddress.ip_network(route["target"]).prefixlen == 0
        ]
        eligible = [
            route for route in defaults
            if route["disabled"] is not True and route["blackhole"] is not True
        ]
        active = [route for route in eligible if route["active"] is True]
        inactive = [route for route in eligible if route["active"] is False]
        unknown = [route for route in eligible if route["active"] is None]
        for route in defaults:
            by_site_family_table[
                (entry["site_id"], route["ip_version"], route["routing_table"])
            ].append(route)
        router_summaries.append({
            "site_id": entry["site_id"],
            "router_id": entry["router_id"],
            "adapter_id": entry["adapter_id"],
            "captured_at": entry["captured_at"],
            "route_count": len(routes),
            "default_route_count": len(defaults),
            "eligible_default_route_count": len(eligible),
            "active_default_route_count": len(active),
            "inactive_default_route_count": len(inactive),
            "activation_unknown_default_route_count": len(unknown),
        })

    if len(by_site_family_table) > MAX_DEFAULT_GROUPS:
        raise ValueError(f"default-route groups may contain no more than {MAX_DEFAULT_GROUPS} entries")

    groups = []
    findings = []
    status_counts = Counter()
    for (site_id, ip_version, table), routes in sorted(by_site_family_table.items()):
        routers = defaultdict(list)
        for route in routes:
            routers[route["router_id"]].append(route)
        eligible = [
            route for route in routes
            if route["disabled"] is not True and route["blackhole"] is not True
        ]
        active = [route for route in eligible if route["active"] is True]
        inactive = [route for route in eligible if route["active"] is False]
        unknown = [route for route in eligible if route["active"] is None]
        eligible_router_ids = sorted({route["router_id"] for route in eligible})
        active_router_ids = sorted({route["router_id"] for route in active})
        gateway_paths = sorted(
            {
                identity for route in eligible
                if (identity := _path_identity(route)) is not None
            },
            key=lambda identity: (identity[0], identity[1] or ""),
        )
        gateway_values = sorted({identity[0] for identity in gateway_paths})
        all_route_count = len(routes)

        if not routes:
            status = "no_default_routes"
        elif not eligible:
            status = "no_forwarding_candidates"
        elif len(eligible_router_ids) == 1:
            status = "single_router_candidate"
        elif len(active_router_ids) >= 2 and len(gateway_paths) >= 2:
            status = "multiple_active_router_paths"
        elif len(eligible_router_ids) >= 2 and len(gateway_paths) >= 2:
            status = "multiple_configured_paths_unverified"
        elif len(eligible_router_ids) >= 2 and len(gateway_paths) == 1 and all(
            route["gateway"] is not None for route in eligible
        ):
            status = "shared_next_hop"
        elif len(eligible_router_ids) >= 2 and len(gateway_paths) == 0:
            status = "multiple_router_candidates_gateway_unknown"
        elif len(eligible_router_ids) >= 2 and any(route["gateway"] is None for route in eligible):
            status = "multiple_router_candidates_gateway_unknown"
        else:
            status = "unknown"
        status_counts[status] += 1

        group_findings = []
        if routes and not eligible:
            group_findings.append({
                "severity": "warning",
                "code": "gateway.no_eligible_default",
                "message": "All default routes in this site/table/family are disabled or blackhole routes.",
            })
        elif len(eligible_router_ids) == 1:
            group_findings.append({
                "severity": "warning",
                "code": "gateway.single_router_candidate",
                "message": "Only one router has a non-disabled, non-blackhole default-route candidate for this site/table/family.",
            })
        if len(eligible_router_ids) >= 2 and len(gateway_paths) == 1 and all(
            route["gateway"] is not None for route in eligible
        ):
            group_findings.append({
                "severity": "info",
                "code": "gateway.shared_next_hop",
                "message": "Multiple routers use the same next-hop identity; this may remain a shared upstream dependency.",
            })
        elif len(eligible_router_ids) >= 2 and len(gateway_paths) >= 2:
            group_findings.append({
                "severity": "info",
                "code": "gateway.multiple_configured_paths",
                "message": "Multiple routers and distinct next-hop identities are configured; actual failover and upstream independence have not been tested.",
            })
        elif len(eligible_router_ids) >= 2 and any(route["gateway"] is None for route in eligible):
            group_findings.append({
                "severity": "info",
                "code": "gateway.next_hop_unknown",
                "message": "Multiple routers have default routes but at least one next-hop address is not recorded.",
            })
        if unknown:
            group_findings.append({
                "severity": "info",
                "code": "gateway.activation_unknown",
                "route_count": len(unknown),
                "message": "Some default-route candidates do not expose an active/inactive flag in this adapter snapshot.",
            })
        if inactive and not active:
            group_findings.append({
                "severity": "warning",
                "code": "gateway.no_known_active_candidate",
                "message": "No default-route candidate is explicitly marked active; standby or unknown routes may still be valid by design.",
            })

        router_details = []
        for router_id in sorted(routers):
            router_routes = routers[router_id]
            router_details.append({
                "router_id": router_id,
                "adapter_ids": sorted({item["adapter_id"] for item in router_routes}),
                "route_count": len(router_routes),
                "active_count": sum(item["active"] is True and item["disabled"] is not True
                                    and item["blackhole"] is not True for item in router_routes),
                "inactive_count": sum(item["active"] is False and item["disabled"] is not True
                                      and item["blackhole"] is not True for item in router_routes),
                "gateway_identities": sorted(
                    {
                        identity for item in router_routes
                        if item["disabled"] is not True and item["blackhole"] is not True
                        if (identity := _path_identity(item)) is not None
                    },
                    key=lambda identity: (identity[0], identity[1] or ""),
                ),
            })
        for finding in group_findings:
            findings.append({
                "site_id": site_id,
                "ip_version": ip_version,
                "routing_table": table,
                "router_ids": sorted(routers),
                **finding,
            })
        groups.append({
            "site_id": site_id,
            "ip_version": ip_version,
            "routing_table": table,
            "status": status,
            "router_count": len(routers),
            "eligible_router_count": len(eligible_router_ids),
            "active_router_count": len(active_router_ids),
            "inactive_route_count": len(inactive),
            "activation_unknown_route_count": len(unknown),
            "default_route_count": all_route_count,
            "distinct_gateway_count": len(gateway_paths),
            "distinct_gateway_addresses": gateway_values,
            "routers": router_details,
            "findings": group_findings,
        })

    site_ids = sorted({item["site_id"] for item in entries})
    sites = []
    for site_id in site_ids:
        site_groups = [item for item in groups if item["site_id"] == site_id]
        sites.append({
            "site_id": site_id,
            "router_count": len({item["router_id"] for item in router_summaries if item["site_id"] == site_id}),
            "router_with_default_route_count": sum(
                item["default_route_count"] > 0 for item in router_summaries if item["site_id"] == site_id
            ),
            "router_without_default_route_count": sum(
                item["default_route_count"] == 0 for item in router_summaries if item["site_id"] == site_id
            ),
            "default_route_group_count": len(site_groups),
            "multiple_path_group_count": sum(item["status"] in {
                "multiple_active_router_paths", "multiple_configured_paths_unverified"
            } for item in site_groups),
            "single_router_group_count": sum(item["status"] == "single_router_candidate" for item in site_groups),
        })
    severity_counts = Counter(item["severity"] for item in findings)
    return {
        "status": "audited",
        "summary": {
            "router_count": len(router_summaries),
            "site_count": len(site_ids),
            "default_route_group_count": len(groups),
            "configured_default_route_count": sum(item["default_route_count"] for item in router_summaries),
            "router_without_default_route_count": sum(item["default_route_count"] == 0 for item in router_summaries),
            "multiple_path_group_count": sum(item["status"] in {
                "multiple_active_router_paths", "multiple_configured_paths_unverified"
            } for item in groups),
            "single_router_group_count": sum(item["status"] == "single_router_candidate" for item in groups),
            "finding_count": len(findings),
            "warning_count": severity_counts["warning"],
            "info_count": severity_counts["info"],
        },
        "sites": sites,
        "routers": router_summaries,
        "groups": groups,
        "findings": findings[:400],
        "details_truncated": len(findings) > 400,
        "note": (
            "This report compares configured route candidates only. It does not perform health checks, "
            "probe gateways, simulate failover, or prove that different next hops use independent upstream "
            "circuits. ECMP, standby routes, VRFs, recursive routes and shared CPEs require operator context."
        ),
    }


FEATURE = {
    "id": "F180",
    "slug": "router_gateway_redundancy_audit",
    "name": "Cross-router default-gateway redundancy audit",
    "category": "Router integrations",
    "description": (
        "Compare OpenWrt and MikroTik default-route candidates by site, IP family and routing table; "
        "report single-router paths, shared next hops, distinct configured paths and unknown activation."
    ),
    "parameters": {
        "snapshots": "1 to 64 normalized OpenWrt or MikroTik router snapshots with router_id and site_id",
    },
    "run": run,
}
