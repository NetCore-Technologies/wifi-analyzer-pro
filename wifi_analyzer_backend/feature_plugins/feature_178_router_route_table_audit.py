"""Audit normalized OpenWrt and MikroTik route tables and default gateways.

The feature uses only normalized route/address fields. It does not probe gateways, run
traceroutes, change routing policy, or claim that recursive routes are unreachable.
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
MAX_ADDRESSES_PER_ROUTER = 2048
MAX_ADDRESSES_PER_ROUTER = 2048
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


def _network(value: object, field: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be an IP network")
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as error:
        raise ValueError(f"{field} must be a valid IP network") from error


def _ip(value: object, field: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be an IP address")
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError as error:
        raise ValueError(f"{field} must be a valid IP address") from error


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
    captured_at = _timestamp(
        value.get("captured_at", snapshot.get("captured_at")),
        f"{field}.captured_at",
    )
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
        "captured_at": captured_at,
        "snapshot": snapshot,
    }


def _list(snapshot: dict, field: str, adapter: str, maximum: int) -> list[dict]:
    values = snapshot.get(field, [])
    if not isinstance(values, list) or len(values) > maximum:
        raise ValueError(f"{adapter}.{field} must be a list containing no more than {maximum} records")
    if any(not isinstance(item, dict) for item in values):
        raise ValueError(f"{adapter}.{field} entries must be objects")
    return values


def _connected_networks(entry: dict) -> list[dict]:
    snapshot = entry["snapshot"]
    adapter = entry["adapter_id"]
    networks = []
    seen = set()
    if adapter == "openwrt":
        interfaces = _list(snapshot, "interfaces", adapter, 512)
        for index, item in enumerate(interfaces):
            name = item.get("interface")
            if name is not None and (not isinstance(name, str) or not name or len(name) > 64):
                raise ValueError(f"openwrt.interfaces[{index}].interface is invalid")
            for family in ("ipv4_addresses", "ipv6_addresses"):
                addresses = item.get(family, [])
                if not isinstance(addresses, list) or len(addresses) > 32:
                    raise ValueError(f"openwrt.interfaces[{index}].{family} must be a bounded list")
                for address_index, raw_address in enumerate(addresses):
                    field = f"openwrt.interfaces[{index}].{family}[{address_index}]"
                    if not isinstance(raw_address, str):
                        raise ValueError(f"{field} must be an IP interface address")
                    try:
                        interface = ipaddress.ip_interface(raw_address)
                    except ValueError as error:
                        raise ValueError(f"{field} must be a valid IP interface address") from error
                    network = interface.network
                    key = str(network)
                    if key not in seen:
                        seen.add(key)
                        networks.append({
                            "network": key,
                            "interface": name,
                            "ip_version": network.version,
                        })
    else:
        addresses = _list(snapshot, "addresses", adapter, MAX_ADDRESSES_PER_ROUTER)
        for index, item in enumerate(addresses):
            field = f"mikrotik.addresses[{index}]"
            network_value = item.get("network")
            if network_value is None:
                address = item.get("address")
                prefix = item.get("prefix_length")
                if not isinstance(address, str) or isinstance(prefix, bool) or not isinstance(prefix, int):
                    raise ValueError(f"{field} must contain a normalized network or address/prefix")
                network_value = f"{address}/{prefix}"
            network = _network(network_value, f"{field}.network")
            key = str(network)
            if key not in seen:
                seen.add(key)
                networks.append({
                    "network": key,
                    "interface": item.get("interface"),
                    "ip_version": network.version,
                })
    return networks


def _routes(entry: dict) -> list[dict]:
    snapshot = entry["snapshot"]
    adapter = entry["adapter_id"]
    records = _list(snapshot, "routes", adapter, MAX_ROUTES_PER_ROUTER)
    routes = []
    for index, record in enumerate(records):
        field = f"{adapter}.routes[{index}]"
        target = _network(record.get("target"), f"{field}.target")
        raw_gateway = record.get("gateway")
        gateway = _ip(raw_gateway, f"{field}.gateway") if raw_gateway is not None else None
        if gateway is not None and gateway.version != target.version:
            raise ValueError(f"{field}.gateway IP version must match target")
        if adapter == "openwrt":
            device = record.get("device")
            if device is not None and (not isinstance(device, str) or len(device) > 64):
                raise ValueError(f"{field}.device is invalid")
            metric = record.get("metric")
            if metric is not None and (
                isinstance(metric, bool) or not isinstance(metric, int) or not 0 <= metric <= 65535
            ):
                raise ValueError(f"{field}.metric must be an integer from 0 to 65535")
            table = "main"
            distance = metric
            active = None
            disabled = None
            blackhole = False
            gateway_interface = device
        else:
            table = record.get("routing_table", "main")
            if not isinstance(table, str) or not table or len(table) > 64:
                raise ValueError(f"{field}.routing_table must be a string of at most 64 characters")
            distance = record.get("distance")
            if distance is not None and (
                isinstance(distance, bool) or not isinstance(distance, int) or not 1 <= distance <= 255
            ):
                raise ValueError(f"{field}.distance must be an integer from 1 to 255")
            active = record.get("active")
            disabled = record.get("disabled")
            blackhole = record.get("blackhole", False)
            if active is not None and not isinstance(active, bool):
                raise ValueError(f"{field}.active must be a boolean")
            if disabled is not None and not isinstance(disabled, bool):
                raise ValueError(f"{field}.disabled must be a boolean")
            if not isinstance(blackhole, bool):
                raise ValueError(f"{field}.blackhole must be a boolean")
            gateway_interface = record.get("gateway_interface")
            if gateway_interface is not None and (
                not isinstance(gateway_interface, str) or not gateway_interface or len(gateway_interface) > 64
            ):
                raise ValueError(f"{field}.gateway_interface is invalid")
        route = {
            "target": str(target),
            "ip_version": target.version,
            "gateway": str(gateway) if gateway is not None else None,
            "gateway_interface": gateway_interface,
            "routing_table": table,
            "distance": distance,
            "active": active,
            "disabled": disabled,
            "blackhole": blackhole,
        }
        routes.append(route)
    return routes


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    try:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError("route audit input must contain JSON-compatible finite values") from error
    if len(encoded.encode("utf-8")) > MAX_INPUT_BYTES:
        raise ValueError(f"route audit input exceeds the {MAX_INPUT_BYTES}-byte input limit")
    raw_snapshots = payload.get("snapshots")
    if not isinstance(raw_snapshots, list) or not 1 <= len(raw_snapshots) <= MAX_ROUTERS:
        raise ValueError(f"snapshots must contain from 1 to {MAX_ROUTERS} router records")
    entries = [_snapshot_entry(item, index) for index, item in enumerate(raw_snapshots)]
    keys = [(item["site_id"], item["router_id"]) for item in entries]
    if len(keys) != len(set(keys)):
        raise ValueError("router identities must be unique within each site")

    routers = []
    total_routes = 0
    total_findings = Counter()
    for entry in sorted(entries, key=lambda item: (item["site_id"], item["router_id"])):
        connected = _connected_networks(entry)
        routes = _routes(entry)
        total_routes += len(routes)
        if total_routes > MAX_ROUTES_PER_ROUTER * MAX_ROUTERS:
            raise ValueError("combined route inventory exceeds the supported limit")
        findings = []
        route_by_identity = {}
        defaults_by_table = defaultdict(list)

        for route in routes:
            target = ipaddress.ip_network(route["target"])
            identity = (
                route["target"], route["gateway"], route["gateway_interface"],
                route["routing_table"], route["distance"], route["blackhole"],
            )
            route_by_identity[identity] = route_by_identity.get(identity, 0) + 1
            is_default = target.prefixlen == 0
            if is_default:
                defaults_by_table[route["routing_table"]].append(route)
            if route["disabled"] is True and is_default:
                findings.append({
                    "severity": "warning",
                    "code": "route.default_disabled",
                    "route": route,
                    "message": "A default route is explicitly disabled.",
                })
            if route["active"] is False and route["disabled"] is not True and is_default:
                findings.append({
                    "severity": "warning",
                    "code": "route.default_inactive",
                    "route": route,
                    "message": "A default route is explicitly marked inactive.",
                })
            if route["blackhole"] and is_default:
                findings.append({
                    "severity": "warning",
                    "code": "route.default_blackhole",
                    "route": route,
                    "message": "A default route discards traffic instead of forwarding it.",
                })
            gateway = route["gateway"]
            if gateway is not None and not route["blackhole"]:
                address = ipaddress.ip_address(gateway)
                if not any(
                    address.version == network["ip_version"]
                    and address in ipaddress.ip_network(network["network"])
                    for network in connected
                ):
                    findings.append({
                        "severity": "info",
                        "code": "route.gateway_not_directly_connected",
                        "route": route,
                        "message": (
                            "The gateway does not match a directly connected address prefix in this snapshot. "
                            "Recursive, point-to-point and tunnel routes require operator review."
                        ),
                    })

        for identity, count in route_by_identity.items():
            if count > 1:
                route = routes[next(
                    index for index, candidate in enumerate(routes)
                    if (
                        candidate["target"], candidate["gateway"], candidate["gateway_interface"],
                        candidate["routing_table"], candidate["distance"], candidate["blackhole"],
                    ) == identity
                )]
                findings.append({
                    "severity": "warning",
                    "code": "route.duplicate",
                    "route": route,
                    "duplicate_count": count,
                    "message": "The same normalized route appears more than once.",
                })

        for table, defaults in sorted(defaults_by_table.items()):
            eligible = [
                item for item in defaults
                if item["disabled"] is not True and item["blackhole"] is not True
            ]
            active = [item for item in eligible if item["active"] is True]
            if len(eligible) > 1:
                findings.append({
                    "severity": "info",
                    "code": "route.multiple_default_candidates",
                    "routing_table": table,
                    "candidate_count": len(eligible),
                    "active_count": len(active),
                    "message": (
                        "Multiple default-route candidates exist in this routing table. "
                        "This can be intentional ECMP or failover; inspect distance and active state."
                    ),
                })
            if defaults and not eligible:
                findings.append({
                    "severity": "warning",
                    "code": "route.no_forwarding_default",
                    "routing_table": table,
                    "message": "The routing table has default routes, but all are disabled or blackhole routes.",
                })
            elif defaults and entry["adapter_id"] == "mikrotik" and not active:
                explicit_states = [item["active"] for item in eligible]
                if explicit_states and all(state is False for state in explicit_states):
                    findings.append({
                        "severity": "warning",
                        "code": "route.no_active_default",
                        "routing_table": table,
                        "message": "No default route is marked active in this routing table.",
                    })

        findings.sort(key=lambda item: (
            SEVERITY_ORDER[item["severity"]], item["code"],
            item.get("routing_table", ""),
            item.get("route", {}).get("target", ""),
        ))
        counts = Counter(item["severity"] for item in findings)
        for severity, count in counts.items():
            total_findings[severity] += count
        default_count = sum(
            ipaddress.ip_network(item["target"]).prefixlen == 0 for item in routes
        )
        active_default_count = sum(
            ipaddress.ip_network(item["target"]).prefixlen == 0
            and item["disabled"] is not True
            and item["blackhole"] is not True
            and item["active"] is True
            for item in routes
        )
        routers.append({
            "router_id": entry["router_id"],
            "site_id": entry["site_id"],
            "adapter_id": entry["adapter_id"],
            "captured_at": entry["captured_at"],
            "route_count": len(routes),
            "connected_network_count": len(connected),
            "default_route_count": default_count,
            "active_default_route_count": active_default_count,
            "routing_tables": sorted({item["routing_table"] for item in routes}),
            "findings": findings[:200],
            "findings_truncated": len(findings) > 200,
            "summary": {
                "critical_count": counts["critical"],
                "warning_count": counts["warning"],
                "info_count": counts["info"],
                "finding_count": len(findings),
            },
        })

    return {
        "status": "audited",
        "summary": {
            "router_count": len(routers),
            "route_count": total_routes,
            "default_route_count": sum(item["default_route_count"] for item in routers),
            "finding_count": sum(item["summary"]["finding_count"] for item in routers),
            "critical_count": total_findings["critical"],
            "warning_count": total_findings["warning"],
            "info_count": total_findings["info"],
        },
        "routers": routers,
        "note": (
            "This audit validates normalized route metadata and connected prefixes only. It does not probe "
            "gateways or prove end-to-end reachability. An unmatched gateway may be recursive, point-to-point, "
            "or reachable through a tunnel; review it rather than assuming it is broken. Multiple default "
            "routes may implement valid ECMP or failover."
        ),
    }


FEATURE = {
    "id": "F178",
    "slug": "router_route_table_audit",
    "name": "OpenWrt and MikroTik route-table audit",
    "category": "Router integrations",
    "description": (
        "Audit normalized OpenWrt and MikroTik routes, connected prefixes, duplicate rows, default-route "
        "candidates, disabled/inactive/blackhole defaults and gateways lacking a direct-prefix match."
    ),
    "parameters": {
        "snapshots": "1 to 64 normalized OpenWrt or MikroTik router snapshots with router_id and site_id",
    },
    "run": run,
}
