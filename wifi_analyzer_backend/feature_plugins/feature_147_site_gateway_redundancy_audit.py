"""Audit high-availability gateway groups from explicit router/controller state."""
from __future__ import annotations

import ipaddress


PROTOCOLS = {"vrrp", "hsrp", "glbp", "active_standby", "unknown"}
STATES = {"active", "standby", "load_sharing", "unknown"}
FAILOVER_PROTOCOLS = {"vrrp", "hsrp", "active_standby"}


def _identifier(value: object, field: str) -> str:
    result = str(value or "").strip()
    if not result or len(result) > 128:
        raise ValueError(f"{field} must be a non-empty identifier up to 128 characters")
    return result


def run(payload: dict) -> dict:
    gateways = payload.get("gateways", [])
    if not isinstance(gateways, list):
        raise ValueError("'gateways' must be a list")
    if len(gateways) > 2048:
        raise ValueError("'gateways' may contain no more than 2048 records")

    seen_ids = set()
    grouped = {}
    ips_by_site = {}
    for gateway in gateways:
        if not isinstance(gateway, dict):
            raise ValueError("Each gateway must be an object")
        gateway_id = _identifier(gateway.get("gateway_id"), "gateway_id")
        if gateway_id in seen_ids:
            raise ValueError("gateway_id values must be unique")
        seen_ids.add(gateway_id)
        site_id = _identifier(gateway.get("site_id") or "unassigned", "site_id")
        group_id = _identifier(gateway.get("group_id"), "group_id")
        protocol = str(gateway.get("protocol") or "unknown").strip().lower()
        state = str(gateway.get("state") or "unknown").strip().lower()
        if protocol not in PROTOCOLS:
            raise ValueError(f"protocol must be one of {sorted(PROTOCOLS)}")
        if state not in STATES:
            raise ValueError(f"state must be one of {sorted(STATES)}")
        try:
            address = ipaddress.ip_address(str(gateway.get("ip") or ""))
        except ValueError as error:
            raise ValueError("Each gateway needs a valid IPv4 or IPv6 ip") from error

        priority = gateway.get("priority")
        if priority is not None:
            if isinstance(priority, bool):
                raise ValueError("priority must be an integer from 0 to 255")
            try:
                priority = int(priority)
            except (TypeError, ValueError):
                raise ValueError("priority must be an integer from 0 to 255")
            if not 0 <= priority <= 255:
                raise ValueError("priority must be an integer from 0 to 255")

        key = (site_id, protocol, group_id)
        group = grouped.setdefault(key, {"members": [], "active": 0, "standby": 0, "load_sharing": 0, "unknown": 0})
        member = {
            "gateway_id": gateway_id, "ip": str(address), "state": state,
            "priority": priority, "source": str(gateway.get("source") or "operator_supplied"),
        }
        group["members"].append(member)
        group[state] += 1
        ips_by_site.setdefault((site_id, str(address)), []).append(gateway_id)

    duplicate_ips = [
        {"site_id": site_id, "ip": address, "gateway_ids": sorted(ids)}
        for (site_id, address), ids in sorted(ips_by_site.items()) if len(ids) > 1
    ]
    duplicate_keys = {(item["site_id"], item["ip"]) for item in duplicate_ips}

    results = []
    for (site_id, protocol, group_id), group in sorted(grouped.items()):
        issues = []
        if group["active"] == 0:
            issues.append("no_confirmed_active_gateway")
        if protocol in FAILOVER_PROTOCOLS and group["active"] > 0 and group["standby"] == 0:
            issues.append("no_confirmed_standby_gateway")
        if protocol not in {"glbp", "unknown"} and group["active"] > 1:
            issues.append("multiple_active_gateways")
        if any((site_id, member["ip"]) in duplicate_keys for member in group["members"]):
            issues.append("duplicate_gateway_ip")
        if group["unknown"]:
            issues.append("gateway_state_unknown")
        results.append({
            "site_id": site_id,
            "protocol": protocol,
            "group_id": group_id,
            "member_count": len(group["members"]),
            "active_count": group["active"],
            "standby_count": group["standby"],
            "load_sharing_count": group["load_sharing"],
            "unknown_state_count": group["unknown"],
            "issues": issues,
            "status": "review" if issues else "no_reported_issue",
            "members": sorted(group["members"], key=lambda item: item["gateway_id"]),
        })

    return {
        "gateway_count": len(gateways),
        "group_count": len(results),
        "groups_with_issues": sum(bool(item["issues"]) for item in results),
        "duplicate_gateway_ips": duplicate_ips,
        "groups": results,
        "note": (
            "Uses explicit gateway state from supplied controller/router data. "
            "No redundancy is assumed from IP reachability alone, and unknown state is not treated as standby."
        ),
    }


FEATURE = {
    "id": "F147",
    "slug": "site_gateway_redundancy_audit",
    "name": "Site gateway redundancy audit",
    "category": "Site inventory",
    "description": "Review gateway failover groups, duplicate addresses and explicitly reported active/standby state.",
    "parameters": {"gateways": "gateway[]"},
    "run": run,
}
