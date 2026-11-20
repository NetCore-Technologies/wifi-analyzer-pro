"""Find cross-router IP subnet overlaps in normalised multi-vendor snapshots."""
from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone

MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_ROUTERS = 64
MAX_SUBNETS = 2048
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")


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


def _snapshot_entry(entry: object, index: int) -> dict:
    field = f"snapshots[{index}]"
    if not isinstance(entry, dict):
        raise ValueError(f"{field} must be an object")
    snapshot = entry.get("snapshot", entry)
    if not isinstance(snapshot, dict):
        raise ValueError(f"{field}.snapshot must be an object")
    adapter = snapshot.get("adapter_id", entry.get("adapter_id"))
    if adapter not in {"openwrt", "unifi", "mikrotik"}:
        raise ValueError(f"{field} must contain a normalised OpenWrt, UniFi or MikroTik snapshot")
    captured_at = _timestamp(entry.get("captured_at", snapshot.get("captured_at")), f"{field}.captured_at")
    raw_id = (
        entry.get("router_id") or entry.get("agent_id") or entry.get("id")
        or snapshot.get("router_id") or snapshot.get("agent_id")
    )
    if raw_id is None and adapter == "unifi":
        controller = snapshot.get("controller", {})
        if isinstance(controller, dict):
            raw_id = controller.get("hostname")
    if raw_id is None and adapter == "mikrotik":
        router = snapshot.get("router", {})
        if isinstance(router, dict):
            raw_id = router.get("serial_number")
    router_id = _identifier(raw_id, f"{field}.router_id")
    site_id = _identifier(entry.get("site_id", "unassigned"), f"{field}.site_id")
    return {
        "router_id": router_id,
        "site_id": site_id,
        "adapter_id": adapter,
        "captured_at": captured_at,
        "snapshot": snapshot,
    }


def _list(snapshot: dict, name: str, adapter: str, maximum: int) -> list[dict]:
    value = snapshot.get(name, [])
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError(f"{adapter}.{name} must be a list containing no more than {maximum} records")
    if any(not isinstance(item, dict) for item in value):
        raise ValueError(f"{adapter}.{name} entries must be objects")
    return value


def _cidr(value: object, field: str, *, interface: bool) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a CIDR network")
    try:
        if interface:
            return ipaddress.ip_interface(value.strip()).network
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as error:
        raise ValueError(f"{field} must be a valid CIDR network") from error


def _extract(entry: dict) -> list[dict]:
    snapshot = entry["snapshot"]
    adapter = entry["adapter_id"]
    found = []

    def append(raw_cidr, field, source, *, interface=False, vlan_id=None):
        network = _cidr(raw_cidr, field, interface=interface)
        if vlan_id is not None:
            if isinstance(vlan_id, bool) or not isinstance(vlan_id, int) or not 1 <= vlan_id <= 4094:
                raise ValueError(f"{field}.vlan_id must be an integer from 1 to 4094")
        found.append({
            "site_id": entry["site_id"],
            "router_id": entry["router_id"],
            "adapter_id": adapter,
            "source": source,
            "cidr": str(network),
            "ip_version": network.version,
            "vlan_id": vlan_id,
        })
        if len(found) > MAX_SUBNETS:
            raise ValueError(f"normalised subnet inventory may contain no more than {MAX_SUBNETS} records")

    if adapter == "openwrt":
        interfaces = _list(snapshot, "interfaces", adapter, 512)
        for index, item in enumerate(interfaces):
            name = item.get("interface")
            if name is not None and (not isinstance(name, str) or len(name) > 64):
                raise ValueError(f"openwrt.interfaces[{index}].interface is invalid")
            for family in ("ipv4_addresses", "ipv6_addresses"):
                values = item.get(family, [])
                if not isinstance(values, list) or len(values) > 32:
                    raise ValueError(f"openwrt.interfaces[{index}].{family} must be a bounded list")
                for address_index, value in enumerate(values):
                    append(
                        value, f"openwrt.interfaces[{index}].{family}[{address_index}]",
                        f"interface:{name or 'unknown'}", interface=True,
                    )
    elif adapter == "unifi":
        networks = _list(snapshot, "networks", adapter, 1024)
        for index, item in enumerate(networks):
            subnet = item.get("ip_subnet")
            if subnet is None:
                continue
            append(
                subnet, f"unifi.networks[{index}].ip_subnet",
                f"network:{item.get('name') or item.get('id') or 'unnamed'}",
                interface=False, vlan_id=item.get("vlan_id"),
            )
    else:
        addresses = _list(snapshot, "addresses", adapter, 2048)
        for index, item in enumerate(addresses):
            raw = item.get("network")
            if raw is None:
                address = item.get("address")
                prefix = item.get("prefix_length")
                if not isinstance(prefix, int) or isinstance(prefix, bool):
                    raise ValueError(f"mikrotik.addresses[{index}].prefix_length must be an integer")
                raw = f"{address}/{prefix}" if isinstance(address, str) else None
            append(
                raw, f"mikrotik.addresses[{index}].network",
                f"interface:{item.get('interface') or 'unknown'}", interface=True,
            )
    return found


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    try:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError("subnet audit input must contain JSON-compatible finite values") from error
    if len(encoded.encode("utf-8")) > MAX_INPUT_BYTES:
        raise ValueError(f"subnet audit input exceeds the {MAX_INPUT_BYTES}-byte input limit")

    raw_entries = payload.get("snapshots")
    if not isinstance(raw_entries, list) or not 1 <= len(raw_entries) <= MAX_ROUTERS:
        raise ValueError(f"snapshots must contain from 1 to {MAX_ROUTERS} router records")
    entries = [_snapshot_entry(item, index) for index, item in enumerate(raw_entries)]
    keys = [(item["site_id"], item["router_id"]) for item in entries]
    if len(keys) != len(set(keys)):
        raise ValueError("router identities must be unique within each site")

    subnets = []
    by_site: dict[str, list[dict]] = defaultdict(list)
    for entry in entries:
        records = _extract(entry)
        # Repeated interfaces on a single router may legitimately reference the same
        # connected segment (for example a bridge and its member); compare it once.
        seen = set()
        for record in records:
            identity = (record["cidr"], record["vlan_id"])
            if identity in seen:
                continue
            seen.add(identity)
            subnets.append(record)
            by_site[record["site_id"]].append(record)
    if len(subnets) > MAX_SUBNETS:
        raise ValueError(f"subnet inventory may contain no more than {MAX_SUBNETS} records")

    overlaps = []
    site_summaries = []
    for site_id, records in sorted(by_site.items()):
        site_overlaps = []
        parsed = [(record, ipaddress.ip_network(record["cidr"], strict=False)) for record in records]
        for index, (left_record, left_network) in enumerate(parsed):
            for right_record, right_network in parsed[index + 1:]:
                if left_record["router_id"] == right_record["router_id"]:
                    continue
                if left_network.version != right_network.version or not left_network.overlaps(right_network):
                    continue
                exact = left_network == right_network
                finding = {
                    "severity": "warning",
                    "code": "subnet.duplicate" if exact else "subnet.overlap",
                    "overlap_type": "duplicate" if exact else "overlap",
                    "site_id": site_id,
                    "left": left_record,
                    "right": right_record,
                    "message": (
                        "The same IP subnet is configured on multiple routers in this site."
                        if exact else
                        "IP subnet ranges overlap across different routers in this site."
                    ),
                }
                site_overlaps.append(finding)
        overlaps.extend(site_overlaps)
        site_summaries.append({
            "site_id": site_id,
            "router_count": len({record["router_id"] for record in records}),
            "subnet_count": len(records),
            "overlap_count": len(site_overlaps),
            "duplicate_count": sum(item["overlap_type"] == "duplicate" for item in site_overlaps),
        })

    return {
        "status": "audited" if subnets else "no_subnets",
        "summary": {
            "router_count": len(entries),
            "site_count": len({item["site_id"] for item in entries}),
            "subnet_count": len(subnets),
            "overlap_count": len(overlaps),
            "duplicate_subnet_count": sum(item["overlap_type"] == "duplicate" for item in overlaps),
            "overlapping_subnet_count": sum(item["overlap_type"] == "overlap" for item in overlaps),
        },
        "sites": site_summaries,
        "subnets": subnets,
        "overlaps": overlaps,
        "note": (
            "Only normalized interface/network CIDRs are compared, and only within the same site. "
            "An overlap is review evidence, not proof of a fault: intentional shared addressing, "
            "VRFs, NAT boundaries and isolated network segments require operator context."
        ),
    }


FEATURE = {
    "id": "F176",
    "slug": "router_subnet_overlap_audit",
    "name": "Multi-vendor router subnet overlap audit",
    "category": "Router integrations",
    "description": (
        "Compare normalized OpenWrt interface, UniFi network and MikroTik address CIDRs within "
        "each site and report exact duplicates or overlapping ranges across different routers."
    ),
    "parameters": {
        "snapshots": "1 to 64 normalised router snapshots with router_id and site_id",
    },
    "run": run,
}
