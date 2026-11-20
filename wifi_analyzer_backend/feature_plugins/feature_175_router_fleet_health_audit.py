"""Audit a fleet of normalised OpenWrt, UniFi and MikroTik router snapshots.

Only validated, allow-listed measurements are used. The report never echoes raw
snapshots, configuration blobs, credentials or unknown input properties.
"""
from __future__ import annotations

import json
import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone

MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_ROUTERS = 64
MAX_FINDINGS_PER_ROUTER = 100
MAX_INTERFACES = 512
MAX_RADIOS = 8192
MAX_ASSOCIATIONS = 8192
MAX_ACCESS_POINTS = 1024
MAX_IDENTIFIER_LENGTH = 64
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
MAC = re.compile(r"^[0-9A-F]{2}(?::[0-9A-F]{2}){5}$")
SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone offset")
    return parsed.astimezone(timezone.utc)


def _identifier(value: object, field: str, default: str | None = None) -> str:
    if value is None and default is not None:
        value = default
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError(f"{field} must be a 1 to {MAX_IDENTIFIER_LENGTH} character identifier")
    return value


def _number(value: object, field: str, minimum: float, maximum: float) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a finite number")
    try:
        parsed = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field} must be numeric") from error
    if not math.isfinite(parsed) or not minimum <= parsed <= maximum:
        raise ValueError(f"{field} is outside the supported range")
    return parsed


def _record_list(snapshot: dict, field: str, maximum: int, adapter: str) -> list[dict]:
    records = snapshot.get(field, [])
    if not isinstance(records, list) or len(records) > maximum:
        raise ValueError(f"{adapter}.{field} must be a list containing no more than {maximum} records")
    if any(not isinstance(record, dict) for record in records):
        raise ValueError(f"{adapter}.{field} entries must be objects")
    return records


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
    captured = entry.get("captured_at", snapshot.get("captured_at"))
    captured_at = _timestamp(captured, f"{field}.captured_at")
    raw_router_id = (
        entry.get("router_id")
        or entry.get("agent_id")
        or entry.get("id")
        or snapshot.get("router_id")
        or snapshot.get("agent_id")
    )
    if raw_router_id is None and adapter == "unifi":
        controller = snapshot.get("controller", {})
        if isinstance(controller, dict):
            raw_router_id = controller.get("hostname")
    if raw_router_id is None and adapter == "mikrotik":
        router = snapshot.get("router", {})
        if isinstance(router, dict):
            raw_router_id = router.get("serial_number")
    if raw_router_id is None:
        raise ValueError(f"{field} must include router_id, agent_id or a stable vendor identity")
    router_id = _identifier(raw_router_id, f"{field}.router_id")
    site_id = _identifier(entry.get("site_id", "unassigned"), f"{field}.site_id")
    return {
        "router_id": router_id,
        "site_id": site_id,
        "adapter_id": adapter,
        "captured_at": captured_at,
        "snapshot": snapshot,
    }


def _memory_metrics(snapshot: dict, adapter: str) -> tuple[float | None, dict | None]:
    if adapter == "openwrt":
        health = snapshot.get("system_health")
        if health is None:
            return None, None
        if not isinstance(health, dict):
            raise ValueError("openwrt.system_health must be an object")
        memory = health.get("memory_bytes")
        if not isinstance(memory, dict):
            raise ValueError("openwrt.system_health.memory_bytes must be an object")
        total = _number(memory.get("total"), "openwrt.memory.total", 1, 2**63 - 1)
        available = memory.get("available", memory.get("free"))
        available = _number(available, "openwrt.memory.available", 0, 2**63 - 1)
    elif adapter == "mikrotik":
        resource = snapshot.get("resource", {})
        if not isinstance(resource, dict):
            raise ValueError("mikrotik.resource must be an object")
        total = _number(resource.get("total_memory_bytes"), "mikrotik.resource.total_memory_bytes", 1, 2**63 - 1)
        available = _number(resource.get("free_memory_bytes"), "mikrotik.resource.free_memory_bytes", 0, 2**63 - 1)
        if total is None or available is None:
            return None, None
    else:
        return None, None
    if total is None or available is None:
        return None, None
    if available > total:
        raise ValueError(f"{adapter} memory available cannot exceed total")
    used_pct = ((total - available) / total) * 100
    return used_pct, {"total_bytes": int(total), "available_bytes": int(available)}


def _cpu_metrics(snapshot: dict, adapter: str) -> float | None:
    if adapter == "mikrotik":
        resource = snapshot.get("resource", {})
        if not isinstance(resource, dict):
            raise ValueError("mikrotik.resource must be an object")
        return _number(resource.get("cpu_load_pct"), "mikrotik.resource.cpu_load_pct", 0, 100)
    # OpenWrt and UniFi normalisers deliberately do not invent a CPU value.
    return None


def _audit_one(entry: dict, now: datetime, max_age_seconds: int,
               weak_signal_dbm: int, critical_signal_dbm: int) -> dict:
    snapshot = entry["snapshot"]
    adapter = entry["adapter_id"]
    age = max(0, int((now - entry["captured_at"]).total_seconds()))
    findings = []
    evidence = set()

    def add(severity: str, code: str, resource_type: str, resource_id: str | None,
            message: str, observed=None, threshold=None):
        findings.append({
            "severity": severity,
            "code": code,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "message": message,
            "observed": observed,
            "threshold": threshold,
        })

    if age > max_age_seconds:
        severity = "critical" if age > max_age_seconds * 4 else "warning"
        add(
            severity, "snapshot.stale", "router", entry["router_id"],
            "The last captured snapshot is older than the configured freshness limit.",
            observed=age, threshold=max_age_seconds,
        )
    cpu = _cpu_metrics(snapshot, adapter)
    if cpu is not None:
        evidence.add("cpu")
        if cpu >= 95:
            add("critical", "resource.cpu_critical", "router", entry["router_id"],
                "CPU load is at or above 95 percent.", observed=round(cpu, 2), threshold=95)
        elif cpu >= 85:
            add("warning", "resource.cpu_high", "router", entry["router_id"],
                "CPU load is elevated.", observed=round(cpu, 2), threshold=85)

    memory_pct, memory_values = _memory_metrics(snapshot, adapter)
    if memory_pct is not None:
        evidence.add("memory")
        if memory_pct >= 95:
            add("critical", "resource.memory_critical", "router", entry["router_id"],
                "Measured memory use is at or above 95 percent.",
                observed=round(memory_pct, 2), threshold=95)
        elif memory_pct >= 90:
            add("warning", "resource.memory_high", "router", entry["router_id"],
                "Measured memory use is elevated.",
                observed=round(memory_pct, 2), threshold=90)

    if adapter == "openwrt":
        interfaces = _record_list(snapshot, "interfaces", MAX_INTERFACES, adapter)
        radios = _record_list(snapshot, "wireless_radios", MAX_RADIOS, adapter)
        associations = _record_list(snapshot, "associations", MAX_ASSOCIATIONS, adapter)
        for record in interfaces:
            state = record.get("up")
            if isinstance(state, bool):
                evidence.add("interface_state")
                if state is False:
                    name = record.get("interface")
                    add("warning", "interface.down", "interface",
                        name if isinstance(name, str) and len(name) <= 64 else None,
                        "A network interface is reported down.")
        for record in radios:
            state = record.get("up")
            if isinstance(state, bool):
                evidence.add("radio_state")
                if state is False:
                    name = record.get("interface")
                    add("warning", "radio.down", "radio",
                        name if isinstance(name, str) and len(name) <= 64 else None,
                        "A wireless radio is reported down.")
    elif adapter == "mikrotik":
        interfaces = _record_list(snapshot, "interfaces", MAX_INTERFACES, adapter)
        radios = _record_list(snapshot, "wireless_radios", MAX_RADIOS, adapter)
        associations = _record_list(snapshot, "associations", MAX_ASSOCIATIONS, adapter)
        for record in interfaces:
            state = record.get("state")
            if state in {"up", "down", "disabled"}:
                evidence.add("interface_state")
                if state == "down":
                    name = record.get("name")
                    add("warning", "interface.down", "interface",
                        name if isinstance(name, str) and len(name) <= 64 else None,
                        "A network interface is reported down.")
        for record in radios:
            state = record.get("state")
            if state in {"up", "down", "disabled"}:
                evidence.add("radio_state")
                if state == "down":
                    name = record.get("interface")
                    add("warning", "radio.down", "radio",
                        name if isinstance(name, str) and len(name) <= 64 else None,
                        "A wireless interface is reported down.")
    else:
        interfaces = []
        access_points = _record_list(snapshot, "access_points", MAX_ACCESS_POINTS, adapter)
        radios = _record_list(snapshot, "wireless_radios", MAX_RADIOS, adapter)
        associations = _record_list(snapshot, "associations", MAX_ASSOCIATIONS, adapter)
        for record in access_points:
            state = record.get("status")
            if state in {"online", "offline"}:
                evidence.add("access_point_state")
                if state == "offline":
                    mac = record.get("mac")
                    add("critical", "access_point.offline", "access_point",
                        mac if isinstance(mac, str) and MAC.fullmatch(mac) else None,
                        "An access point is reported offline.")
        for record in radios:
            state = record.get("up")
            if isinstance(state, bool):
                evidence.add("radio_state")
                if state is False:
                    radio = record.get("radio")
                    ap_mac = record.get("ap_mac")
                    resource_id = f"{ap_mac}/{radio}" if isinstance(ap_mac, str) and isinstance(radio, str) else None
                    add("warning", "radio.down", "radio",
                        resource_id if resource_id and len(resource_id) <= 64 else None,
                        "A wireless radio is reported down.")

    for record in associations:
        signal = record.get("signal_dbm")
        if signal is None:
            continue
        signal = _number(signal, f"{adapter}.association.signal_dbm", -150, 0)
        if signal is None:
            continue
        evidence.add("client_signal")
        if signal <= critical_signal_dbm:
            client_mac = record.get("client_mac")
            add("critical", "client.signal_critical", "client",
                client_mac if isinstance(client_mac, str) and MAC.fullmatch(client_mac) else None,
                "A client has a critically weak measured signal.",
                observed=round(signal, 2), threshold=critical_signal_dbm)
        elif signal <= weak_signal_dbm:
            client_mac = record.get("client_mac")
            add("warning", "client.signal_weak", "client",
                client_mac if isinstance(client_mac, str) and MAC.fullmatch(client_mac) else None,
                "A client has a weak measured signal.",
                observed=round(signal, 2), threshold=weak_signal_dbm)

    findings.sort(key=lambda item: (
        SEVERITY_ORDER[item["severity"]], item["code"], item["resource_id"] or ""
    ))
    severity_counts = Counter(item["severity"] for item in findings)
    score = max(0, 100 - severity_counts["critical"] * 25
                - severity_counts["warning"] * 10 - severity_counts["info"] * 2)
    status = (
        "critical" if severity_counts["critical"]
        else "degraded" if severity_counts["warning"]
        else "healthy" if evidence
        else "unknown"
    )
    total_findings = len(findings)
    return {
        "router_id": entry["router_id"],
        "site_id": entry["site_id"],
        "adapter_id": adapter,
        "captured_at": entry["captured_at"].isoformat(),
        "age_seconds": age,
        "health_status": status,
        "health_score": score,
        "evidence": sorted(evidence),
        "resource_metrics": {
            "cpu_load_pct": round(cpu, 2) if cpu is not None else None,
            "memory_used_pct": round(memory_pct, 2) if memory_pct is not None else None,
            "memory": memory_values,
        },
        "summary": {
            "finding_count": total_findings,
            "critical_count": severity_counts["critical"],
            "warning_count": severity_counts["warning"],
            "info_count": severity_counts["info"],
            "interface_count": len(interfaces),
            "radio_count": len(radios),
            "association_count": len(associations),
        },
        "findings": findings[:MAX_FINDINGS_PER_ROUTER],
        "findings_truncated": total_findings > MAX_FINDINGS_PER_ROUTER,
    }


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    try:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError("fleet input must contain JSON-compatible finite values") from error
    if len(encoded.encode("utf-8")) > MAX_INPUT_BYTES:
        raise ValueError(f"fleet input exceeds the {MAX_INPUT_BYTES}-byte input limit")

    raw_entries = payload.get("snapshots")
    if not isinstance(raw_entries, list) or not 1 <= len(raw_entries) <= MAX_ROUTERS:
        raise ValueError(f"snapshots must contain from 1 to {MAX_ROUTERS} router records")
    now = _timestamp(payload.get("now"), "now")
    max_age = payload.get("max_age_seconds", 900)
    if isinstance(max_age, bool) or not isinstance(max_age, int) or not 60 <= max_age <= 86400:
        raise ValueError("max_age_seconds must be an integer between 60 and 86400")
    weak_signal = payload.get("weak_signal_dbm", -75)
    critical_signal = payload.get("critical_signal_dbm", -85)
    if (isinstance(weak_signal, bool) or not isinstance(weak_signal, int)
            or not -100 <= weak_signal <= -40):
        raise ValueError("weak_signal_dbm must be an integer between -100 and -40")
    if (isinstance(critical_signal, bool) or not isinstance(critical_signal, int)
            or not -110 <= critical_signal <= -50 or critical_signal >= weak_signal):
        raise ValueError("critical_signal_dbm must be lower than weak_signal_dbm and between -110 and -50")

    entries = [_snapshot_entry(item, index) for index, item in enumerate(raw_entries)]
    identities = [(item["site_id"], item["router_id"]) for item in entries]
    if len(identities) != len(set(identities)):
        raise ValueError("router identities must be unique within each site")
    for item in entries:
        if (item["captured_at"] - now).total_seconds() > 300:
            raise ValueError(f"snapshot for {item['router_id']} is more than five minutes in the future")

    devices = [
        _audit_one(item, now, max_age, weak_signal, critical_signal)
        for item in sorted(entries, key=lambda value: (value["site_id"], value["router_id"]))
    ]
    site_groups = defaultdict(list)
    for device in devices:
        site_groups[device["site_id"]].append(device)

    sites = []
    for site_id, site_devices in sorted(site_groups.items()):
        counts = Counter(item["health_status"] for item in site_devices)
        site_findings = sum(item["summary"]["finding_count"] for item in site_devices)
        sites.append({
            "site_id": site_id,
            "router_count": len(site_devices),
            "status_counts": {
                status: counts.get(status, 0)
                for status in ("healthy", "degraded", "critical", "unknown")
            },
            "finding_count": site_findings,
            "average_health_score": round(
                sum(item["health_score"] for item in site_devices) / len(site_devices), 1
            ),
        })

    status_counts = Counter(item["health_status"] for item in devices)
    finding_counts = Counter()
    for device in devices:
        finding_counts["critical"] += device["summary"]["critical_count"]
        finding_counts["warning"] += device["summary"]["warning_count"]
        finding_counts["info"] += device["summary"]["info_count"]
    return {
        "status": "audited",
        "generated_at": now.isoformat(),
        "thresholds": {
            "snapshot_max_age_seconds": max_age,
            "weak_signal_dbm": weak_signal,
            "critical_signal_dbm": critical_signal,
            "cpu_warning_pct": 85,
            "cpu_critical_pct": 95,
            "memory_warning_pct": 90,
            "memory_critical_pct": 95,
        },
        "summary": {
            "router_count": len(devices),
            "site_count": len(sites),
            "healthy_count": status_counts["healthy"],
            "degraded_count": status_counts["degraded"],
            "critical_count": status_counts["critical"],
            "unknown_count": status_counts["unknown"],
            "finding_count": sum(item["summary"]["finding_count"] for item in devices),
            "critical_finding_count": finding_counts["critical"],
            "warning_finding_count": finding_counts["warning"],
            "average_health_score": round(sum(item["health_score"] for item in devices) / len(devices), 1),
        },
        "sites": sites,
        "routers": devices,
        "note": (
            "This audit reports only measured, allow-listed facts from the supplied normalised snapshots. "
            "Missing telemetry is labelled unknown rather than healthy; thresholds are screening defaults, "
            "not vendor SLAs or proof of root cause."
        ),
    }


FEATURE = {
    "id": "F175",
    "slug": "router_fleet_health_audit",
    "name": "Multi-vendor router fleet health audit",
    "category": "Router integrations",
    "description": (
        "Audit normalized OpenWrt, UniFi and MikroTik snapshots for stale data, measured resource "
        "pressure, down interfaces/radios, offline access points and weak client signals."
    ),
    "parameters": {
        "snapshots": "1 to 64 normalised router snapshots with router and site identifiers",
        "now": "timezone-aware ISO-8601 evaluation time",
        "max_age_seconds": "optional snapshot freshness threshold from 60 to 86400 seconds",
        "weak_signal_dbm": "optional weak-client signal threshold",
        "critical_signal_dbm": "optional critical-client signal threshold",
    },
    "run": run,
}
