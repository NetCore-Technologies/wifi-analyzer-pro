"""Compare normalised OpenWrt, UniFi and MikroTik router snapshots safely.

The comparison is deliberately schema-aware: only documented inventory and telemetry
fields can enter the report. Unknown input keys, secrets and raw configuration blobs are
never copied into the result.
"""
from __future__ import annotations

import json
import math
from datetime import datetime, timezone

MAX_INPUT_BYTES = 1024 * 1024
MAX_DETAIL_RECORDS = 200
MAX_SCALAR_STRING = 512

# Each section describes a stable identity and the only fields permitted in a diff.
SCHEMAS = {
    "openwrt": {
        "metadata": {
            "board": ("distribution", "version", "target", "subtarget", "model", "board_name", "revision"),
            "system_health": ("uptime_seconds", "load_average_1m", "load_average_5m", "load_average_15m",
                              "memory_total_bytes", "memory_free_bytes", "memory_available_bytes",
                              "swap_total_bytes", "swap_free_bytes"),
        },
        "collections": {
            "interfaces": (("interface",), (
                "interface", "device", "protocol", "up", "ipv4_addresses", "ipv6_addresses",
            ), 256),
            "wireless_radios": (("interface",), (
                "interface", "ssid", "bssid", "band", "channel", "frequency_mhz",
                "channel_width_mhz", "tx_power_dbm", "signal_dbm", "noise_dbm", "security", "up",
            ), 256),
            "associations": (("interface", "client_mac"), (
                "interface", "client_mac", "signal_dbm", "tx_rate_mbps", "rx_rate_mbps",
            ), 8192),
            "routes": (("target", "device", "metric"), (
                "target", "gateway", "device", "metric",
            ), 2048),
        },
    },
    "unifi": {
        "metadata": {
            "controller": ("model", "version", "hostname"),
        },
        "collections": {
            "access_points": (("mac",), (
                "id", "mac", "name", "model", "ip_address", "status", "adopted",
                "radio_count", "associated_client_count",
            ), 1024),
            "wireless_radios": (("ap_mac", "radio"), (
                "ap_mac", "radio", "band", "bssid", "channel", "channel_width_mhz",
                "frequency_mhz", "tx_power_dbm", "up",
            ), 8192),
            "associations": (("client_mac",), (
                "client_mac", "ap_mac", "ap_known", "hostname", "ip_address", "ssid",
                "signal_dbm", "channel", "is_wired", "tx_bytes", "rx_bytes",
            ), 8192),
            "networks": (("id",), (
                "id", "name", "purpose", "enabled", "vlan_enabled", "vlan_id", "ip_subnet",
            ), 1024),
        },
    },
    "mikrotik": {
        "metadata": {
            "router": ("board_name", "model", "version", "architecture", "serial_number"),
            "resource": ("uptime", "cpu_load_pct", "free_memory_bytes", "total_memory_bytes"),
        },
        "collections": {
            "interfaces": (("name",), (
                "name", "type", "mac_address", "mtu", "actual_mtu", "running", "disabled", "state",
            ), 512),
            "wireless_radios": (("interface",), (
                "interface", "ssid", "band", "channel", "frequency_mhz", "channel_width_mhz",
                "channel_width_setting", "tx_power_dbm", "bssid", "state",
            ), 128),
            "associations": (("client_mac", "interface"), (
                "client_mac", "interface", "interface_known", "signal_dbm", "tx_rate", "rx_rate", "uptime",
            ), 8192),
            "addresses": (("interface", "address", "prefix_length"), (
                "interface", "address", "prefix_length", "network", "version", "interface_known",
            ), 2048),
            "vlans": (("name", "interface", "vlan_id"), (
                "name", "interface", "interface_known", "vlan_id", "running",
            ), 1024),
            "dhcp_leases": (("mac_address", "address"), (
                "mac_address", "address", "host_name", "status", "expires_after",
            ), 8192),
        },
    },
}


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


def _entry(value: object, field: str) -> tuple[dict, str]:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be a snapshot object")
    snapshot = value.get("snapshot", value)
    if not isinstance(snapshot, dict):
        raise ValueError(f"{field}.snapshot must be an object")
    adapter_id = snapshot.get("adapter_id")
    if adapter_id not in SCHEMAS:
        raise ValueError(f"{field} must use a supported normalised adapter (openwrt, unifi, mikrotik)")
    return snapshot, adapter_id


def _safe_value(value: object, field: str):
    """Keep only bounded JSON scalar values and lists of bounded scalars."""
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        if len(value) > MAX_SCALAR_STRING:
            raise ValueError(f"{field} exceeds the {MAX_SCALAR_STRING}-character limit")
        return value
    if isinstance(value, int):
        if not -(2**63) <= value <= 2**63 - 1:
            raise ValueError(f"{field} is outside the supported integer range")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{field} must be finite")
        return value
    if isinstance(value, list):
        if len(value) > 128:
            raise ValueError(f"{field} contains too many values")
        safe = []
        for index, item in enumerate(value):
            if item is None or isinstance(item, (str, bool, int, float)):
                safe.append(_safe_value(item, f"{field}[{index}]"))
            else:
                raise ValueError(f"{field} may contain only scalar values")
        return safe
    # Nested objects are intentionally omitted rather than echoed into a report.
    return _OMIT


class _Omit:
    pass


_OMIT = _Omit()


def _project(record: dict, fields: tuple[str, ...], field: str) -> dict:
    result = {}
    for name in fields:
        if name not in record:
            continue
        value = _safe_value(record[name], f"{field}.{name}")
        if value is not _OMIT:
            result[name] = value
    return result


def _records(snapshot: dict, name: str, spec: tuple, adapter: str) -> list[dict]:
    identity_fields, allowed_fields, maximum = spec
    records = snapshot.get(name, [])
    if not isinstance(records, list) or len(records) > maximum:
        raise ValueError(f"{adapter}.{name} must be a list containing no more than {maximum} records")
    result = []
    seen = set()
    for index, raw in enumerate(records):
        if not isinstance(raw, dict):
            raise ValueError(f"{adapter}.{name}[{index}] must be an object")
        projected = _project(raw, allowed_fields, f"{adapter}.{name}[{index}]")
        identity_values = []
        if adapter == "unifi" and name == "networks" and not projected.get("id"):
            identity_values = [projected.get("name")]
        else:
            identity_values = [projected.get(key) for key in identity_fields]
        if any(value is None or value == "" for value in identity_values):
            raise ValueError(f"{adapter}.{name}[{index}] is missing a stable identity field")
        identity_key = json.dumps(identity_values, ensure_ascii=False, separators=(",", ":"))
        if identity_key in seen:
            raise ValueError(f"{adapter}.{name} contains duplicate identities")
        seen.add(identity_key)
        if adapter == "unifi" and name == "networks" and not projected.get("id"):
            projected["id"] = None
        result.append(projected)
    return result


def _metadata(snapshot: dict, adapter: str, section: str, fields: tuple[str, ...]) -> dict:
    raw = snapshot.get(section, {})
    if not isinstance(raw, dict):
        raise ValueError(f"{adapter}.{section} must be an object")
    if adapter == "openwrt" and section == "system_health":
        load = raw.get("load_average", {})
        memory = raw.get("memory_bytes", {})
        swap = raw.get("swap_bytes", {})
        for name, value in (("load_average", load), ("memory_bytes", memory), ("swap_bytes", swap)):
            if not isinstance(value, dict):
                raise ValueError(f"{adapter}.system_health.{name} must be an object")
        flattened = {
            "uptime_seconds": raw.get("uptime_seconds"),
            "load_average_1m": load.get("1m"),
            "load_average_5m": load.get("5m"),
            "load_average_15m": load.get("15m"),
            "memory_total_bytes": memory.get("total"),
            "memory_free_bytes": memory.get("free"),
            "memory_available_bytes": memory.get("available"),
            "swap_total_bytes": swap.get("total"),
            "swap_free_bytes": swap.get("free"),
        }
        return _project(flattened, fields, f"{adapter}.{section}")
    return _project(raw, fields, f"{adapter}.{section}")


def _metadata_diff(before: dict, after: dict) -> list[dict]:
    changed = []
    for field in sorted(before.keys() | after.keys()):
        if before.get(field) != after.get(field):
            changed.append({
                "field": field,
                "previous": before.get(field),
                "current": after.get(field),
            })
    return changed


def _collection_diff(previous: list[dict], current: list[dict], identity_fields: tuple[str, ...]) -> dict:
    def index(records: list[dict]) -> dict[str, dict]:
        result = {}
        for record in records:
            identity_values = (
                [record.get("name")] if identity_fields == ("id",) and not record.get("id")
                else [record.get(field) for field in identity_fields]
            )
            key = json.dumps(identity_values, ensure_ascii=False, separators=(",", ":"))
            result[key] = record
        return result

    before = index(previous)
    after = index(current)
    added_keys = sorted(after.keys() - before.keys())
    removed_keys = sorted(before.keys() - after.keys())
    changed = []
    for key in sorted(before.keys() & after.keys()):
        old, new = before[key], after[key]
        fields = sorted(name for name in old.keys() | new.keys() if old.get(name) != new.get(name))
        if fields:
            identity = {
                name: new.get(name)
                for name in identity_fields
                if name in new
            }
            if identity_fields == ("id",) and not identity.get("id"):
                identity = {"name": new.get("name")}
            changed.append({
                "identity": identity,
                "changed_fields": [
                    {"field": name, "previous": old.get(name), "current": new.get(name)}
                    for name in fields
                ],
            })
    return {
        "added_count": len(added_keys),
        "removed_count": len(removed_keys),
        "changed_count": len(changed),
        "added": [after[key] for key in added_keys[:MAX_DETAIL_RECORDS]],
        "removed": [before[key] for key in removed_keys[:MAX_DETAIL_RECORDS]],
        "changed": changed[:MAX_DETAIL_RECORDS],
        "details_truncated": (
            len(added_keys) > MAX_DETAIL_RECORDS
            or len(removed_keys) > MAX_DETAIL_RECORDS
            or len(changed) > MAX_DETAIL_RECORDS
        ),
    }


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    try:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError("snapshot diff input must contain JSON-compatible finite values") from error
    if len(encoded.encode("utf-8")) > MAX_INPUT_BYTES:
        raise ValueError(f"snapshot diff input exceeds the {MAX_INPUT_BYTES}-byte input limit")

    current_entry = payload.get("current")
    current, adapter = _entry(current_entry, "current")
    schema = SCHEMAS[adapter]
    current_at = _timestamp(
        payload.get("current_captured_at", current_entry.get("captured_at") or current.get("captured_at")),
        "current_captured_at",
    )

    previous_entry = payload.get("previous")
    previous = None
    previous_at = None
    if previous_entry is not None:
        previous, previous_adapter = _entry(previous_entry, "previous")
        if previous_adapter != adapter:
            raise ValueError("previous and current snapshots must use the same adapter")
        previous_at = _timestamp(
            payload.get("previous_captured_at", previous_entry.get("captured_at") or previous.get("captured_at")),
            "previous_captured_at",
        )
        if datetime.fromisoformat(previous_at) >= datetime.fromisoformat(current_at):
            raise ValueError("snapshot timestamps must be strictly increasing")

    metadata_changes = {}
    for section, fields in schema["metadata"].items():
        current_meta = _metadata(current, adapter, section, fields)
        previous_meta = _metadata(previous, adapter, section, fields) if previous else {}
        metadata_changes[section] = _metadata_diff(previous_meta, current_meta) if previous else []

    changes = {}
    summary = {}
    for section, spec in schema["collections"].items():
        current_records = _records(current, section, spec, adapter)
        previous_records = _records(previous, section, spec, adapter) if previous else []
        diff = _collection_diff(previous_records, current_records, spec[0]) if previous else {
            "added_count": 0, "removed_count": 0, "changed_count": 0,
            "added": [], "removed": [], "changed": [], "details_truncated": False,
        }
        if previous is None:
            diff["baseline_count"] = len(current_records)
        changes[section] = diff
        summary[f"{section}_added"] = diff["added_count"]
        summary[f"{section}_removed"] = diff["removed_count"]
        summary[f"{section}_changed"] = diff["changed_count"]
        summary[f"{section}_baseline"] = len(current_records) if previous is None else 0

    summary["metadata_changed_field_count"] = sum(len(items) for items in metadata_changes.values())
    summary["total_changes"] = sum(
        value for key, value in summary.items()
        if key.endswith(("_added", "_removed", "_changed"))
    ) + summary["metadata_changed_field_count"]

    return {
        "status": "compared" if previous else "initial_snapshot",
        "adapter_id": adapter,
        "previous_snapshot_id": previous_entry.get("id", previous_entry.get("snapshot_id")) if previous_entry else None,
        "current_snapshot_id": current_entry.get("id", current_entry.get("snapshot_id")),
        "previous_captured_at": previous_at,
        "current_captured_at": current_at,
        "summary": summary,
        "metadata_changes": metadata_changes,
        "changes": changes,
        "note": (
            "This report compares only allow-listed, normalised router inventory and telemetry fields. "
            "Unknown fields and credential-like data are not copied into the report. A difference does "
            "not establish who made a change or whether it was authorised."
        ),
    }


FEATURE = {
    "id": "F174",
    "slug": "router_snapshot_drift_report",
    "name": "Multi-vendor router snapshot drift report",
    "category": "Router integrations",
    "description": (
        "Compare two normalised OpenWrt, UniFi or MikroTik snapshots and report bounded changes "
        "to router metadata, interfaces, radios, client associations, routes and network services."
    ),
    "parameters": {
        "previous": "optional prior normalised router snapshot",
        "current": "current normalised router snapshot",
    },
    "run": run,
}
