"""Compare recent normalised OpenWrt snapshots without exposing raw router payloads."""
from __future__ import annotations

import json
from datetime import datetime, timezone


MAX_INTERFACES = 256
MAX_RADIOS = 256
MAX_ASSOCIATIONS = 8192
MAX_ROUTES = 2048
MAX_DETAIL_RECORDS = 500


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


def _snapshot(entry: object, field: str) -> dict:
    if not isinstance(entry, dict):
        raise ValueError(f"{field} must be a snapshot object")
    snapshot = entry.get("snapshot", entry)
    if not isinstance(snapshot, dict) or snapshot.get("adapter_id") != "openwrt":
        raise ValueError(f"{field} must be a normalised OpenWrt snapshot")
    return snapshot


def _records(snapshot: dict, section: str, limit: int) -> list[dict]:
    records = snapshot.get(section, [])
    if not isinstance(records, list) or len(records) > limit:
        raise ValueError(f"{section} must be a list containing no more than {limit} records")
    if any(not isinstance(record, dict) for record in records):
        raise ValueError(f"{section} entries must be objects")
    return records


def _empty_diff() -> dict:
    return {
        "added_count": 0,
        "removed_count": 0,
        "changed_count": 0,
        "added": [],
        "removed": [],
        "changed": [],
        "details_truncated": False,
    }


def _collection_diff(previous: list[dict], current: list[dict], identity_fields: tuple[str, ...], section: str) -> dict:
    def index(records, name):
        result = {}
        for position, record in enumerate(records):
            if any(field not in record for field in identity_fields):
                raise ValueError(f"{name}[{position}] is missing a stable identity field")
            identity = tuple(record[field] for field in identity_fields)
            if any(isinstance(value, (dict, list)) for value in identity):
                raise ValueError(f"{name}[{position}] identity fields must be scalar values")
            key = json.dumps(identity, ensure_ascii=False, separators=(",", ":"))
            if key in result:
                raise ValueError(f"{section} contains duplicate identities")
            result[key] = record
        return result

    before = index(previous, "previous records")
    after = index(current, "current records")
    added_keys = sorted(after.keys() - before.keys())
    removed_keys = sorted(before.keys() - after.keys())
    shared_keys = sorted(before.keys() & after.keys())
    changed = []
    for key in shared_keys:
        old = before[key]
        new = after[key]
        fields = sorted(field for field in old.keys() | new.keys() if old.get(field) != new.get(field))
        if fields:
            changed.append({
                "identity": {name: new.get(name) for name in identity_fields},
                "changed_fields": [
                    {"field": field, "previous": old.get(field), "current": new.get(field)}
                    for field in fields
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
    current_entry = payload.get("current")
    current = _snapshot(current_entry, "current")
    current_at = _timestamp(
        payload.get("current_captured_at", current_entry.get("captured_at") or current.get("captured_at")),
        "current_captured_at",
    )
    previous_entry = payload.get("previous")
    previous = None if previous_entry is None else _snapshot(previous_entry, "previous")
    previous_at = None
    if previous_entry is not None:
        previous_at = _timestamp(
            payload.get("previous_captured_at", previous_entry.get("captured_at") or previous.get("captured_at")),
            "previous_captured_at",
        )
        if datetime.fromisoformat(previous_at) >= datetime.fromisoformat(current_at):
            raise ValueError("snapshot timestamps must be strictly increasing")

    current_interfaces = _records(current, "interfaces", MAX_INTERFACES)
    current_radios = _records(current, "wireless_radios", MAX_RADIOS)
    current_associations = _records(current, "associations", MAX_ASSOCIATIONS)
    current_routes = _records(current, "routes", MAX_ROUTES)
    before_interfaces = _records(previous, "interfaces", MAX_INTERFACES) if previous else []
    before_radios = _records(previous, "wireless_radios", MAX_RADIOS) if previous else []
    before_associations = _records(previous, "associations", MAX_ASSOCIATIONS) if previous else []
    before_routes = _records(previous, "routes", MAX_ROUTES) if previous else []

    board_changes = []
    old_board = previous.get("board", {}) if previous else {}
    new_board = current.get("board", {})
    if not isinstance(old_board, dict) or not isinstance(new_board, dict):
        raise ValueError("snapshot board sections must be objects")
    if previous:
        for field in sorted(old_board.keys() | new_board.keys()):
            if old_board.get(field) != new_board.get(field):
                board_changes.append({
                    "field": field,
                    "previous": old_board.get(field),
                    "current": new_board.get(field),
                })

    if previous:
        changes = {
            "interfaces": _collection_diff(before_interfaces, current_interfaces, ("interface",), "interfaces"),
            "wireless_radios": _collection_diff(before_radios, current_radios, ("interface",), "wireless_radios"),
            "associations": _collection_diff(before_associations, current_associations, ("interface", "client_mac"), "associations"),
            "routes": _collection_diff(before_routes, current_routes, ("target", "device", "metric"), "routes"),
        }
    else:
        # Validate stable identities even for the first baseline. A baseline is not a
        # diff, but it must not silently accept duplicate interfaces/radios/routes.
        _collection_diff(current_interfaces, current_interfaces, ("interface",), "interfaces")
        _collection_diff(current_radios, current_radios, ("interface",), "wireless_radios")
        _collection_diff(current_associations, current_associations, ("interface", "client_mac"), "associations")
        _collection_diff(current_routes, current_routes, ("target", "device", "metric"), "routes")
        changes = {
            "interfaces": _empty_diff(),
            "wireless_radios": _empty_diff(),
            "associations": _empty_diff(),
            "routes": _empty_diff(),
        }

    summary = {
        "interface_added": changes["interfaces"]["added_count"],
        "interface_removed": changes["interfaces"]["removed_count"],
        "interface_changed": changes["interfaces"]["changed_count"],
        "radio_added": changes["wireless_radios"]["added_count"],
        "radio_removed": changes["wireless_radios"]["removed_count"],
        "radio_changed": changes["wireless_radios"]["changed_count"],
        "association_added": changes["associations"]["added_count"],
        "association_removed": changes["associations"]["removed_count"],
        "association_changed": changes["associations"]["changed_count"],
        "route_added": changes["routes"]["added_count"],
        "route_removed": changes["routes"]["removed_count"],
        "route_changed": changes["routes"]["changed_count"],
        "board_changed_field_count": len(board_changes),
    }
    summary["total_changes"] = sum(summary.values())
    return {
        "status": "compared" if previous else "initial_snapshot",
        "previous_snapshot_id": previous_entry.get("id", previous_entry.get("snapshot_id")) if previous_entry else None,
        "current_snapshot_id": current_entry.get("id", current_entry.get("snapshot_id")),
        "previous_captured_at": previous_at,
        "current_captured_at": current_at,
        "summary": summary,
        "board_changes": board_changes,
        "changes": changes,
        "note": (
            "This report compares only retained, credential-free OpenWrt snapshots. A changed field identifies "
            "a difference between captures; it does not establish who made the change or whether it was authorised."
        ),
    }


FEATURE = {
    "id": "F165",
    "slug": "openwrt_agent_snapshot_diff",
    "name": "OpenWrt agent snapshot diff",
    "category": "Router integrations",
    "description": "Compare the two most recent retained OpenWrt snapshots and report board, interface, radio, client-association and route drift with bounded detail.",
    "parameters": {"previous": "normalised_snapshot|null", "current": "normalised_snapshot"},
    "run": run,
}
