"""Compare two explicit AP inventory snapshots using BSSID as stable identity."""
from __future__ import annotations

import re


TRACKED_FIELDS = (
    "site_id", "name", "ssid", "vendor", "model", "band", "channel",
    "channel_width_mhz", "location", "management_ip",
)


def _bssid(value: object) -> str:
    normalised = str(value or "").replace("-", ":").upper()
    if not re.fullmatch(r"[0-9A-F]{2}(?::[0-9A-F]{2}){5}", normalised):
        raise ValueError("Each AP inventory record needs a valid BSSID")
    return normalised


def _index(records: object, field: str) -> dict[str, dict]:
    if not isinstance(records, list):
        raise ValueError(f"'{field}' must be a list")
    if len(records) > 4096:
        raise ValueError(f"'{field}' may contain no more than 4096 records")
    result = {}
    for record in records:
        if not isinstance(record, dict):
            raise ValueError(f"Each {field} record must be an object")
        identity = _bssid(record.get("bssid"))
        if identity in result:
            raise ValueError(f"Duplicate BSSID in {field} snapshot")
        result[identity] = {key: record.get(key) for key in TRACKED_FIELDS}
    return result


def run(payload: dict) -> dict:
    previous = _index(payload.get("previous", []), "previous")
    current = _index(payload.get("current", []), "current")
    previous_ids, current_ids = set(previous), set(current)
    added_ids = sorted(current_ids - previous_ids)
    removed_ids = sorted(previous_ids - current_ids)
    changed = []
    unchanged = 0
    site_moves = []

    for bssid in sorted(previous_ids & current_ids):
        before, after = previous[bssid], current[bssid]
        changes = [
            {"field": field, "previous": before[field], "current": after[field]}
            for field in TRACKED_FIELDS if before[field] != after[field]
        ]
        if changes:
            changed.append({"bssid": bssid, "changes": changes})
            if before["site_id"] != after["site_id"]:
                site_moves.append({
                    "bssid": bssid, "previous_site_id": before["site_id"],
                    "current_site_id": after["site_id"],
                })
        else:
            unchanged += 1

    return {
        "previous_count": len(previous),
        "current_count": len(current),
        "added": [{"bssid": bssid, **current[bssid]} for bssid in added_ids],
        "removed": [{"bssid": bssid, **previous[bssid]} for bssid in removed_ids],
        "changed": changed,
        "unchanged_count": unchanged,
        "site_moves": site_moves,
        "change_count": len(added_ids) + len(removed_ids) + len(changed),
        "note": (
            "Comparison uses BSSID as the stable key and only compares listed inventory fields. "
            "A missing field and an explicit null are treated as equivalent."
        ),
    }


FEATURE = {
    "id": "F145",
    "slug": "site_inventory_snapshot_diff",
    "name": "Site inventory snapshot diff",
    "category": "Site inventory",
    "description": "Compare AP inventory snapshots to identify additions, removals, metadata changes and site moves.",
    "parameters": {"previous": "access_point[]", "current": "access_point[]"},
    "run": run,
}
