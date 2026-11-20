"""Compare explicit site topology snapshots for AP and relationship changes."""
from __future__ import annotations

import re


RELATIONSHIPS = {"wired_uplink", "wireless_backhaul", "mesh_backhaul", "rf_neighbor"}
AP_FIELDS = ("site_id", "name", "bssid", "management_ip")


def _ap_index(records: object, field: str) -> dict[str, dict]:
    if not isinstance(records, list):
        raise ValueError(f"{field}.access_points must be a list")
    result = {}
    for ap in records:
        if not isinstance(ap, dict) or not ap.get("ap_id"):
            raise ValueError(f"Each {field} AP needs ap_id")
        ap_id = str(ap["ap_id"]).strip()
        if not ap_id or ap_id in result:
            raise ValueError(f"{field} AP identifiers must be unique and non-empty")
        result[ap_id] = {key: ap.get(key) for key in AP_FIELDS}
    return result


def _link_index(records: object, field: str) -> dict[tuple[str, str, str], dict]:
    if not isinstance(records, list):
        raise ValueError(f"{field}.links must be a list")
    result = {}
    for link in records:
        if not isinstance(link, dict):
            raise ValueError(f"Each {field} link must be an object")
        source = str(link.get("from_ap_id") or "").strip()
        target = str(link.get("to_ap_id") or "").strip()
        relationship = str(link.get("relationship") or "").strip().lower()
        if not source or not target or source == target:
            raise ValueError("Topology links need two different AP identifiers")
        if relationship not in RELATIONSHIPS:
            raise ValueError(f"relationship must be one of {sorted(RELATIONSHIPS)}")
        left, right = sorted((source, target))
        key = (left, right, relationship)
        if key in result:
            raise ValueError(f"Duplicate link in {field} snapshot")
        result[key] = {
            "from_ap_id": left,
            "to_ap_id": right,
            "relationship": relationship,
        }
    return result


def _snapshot(payload: object, field: str) -> tuple[dict, dict]:
    if not isinstance(payload, dict):
        raise ValueError(f"{field} snapshot must be an object")
    return (
        _ap_index(payload.get("access_points", []), field),
        _link_index(payload.get("links", []), field),
    )


def run(payload: dict) -> dict:
    previous_aps, previous_links = _snapshot(payload.get("previous", {}), "previous")
    current_aps, current_links = _snapshot(payload.get("current", {}), "current")

    old_ap_ids, new_ap_ids = set(previous_aps), set(current_aps)
    added_ap_ids = sorted(new_ap_ids - old_ap_ids)
    removed_ap_ids = sorted(old_ap_ids - new_ap_ids)
    changed_aps = []
    unchanged_ap_count = 0
    for ap_id in sorted(old_ap_ids & new_ap_ids):
        changes = [
            {"field": field, "previous": previous_aps[ap_id][field], "current": current_aps[ap_id][field]}
            for field in AP_FIELDS if previous_aps[ap_id][field] != current_aps[ap_id][field]
        ]
        if changes:
            changed_aps.append({"ap_id": ap_id, "changes": changes})
        else:
            unchanged_ap_count += 1

    old_link_ids, new_link_ids = set(previous_links), set(current_links)
    added_link_ids = sorted(new_link_ids - old_link_ids)
    removed_link_ids = sorted(old_link_ids - new_link_ids)
    added_links = [current_links[key] for key in added_link_ids]
    removed_links = [previous_links[key] for key in removed_link_ids]

    return {
        "previous_access_point_count": len(previous_aps),
        "current_access_point_count": len(current_aps),
        "added_access_points": [{"ap_id": ap_id, **current_aps[ap_id]} for ap_id in added_ap_ids],
        "removed_access_points": [{"ap_id": ap_id, **previous_aps[ap_id]} for ap_id in removed_ap_ids],
        "changed_access_points": changed_aps,
        "unchanged_access_point_count": unchanged_ap_count,
        "added_links": added_links,
        "removed_links": removed_links,
        "added_link_count": len(added_links),
        "removed_link_count": len(removed_links),
        "topology_change_count": len(added_ap_ids) + len(removed_ap_ids) + len(changed_aps) + len(added_links) + len(removed_links),
        "note": (
            "Links are compared as undirected AP relationships with their relationship type retained. "
            "A change is a snapshot difference, not proof of an outage or unauthorised change."
        ),
    }


FEATURE = {
    "id": "F150",
    "slug": "site_topology_snapshot_diff",
    "name": "Site topology snapshot diff",
    "category": "Site inventory",
    "description": "Compare AP inventory and explicit physical/RF topology edges between two site snapshots.",
    "parameters": {"previous": "topology_snapshot", "current": "topology_snapshot"},
    "run": run,
}
