"""Report topology drift within sites and inventory contrasts across sites."""
from __future__ import annotations

import re
from collections import Counter

from .feature_150_site_topology_snapshot_diff import run as compare_topology

MAX_SITES = 20
MAX_ACCESS_POINTS_PER_SITE = 4096
MAX_LINKS_PER_SITE = 8192
BSSID_PATTERN = re.compile(r"^[0-9A-F]{2}(?::[0-9A-F]{2}){5}$")


def _snapshot(value: object, site_id: str, field: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{field} snapshot must be an object")
    if value.get("site_id") != site_id:
        raise ValueError(f"{field} snapshot site_id must match its site record")
    access_points = value.get("access_points", [])
    links = value.get("links", [])
    if not isinstance(access_points, list) or len(access_points) > MAX_ACCESS_POINTS_PER_SITE:
        raise ValueError(f"{field}.access_points must be a list of no more than {MAX_ACCESS_POINTS_PER_SITE} records")
    if not isinstance(links, list) or len(links) > MAX_LINKS_PER_SITE:
        raise ValueError(f"{field}.links must be a list of no more than {MAX_LINKS_PER_SITE} records")
    for index, ap in enumerate(access_points):
        if not isinstance(ap, dict):
            raise ValueError(f"{field}.access_points[{index}] must be an object")
        if ap.get("site_id") not in (None, site_id):
            raise ValueError(f"{field}.access_points[{index}] belongs to a different site")
    return value


def _profile(records: list[dict]) -> dict:
    counters = {key: Counter() for key in ("bands", "vendors", "models", "firmware_versions")}
    missing = {key: 0 for key in ("band", "vendor", "model", "firmware_version")}
    for ap in records:
        for field, key in (
            ("band", "bands"), ("vendor", "vendors"),
            ("model", "models"), ("firmware_version", "firmware_versions"),
        ):
            value = str(ap.get(field) or "").strip()
            if value:
                counters[key][value] += 1
            else:
                missing[field] += 1
    return {
        **{key: dict(sorted(counter.items())) for key, counter in counters.items()},
        "missing_metadata_counts": missing,
    }


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    sites = payload.get("sites", [])
    if not isinstance(sites, list) or len(sites) > MAX_SITES:
        raise ValueError(f"sites must be a list containing no more than {MAX_SITES} sites")
    seen_sites = set()
    reports = []
    bssid_sites = {}
    invalid_bssid_count = 0
    totals = Counter()

    for index, site in enumerate(sites):
        if not isinstance(site, dict):
            raise ValueError(f"sites[{index}] must be an object")
        site_id = site.get("site_id")
        if not isinstance(site_id, str) or not site_id.strip() or len(site_id) > 128:
            raise ValueError(f"sites[{index}].site_id must contain 1 to 128 characters")
        site_id = site_id.strip()
        if site_id in seen_sites:
            raise ValueError("site_id values must be unique")
        seen_sites.add(site_id)
        current_entry = site.get("current")
        if not isinstance(current_entry, dict):
            raise ValueError(f"sites[{index}].current must be a snapshot object")
        current_snapshot = _snapshot(current_entry.get("snapshot", current_entry), site_id, f"sites[{index}].current")
        previous_entry = site.get("previous")
        previous_snapshot = None
        if previous_entry is not None:
            if not isinstance(previous_entry, dict):
                raise ValueError(f"sites[{index}].previous must be a snapshot object or null")
            previous_snapshot = _snapshot(previous_entry.get("snapshot", previous_entry), site_id, f"sites[{index}].previous")

        topology_changes = None
        baseline_status = "initial_snapshot"
        if previous_snapshot is not None:
            topology_changes = compare_topology({
                "previous": {
                    "access_points": previous_snapshot.get("access_points", []),
                    "links": previous_snapshot.get("links", []),
                },
                "current": {
                    "access_points": current_snapshot.get("access_points", []),
                    "links": current_snapshot.get("links", []),
                },
            })
            baseline_status = "compared"

        current_aps = current_snapshot.get("access_points", [])
        profile = _profile(current_aps)
        for ap in current_aps:
            bssid = str(ap.get("bssid") or "").replace("-", ":").upper()
            if not bssid:
                continue
            if not BSSID_PATTERN.fullmatch(bssid):
                invalid_bssid_count += 1
                continue
            bssid_sites.setdefault(bssid, set()).add(site_id)

        added = len(topology_changes["added_access_points"]) if topology_changes else 0
        removed = len(topology_changes["removed_access_points"]) if topology_changes else 0
        changed = len(topology_changes["changed_access_points"]) if topology_changes else 0
        added_links = topology_changes["added_link_count"] if topology_changes else 0
        removed_links = topology_changes["removed_link_count"] if topology_changes else 0
        totals.update({
            "added_access_points": added,
            "removed_access_points": removed,
            "changed_access_points": changed,
            "added_links": added_links,
            "removed_links": removed_links,
        })
        reports.append({
            "site_id": site_id,
            "baseline_status": baseline_status,
            "previous_snapshot_id": previous_entry.get("snapshot_id") if previous_entry else None,
            "current_snapshot_id": current_entry.get("snapshot_id"),
            "previous_captured_at": previous_entry.get("captured_at") if previous_entry else None,
            "current_captured_at": current_entry.get("captured_at") or current_snapshot.get("captured_at"),
            "current_access_point_count": len(current_aps),
            "current_link_count": len(current_snapshot.get("links", [])),
            "profile": profile,
            "changes": topology_changes,
            "change_counts": {
                "added_access_points": added,
                "removed_access_points": removed,
                "changed_access_points": changed,
                "added_links": added_links,
                "removed_links": removed_links,
            },
        })

    collisions = [
        {"bssid": bssid, "site_ids": sorted(site_ids)}
        for bssid, site_ids in sorted(bssid_sites.items()) if len(site_ids) > 1
    ]
    reports.sort(key=lambda item: item["site_id"])
    return {
        "summary": {
            "site_count": len(reports),
            "sites_with_baseline": sum(item["baseline_status"] == "compared" for item in reports),
            "sites_without_baseline": sum(item["baseline_status"] == "initial_snapshot" for item in reports),
            "current_access_point_count": sum(item["current_access_point_count"] for item in reports),
            "added_access_point_count": totals["added_access_points"],
            "removed_access_point_count": totals["removed_access_points"],
            "changed_access_point_count": totals["changed_access_points"],
            "added_link_count": totals["added_links"],
            "removed_link_count": totals["removed_links"],
            "cross_site_bssid_collision_count": len(collisions),
            "invalid_bssid_count": invalid_bssid_count,
        },
        "sites": reports,
        "cross_site_bssid_collisions": collisions,
        "note": (
            "Only stored, caller-supplied snapshots are compared. The report identifies inventory/topology "
            "differences and repeated BSSIDs across sites; it does not establish that a change is unauthorised "
            "or that any device is currently online."
        ),
    }


FEATURE = {
    "id": "F159",
    "slug": "site_to_site_change_report",
    "name": "Site-to-site change report",
    "category": "Site inventory",
    "description": "Compare the latest two stored snapshots per site, summarise AP and topology drift, compare site radio/vendor profiles and flag cross-site BSSID reuse.",
    "parameters": {"sites": "site_snapshot_pair[]"},
    "run": run,
}
