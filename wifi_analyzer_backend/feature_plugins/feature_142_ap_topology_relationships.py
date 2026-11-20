"""AP topology relationships from explicit controller, LLDP or mesh observations.

Only supplied relationships are represented. RF-neighbour observations are
kept separate from physical/backhaul links; no topology is inferred.
"""
from __future__ import annotations

from collections import defaultdict


RELATIONSHIPS = {
    "wired_uplink",
    "wireless_backhaul",
    "mesh_backhaul",
    "rf_neighbor",
}
PHYSICAL_RELATIONSHIPS = {"wired_uplink", "wireless_backhaul", "mesh_backhaul"}


def _identifier(value: object, field: str) -> str:
    result = str(value or "").strip()
    if not result or len(result) > 128:
        raise ValueError(f"{field} must be a non-empty identifier up to 128 characters")
    return result


def run(payload: dict) -> dict:
    access_points = payload.get("access_points", [])
    links = payload.get("links", [])
    if not isinstance(access_points, list) or not isinstance(links, list):
        raise ValueError("access_points and links must be lists")
    if len(access_points) > 2048 or len(links) > 8192:
        raise ValueError("topology snapshot exceeds the supported record limit")

    aps = {}
    for ap in access_points:
        if not isinstance(ap, dict):
            raise ValueError("Each access point must be an object")
        ap_id = _identifier(ap.get("ap_id"), "ap_id")
        if ap_id in aps:
            raise ValueError("AP identifiers must be unique")
        aps[ap_id] = {
            "ap_id": ap_id,
            "name": str(ap.get("name") or ap_id),
            "site_id": str(ap.get("site_id") or "unassigned"),
            "bssid": ap.get("bssid"),
        }

    seen = set()
    duplicate_links = []
    unresolved_links = []
    normalized_links = []
    by_type = {}
    degree = {ap_id: 0 for ap_id in aps}
    physical_parent = {}
    parent_cycles = []

    for index, link in enumerate(links):
        if not isinstance(link, dict):
            raise ValueError("Each topology link must be an object")
        source = _identifier(link.get("from_ap_id"), "from_ap_id")
        target = _identifier(link.get("to_ap_id"), "to_ap_id")
        relationship = str(link.get("relationship") or "").strip().lower()
        if relationship not in RELATIONSHIPS:
            raise ValueError(f"relationship must be one of {sorted(RELATIONSHIPS)}")
        if source == target:
            raise ValueError("A topology link cannot connect an AP to itself")

        key = (source, target, relationship)
        if key in seen:
            duplicate_links.append({
                "from_ap_id": source, "to_ap_id": target,
                "relationship": relationship, "link_index": index,
            })
        else:
            seen.add(key)

        missing = [ap_id for ap_id in (source, target) if ap_id not in aps]
        if missing:
            unresolved_links.append({
                "from_ap_id": source, "to_ap_id": target,
                "relationship": relationship, "missing_ap_ids": missing,
                "link_index": index,
            })
            continue

        record = {
            "from_ap_id": source,
            "to_ap_id": target,
            "relationship": relationship,
            "source": str(link.get("source") or "operator_supplied"),
            "observed_at": link.get("observed_at"),
        }
        normalized_links.append(record)
        by_type[relationship] = by_type.get(relationship, 0) + 1
        degree[source] += 1
        degree[target] += 1
        if relationship == "wired_uplink":
            previous = physical_parent.get(source)
            if previous is None:
                physical_parent[source] = target

    # Detect cycles only in the explicitly directed wired-uplink parent map.
    for start in sorted(physical_parent):
        path = []
        positions = {}
        node = start
        while node in physical_parent:
            if node in positions:
                cycle = path[positions[node]:]
                canonical = tuple(sorted(cycle))
                if canonical not in parent_cycles:
                    parent_cycles.append(canonical)
                break
            positions[node] = len(path)
            path.append(node)
            node = physical_parent[node]

    cycle_results = [
        {"ap_ids": list(cycle), "relationship": "wired_uplink"}
        for cycle in sorted(parent_cycles)
    ]
    physical_degree = {ap_id: 0 for ap_id in aps}
    for item in normalized_links:
        if item["relationship"] in PHYSICAL_RELATIONSHIPS:
            physical_degree[item["from_ap_id"]] += 1
            physical_degree[item["to_ap_id"]] += 1

    return {
        "access_point_count": len(aps),
        "reported_link_count": len(links),
        "resolved_link_count": len(normalized_links),
        "unresolved_link_count": len(unresolved_links),
        "duplicate_link_count": len(duplicate_links),
        "links_by_relationship": dict(sorted(by_type.items())),
        "access_point_degrees": [
            {"ap_id": ap_id, "name": ap["name"], "site_id": ap["site_id"],
             "reported_degree": degree[ap_id], "physical_degree": physical_degree[ap_id]}
            for ap_id, ap in sorted(aps.items())
        ],
        "isolated_access_points": sorted(ap_id for ap_id, count in physical_degree.items() if count == 0),
        "unresolved_links": unresolved_links,
        "duplicate_links": duplicate_links,
        "wired_uplink_cycles": cycle_results,
        "links": normalized_links,
        "note": (
            "Topology is a summary of supplied LLDP/controller/mesh records. "
            "RF-neighbour links are not treated as wired or backhaul connectivity, "
            "and missing endpoints are retained as unresolved evidence."
        ),
    }


FEATURE = {
    "id": "F142",
    "slug": "ap_topology_relationships",
    "name": "Access-point topology relationships",
    "category": "Site inventory",
    "description": "Build an evidence-only AP relationship view, separate RF neighbours from backhaul links, and flag unresolved or cyclic uplinks.",
    "parameters": {"access_points": "access_point[]", "links": "link[]"},
    "run": run,
}
