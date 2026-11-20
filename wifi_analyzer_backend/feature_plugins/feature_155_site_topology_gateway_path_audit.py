"""Audit AP-to-gateway reachability from explicit site topology evidence."""
from __future__ import annotations

from collections import deque

from .feature_150_site_topology_snapshot_diff import run as validate_topology


MAX_ACCESS_POINTS = 4096
MAX_LINKS = 8192
MAX_GATEWAYS = 1024
PHYSICAL_RELATIONSHIPS = {"wired_uplink", "wireless_backhaul", "mesh_backhaul"}


def run(payload: dict) -> dict:
    access_points = payload.get("access_points", [])
    links = payload.get("links", [])
    gateway_ap_ids = payload.get("gateway_ap_ids", [])
    if not isinstance(access_points, list):
        raise ValueError("'access_points' must be a list")
    if not isinstance(links, list):
        raise ValueError("'links' must be a list")
    if not isinstance(gateway_ap_ids, list):
        raise ValueError("'gateway_ap_ids' must be a list")
    if len(access_points) > MAX_ACCESS_POINTS:
        raise ValueError(f"'access_points' may contain no more than {MAX_ACCESS_POINTS} records")
    if len(links) > MAX_LINKS:
        raise ValueError(f"'links' may contain no more than {MAX_LINKS} records")
    if len(gateway_ap_ids) > MAX_GATEWAYS:
        raise ValueError(f"'gateway_ap_ids' may contain no more than {MAX_GATEWAYS} records")

    # Reuse the topology snapshot validator for AP identifiers, link endpoints and relationship types.
    validate_topology({
        "previous": {"access_points": [], "links": []},
        "current": {"access_points": access_points, "links": links},
    })

    ap_index = {}
    for ap in access_points:
        ap_id = str(ap["ap_id"]).strip()
        site_id = str(ap.get("site_id") or "unassigned").strip() or "unassigned"
        ap_index[ap_id] = {"ap_id": ap_id, "site_id": site_id}

    gateway_ids = []
    gateway_seen = set()
    for value in gateway_ap_ids:
        gateway_id = str(value).strip()
        if not gateway_id:
            raise ValueError("gateway_ap_ids must contain non-empty AP identifiers")
        if gateway_id in gateway_seen:
            raise ValueError("gateway_ap_ids must be unique")
        gateway_seen.add(gateway_id)
        gateway_ids.append(gateway_id)

    unknown_gateways = sorted(gateway_seen - set(ap_index))
    roots_by_site = {}
    for gateway_id in gateway_seen & set(ap_index):
        site_id = ap_index[gateway_id]["site_id"]
        roots_by_site.setdefault(site_id, set()).add(gateway_id)

    adjacency = {ap_id: {} for ap_id in ap_index}
    excluded_rf = 0
    cross_site_links = []
    unresolved_links = []
    for link in links:
        source = str(link["from_ap_id"]).strip()
        target = str(link["to_ap_id"]).strip()
        relationship = str(link["relationship"]).strip().lower()
        if relationship == "rf_neighbor":
            excluded_rf += 1
            continue
        if source not in ap_index or target not in ap_index:
            unresolved_links.append({
                "from_ap_id": source,
                "to_ap_id": target,
                "relationship": relationship,
                "unknown_endpoints": sorted({endpoint for endpoint in (source, target) if endpoint not in ap_index}),
            })
            continue
        source_site = ap_index[source]["site_id"]
        target_site = ap_index[target]["site_id"]
        if source_site != target_site:
            cross_site_links.append({
                "from_ap_id": source,
                "to_ap_id": target,
                "relationship": relationship,
                "site_ids": sorted({source_site, target_site}),
            })
            continue
        adjacency[source].setdefault(target, set()).add(relationship)
        adjacency[target].setdefault(source, set()).add(relationship)

    paths_by_site = {}
    for site_id, site_aps in _group_by_site(ap_index).items():
        roots = sorted(roots_by_site.get(site_id, set()))
        if not roots:
            paths_by_site[site_id] = {}
            continue
        parent = {gateway_id: None for gateway_id in roots}
        parent_relationship = {}
        queue = deque(roots)
        while queue:
            current = queue.popleft()
            for neighbour in sorted(adjacency[current]):
                if neighbour in parent:
                    continue
                parent[neighbour] = current
                parent_relationship[neighbour] = sorted(adjacency[current][neighbour])[0]
                queue.append(neighbour)
        paths_by_site[site_id] = {
            ap_id: (parent, parent_relationship)
            for ap_id in site_aps
        }

    results = []
    for ap_id in sorted(ap_index):
        site_id = ap_index[ap_id]["site_id"]
        roots = sorted(roots_by_site.get(site_id, set()))
        if not roots:
            results.append({
                "ap_id": ap_id, "site_id": site_id, "status": "unknown",
                "gateway_ap_id": None, "hop_count": None,
                "path_ap_ids": None, "path_relationships": None,
            })
            continue
        parent, parent_relationship = paths_by_site[site_id][ap_id]
        if ap_id not in parent:
            results.append({
                "ap_id": ap_id, "site_id": site_id, "status": "unreachable",
                "gateway_ap_id": None, "hop_count": None,
                "path_ap_ids": None, "path_relationships": None,
            })
            continue
        path = [ap_id]
        path_relationships = []
        cursor = ap_id
        while parent[cursor] is not None:
            path_relationships.append(parent_relationship[cursor])
            cursor = parent[cursor]
            path.append(cursor)
        results.append({
            "ap_id": ap_id, "site_id": site_id, "status": "reachable",
            "gateway_ap_id": path[-1], "hop_count": len(path) - 1,
            "path_ap_ids": path, "path_relationships": path_relationships,
        })

    site_summaries = []
    for site_id in sorted({item["site_id"] for item in ap_index.values()}):
        members = [item for item in results if item["site_id"] == site_id]
        site_summaries.append({
            "site_id": site_id,
            "access_point_count": len(members),
            "gateway_ap_ids": sorted(roots_by_site.get(site_id, set())),
            "reachable_count": sum(item["status"] == "reachable" for item in members),
            "unreachable_count": sum(item["status"] == "unreachable" for item in members),
            "unknown_count": sum(item["status"] == "unknown" for item in members),
        })

    return {
        "summary": {
            "site_count": len(site_summaries),
            "access_point_count": len(results),
            "gateway_count": sum(len(roots) for roots in roots_by_site.values()),
            "reachable_count": sum(item["status"] == "reachable" for item in results),
            "unreachable_count": sum(item["status"] == "unreachable" for item in results),
            "unknown_count": sum(item["status"] == "unknown" for item in results),
            "excluded_rf_neighbor_link_count": excluded_rf,
            "excluded_cross_site_link_count": len(cross_site_links),
            "unresolved_link_count": len(unresolved_links),
            "unknown_gateway_ap_ids": unknown_gateways,
        },
        "sites": site_summaries,
        "access_points": results,
        "excluded_cross_site_links": cross_site_links,
        "unresolved_links": unresolved_links,
        "note": (
            "Reachability is computed only from supplied AP/link records. RF-neighbour and cross-site links are excluded. "
            "A site without a supplied gateway AP is unknown, not unreachable; this is not a live connectivity probe."
        ),
    }


def _group_by_site(ap_index: dict) -> dict:
    groups = {}
    for ap_id, ap in ap_index.items():
        groups.setdefault(ap["site_id"], []).append(ap_id)
    return groups


FEATURE = {
    "id": "F155",
    "slug": "site_topology_gateway_path_audit",
    "name": "Site AP-to-gateway path audit",
    "category": "Site inventory",
    "description": "Trace AP backhaul paths to supplied gateway APs and separate unreachable, unknown and cross-site topology evidence.",
    "parameters": {"access_points": "access_point[]", "links": "link[]", "gateway_ap_ids": "string[]"},
    "run": run,
}
