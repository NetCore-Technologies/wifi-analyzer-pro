"""Build a deterministic, site-aware visual layout from explicit AP topology."""
from __future__ import annotations

from collections import deque

from .feature_150_site_topology_snapshot_diff import run as validate_topology


MAX_ACCESS_POINTS = 512
MAX_LINKS = 1024
MAX_GATEWAYS = 512
PHYSICAL_RELATIONSHIPS = {"wired_uplink", "wireless_backhaul", "mesh_backhaul"}


def _record_id(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    value = value.strip()
    if not value or len(value) > 128:
        raise ValueError(f"{field} must contain 1 to 128 non-whitespace characters")
    return value


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
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

    # Keep topology semantics aligned with the canonical snapshot-diff tool.
    validate_topology({
        "previous": {"access_points": [], "links": []},
        "current": {"access_points": access_points, "links": links},
    })

    ap_index = {}
    for index, ap in enumerate(access_points):
        ap_id = _record_id(ap.get("ap_id"), f"access_points[{index}].ap_id")
        site_id = "unassigned" if ap.get("site_id") is None else _record_id(ap.get("site_id"), f"access_points[{index}].site_id")
        raw_name = ap.get("name")
        label = str(raw_name).strip()[:80] if raw_name is not None else ap_id
        if not label:
            label = ap_id
        ap_index[ap_id] = {"ap_id": ap_id, "site_id": site_id, "label": label}

    gateway_seen = set()
    for index, value in enumerate(gateway_ap_ids):
        gateway_id = _record_id(value, f"gateway_ap_ids[{index}]")
        if gateway_id in gateway_seen:
            raise ValueError("gateway_ap_ids must be unique")
        gateway_seen.add(gateway_id)

    unknown_gateway_ids = sorted(gateway_seen - set(ap_index))
    roots_by_site = {}
    for gateway_id in sorted(gateway_seen & set(ap_index)):
        roots_by_site.setdefault(ap_index[gateway_id]["site_id"], []).append(gateway_id)

    adjacency = {ap_id: set() for ap_id in ap_index}
    edges = []
    unresolved_links = []
    cross_site_link_count = 0
    physical_link_count = 0
    rf_neighbor_link_count = 0

    for link in links:
        source = str(link["from_ap_id"]).strip()
        target = str(link["to_ap_id"]).strip()
        relationship = str(link["relationship"]).strip().lower()
        missing = sorted({endpoint for endpoint in (source, target) if endpoint not in ap_index})
        if missing:
            unresolved_links.append({
                "from_ap_id": source,
                "to_ap_id": target,
                "relationship": relationship,
                "unknown_endpoints": missing,
            })
            continue

        cross_site = ap_index[source]["site_id"] != ap_index[target]["site_id"]
        if cross_site:
            cross_site_link_count += 1
        elif relationship == "rf_neighbor":
            rf_neighbor_link_count += 1
        else:
            physical_link_count += 1
            if relationship in PHYSICAL_RELATIONSHIPS:
                adjacency[source].add(target)
                adjacency[target].add(source)

        edges.append({
            "from_ap_id": source,
            "to_ap_id": target,
            "relationship": relationship,
            "cross_site": cross_site,
        })

    site_members = {}
    for ap_id, ap in ap_index.items():
        site_members.setdefault(ap["site_id"], []).append(ap_id)

    nodes = []
    site_groups = []
    max_depth = 0
    cursor_y = 12

    for site_id in sorted(site_members):
        members = sorted(site_members[site_id])
        roots = roots_by_site.get(site_id, [])
        parent = {}
        depth = {}
        component_root = {}
        reachable = {}

        # Gateways are the only roots that establish gateway reachability.
        queue = deque()
        for gateway_id in roots:
            if gateway_id not in parent:
                parent[gateway_id] = None
                depth[gateway_id] = 0
                component_root[gateway_id] = gateway_id
                reachable[gateway_id] = True
                queue.append(gateway_id)

        def visit_queue():
            while queue:
                current = queue.popleft()
                for neighbour in sorted(adjacency[current]):
                    if neighbour in parent:
                        continue
                    parent[neighbour] = current
                    depth[neighbour] = depth[current] + 1
                    component_root[neighbour] = component_root[current]
                    reachable[neighbour] = True if roots else None
                    queue.append(neighbour)

        visit_queue()

        # Lay out disconnected physical components without implying a gateway path.
        for seed in members:
            if seed in parent:
                continue
            parent[seed] = None
            depth[seed] = 0
            component_root[seed] = seed
            reachable[seed] = False if roots else None
            queue.append(seed)
            visit_queue()

        layers = {}
        for ap_id in members:
            layers.setdefault(depth[ap_id], []).append(ap_id)
        max_layer_size = max((len(values) for values in layers.values()), default=1)
        group_height = max(172, 124 + max_layer_size * 96)
        group_nodes = []

        for layer_depth in sorted(layers):
            layer = sorted(layers[layer_depth])
            max_depth = max(max_depth, layer_depth)
            row_offset = (max_layer_size - len(layer)) / 2
            for row, ap_id in enumerate(layer):
                ap = ap_index[ap_id]
                node = {
                    **ap,
                    "x": 164 + layer_depth * 220,
                    "y": round(cursor_y + 76 + (row_offset + row) * 96, 2),
                    "layout_depth": layer_depth,
                    "component_root": component_root[ap_id],
                    "is_gateway": ap_id in roots,
                    "reachable_from_gateway": reachable[ap_id],
                }
                nodes.append(node)
                group_nodes.append(node)

        site_groups.append({
            "site_id": site_id,
            "y": cursor_y,
            "height": group_height,
            "access_point_count": len(members),
            "gateway_ap_ids": roots,
            "reachable_count": sum(node["reachable_from_gateway"] is True for node in group_nodes),
            "unreachable_count": sum(node["reachable_from_gateway"] is False for node in group_nodes),
            "unknown_reachability_count": sum(node["reachable_from_gateway"] is None for node in group_nodes),
        })
        cursor_y += group_height + 20

    nodes.sort(key=lambda node: node["ap_id"])
    edges.sort(key=lambda edge: (
        min(edge["from_ap_id"], edge["to_ap_id"]),
        max(edge["from_ap_id"], edge["to_ap_id"]),
        edge["relationship"],
    ))
    width = 220 + max_depth * 220
    height = max(220, cursor_y - 8)

    return {
        "summary": {
            "site_count": len(site_groups),
            "access_point_count": len(nodes),
            "link_count": len(edges),
            "physical_link_count": physical_link_count,
            "rf_neighbor_link_count": rf_neighbor_link_count,
            "cross_site_link_count": cross_site_link_count,
            "unresolved_link_count": len(unresolved_links),
            "gateway_count": sum(len(roots) for roots in roots_by_site.values()),
            "unknown_gateway_count": len(unknown_gateway_ids),
        },
        "canvas": {"width": width, "height": height},
        "site_groups": site_groups,
        "nodes": nodes,
        "edges": edges,
        "unresolved_links": unresolved_links,
        "unknown_gateway_ap_ids": unknown_gateway_ids,
        "note": (
            "Positions are a deterministic visual layout based only on supplied AP and link records. "
            "Physical links determine layers; RF-neighbour and cross-site links are drawn separately and "
            "do not prove connectivity or live reachability."
        ),
    }


FEATURE = {
    "id": "F157",
    "slug": "site_topology_visualisation",
    "name": "Interactive site topology visualisation",
    "category": "Site inventory",
    "description": "Generate a deterministic multi-site AP topology layout with typed physical, RF-neighbour and cross-site links for the interactive Workbench diagram.",
    "parameters": {
        "access_points": "access_point[]",
        "links": "topology_link[]",
        "gateway_ap_ids": "string[]",
    },
    "run": run,
}
