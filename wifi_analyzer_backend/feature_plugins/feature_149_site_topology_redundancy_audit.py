"""Find single-edge and single-AP cut points in an explicit AP backhaul graph."""
from __future__ import annotations

PHYSICAL = {"wired_uplink", "wireless_backhaul", "mesh_backhaul"}
VALID = PHYSICAL | {"rf_neighbor"}


def run(payload: dict) -> dict:
    access_points = payload.get("access_points", [])
    links = payload.get("links", [])
    if not isinstance(access_points, list) or not isinstance(links, list):
        raise ValueError("access_points and links must be lists")
    if len(access_points) > 512 or len(links) > 4096:
        raise ValueError("topology analysis supports at most 512 APs and 4096 links")

    nodes = set()
    for ap in access_points:
        if not isinstance(ap, dict) or not ap.get("ap_id"):
            raise ValueError("Each AP needs ap_id")
        ap_id = str(ap["ap_id"]).strip()
        if not ap_id or len(ap_id) > 128 or ap_id in nodes:
            raise ValueError("AP identifiers must be unique non-empty strings up to 128 characters")
        nodes.add(ap_id)

    graph = {node: [] for node in nodes}
    edges = set()
    unresolved = []
    duplicates = 0
    ignored_rf = 0
    for index, link in enumerate(links):
        if not isinstance(link, dict):
            raise ValueError("Each topology link must be an object")
        source = str(link.get("from_ap_id") or "").strip()
        target = str(link.get("to_ap_id") or "").strip()
        relationship = str(link.get("relationship") or "").strip().lower()
        if relationship not in VALID:
            raise ValueError(f"relationship must be one of {sorted(VALID)}")
        if not source or not target or source == target:
            raise ValueError("Topology links need two different AP identifiers")
        if relationship == "rf_neighbor":
            ignored_rf += 1
            continue
        missing = [node for node in (source, target) if node not in nodes]
        if missing:
            unresolved.append({
                "from_ap_id": source, "to_ap_id": target,
                "missing_ap_ids": missing, "link_index": index,
            })
            continue
        edge = tuple(sorted((source, target)))
        if edge in edges:
            duplicates += 1
            continue
        edges.add(edge)
        graph[source].append(target)
        graph[target].append(source)

    discovery = {}
    low = {}
    parent = {}
    bridges = []
    articulation = set()
    components = []
    clock = 0

    def visit(node: str) -> None:
        nonlocal clock
        clock += 1
        discovery[node] = low[node] = clock
        children = 0
        for neighbour in sorted(graph[node]):
            if neighbour not in discovery:
                parent[neighbour] = node
                children += 1
                visit(neighbour)
                low[node] = min(low[node], low[neighbour])
                if low[neighbour] > discovery[node]:
                    bridges.append(tuple(sorted((node, neighbour))))
                if node in parent and low[neighbour] >= discovery[node]:
                    articulation.add(node)
            elif parent.get(node) != neighbour:
                low[node] = min(low[node], discovery[neighbour])
        if node not in parent and children > 1:
            articulation.add(node)

    for node in sorted(nodes):
        if node not in discovery:
            component = []
            stack = [node]
            seen_component = {node}
            while stack:
                current = stack.pop()
                component.append(current)
                for neighbour in graph[current]:
                    if neighbour not in seen_component:
                        seen_component.add(neighbour)
                        stack.append(neighbour)
            components.append(sorted(component))
            visit(node)

    bridge_results = [
        {"from_ap_id": left, "to_ap_id": right, "impact": "disconnects_component_if_removed"}
        for left, right in sorted(set(bridges))
    ]
    return {
        "access_point_count": len(nodes),
        "physical_link_count": len(edges),
        "rf_neighbor_links_excluded": ignored_rf,
        "duplicate_physical_links": duplicates,
        "unresolved_physical_links": unresolved,
        "component_count": len(components),
        "components": components,
        "isolated_access_points": sorted(node for node, neighbours in graph.items() if not neighbours),
        "critical_access_points": sorted(articulation),
        "critical_links": bridge_results,
        "status": "review" if bridge_results or articulation or unresolved else "no_single_point_cut_found",
        "note": (
            "Only explicit wired/backhaul links are analysed; RF-neighbour observations are excluded. "
            "A cut point indicates graph connectivity dependence, not measured service impact or internet reachability."
        ),
    }


FEATURE = {
    "id": "F149",
    "slug": "site_topology_redundancy_audit",
    "name": "Site topology redundancy audit",
    "category": "Site inventory",
    "description": "Identify physical-backhaul cut links, articulation APs and disconnected components from supplied topology evidence.",
    "parameters": {"access_points": "access_point[]", "links": "link[]"},
    "run": run,
}
