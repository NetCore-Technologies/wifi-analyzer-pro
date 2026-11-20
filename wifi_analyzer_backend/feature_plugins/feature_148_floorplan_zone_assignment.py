"""Assign normalised AP floor-plan anchors to explicit polygonal zones."""
from __future__ import annotations

import math


def _identifier(value: object, field: str) -> str:
    result = str(value or "").strip()
    if not result or len(result) > 128:
        raise ValueError(f"{field} must be a non-empty identifier up to 128 characters")
    return result


def _point(value: object, field: str) -> tuple[float, float]:
    if not isinstance(value, dict):
        raise ValueError(f"{field} points must be objects with x and y")
    coordinates = []
    for axis in ("x", "y"):
        raw = value.get(axis)
        if isinstance(raw, bool):
            raise ValueError(f"{field} {axis} must be numeric")
        try:
            coordinate = float(raw)
        except (TypeError, ValueError):
            raise ValueError(f"{field} {axis} must be numeric")
        if not math.isfinite(coordinate) or not 0 <= coordinate <= 1:
            raise ValueError(f"{field} coordinates must be finite and between 0 and 1")
        coordinates.append(coordinate)
    return coordinates[0], coordinates[1]


def _on_segment(point: tuple[float, float], start: tuple[float, float], end: tuple[float, float]) -> bool:
    px, py = point
    ax, ay = start
    bx, by = end
    cross = (px - ax) * (by - ay) - (py - ay) * (bx - ax)
    if abs(cross) > 1e-9:
        return False
    return min(ax, bx) - 1e-9 <= px <= max(ax, bx) + 1e-9 and min(ay, by) - 1e-9 <= py <= max(ay, by) + 1e-9


def _contains(polygon: list[tuple[float, float]], point: tuple[float, float]) -> bool:
    inside = False
    previous = polygon[-1]
    for current in polygon:
        if _on_segment(point, previous, current):
            return True
        x1, y1 = previous
        x2, y2 = current
        if (y1 > point[1]) != (y2 > point[1]):
            crossing_x = (x2 - x1) * (point[1] - y1) / (y2 - y1) + x1
            if point[0] < crossing_x:
                inside = not inside
        previous = current
    return inside


def run(payload: dict) -> dict:
    zones = payload.get("zones", [])
    anchors = payload.get("anchors", [])
    if not isinstance(zones, list) or not isinstance(anchors, list):
        raise ValueError("zones and anchors must be lists")
    if len(zones) > 2048 or len(anchors) > 4096:
        raise ValueError("floor-plan zone snapshot exceeds the supported record limit")

    parsed_zones = []
    seen_zone_ids = set()
    for zone in zones:
        if not isinstance(zone, dict):
            raise ValueError("Each zone must be an object")
        floorplan_id = _identifier(zone.get("floorplan_id"), "floorplan_id")
        zone_id = _identifier(zone.get("zone_id"), "zone_id")
        identity = (floorplan_id, zone_id)
        if identity in seen_zone_ids:
            raise ValueError("zone_id values must be unique within each floor plan")
        seen_zone_ids.add(identity)
        vertices = zone.get("polygon")
        if not isinstance(vertices, list) or len(vertices) < 3 or len(vertices) > 512:
            raise ValueError("Each zone polygon needs between 3 and 512 points")
        polygon = [_point(vertex, "polygon") for vertex in vertices]
        area_twice = sum(
            polygon[index][0] * polygon[(index + 1) % len(polygon)][1]
            - polygon[(index + 1) % len(polygon)][0] * polygon[index][1]
            for index in range(len(polygon))
        )
        if abs(area_twice) <= 1e-9:
            raise ValueError("Zone polygon must enclose a non-zero area")
        parsed_zones.append({
            "floorplan_id": floorplan_id,
            "zone_id": zone_id,
            "name": str(zone.get("name") or zone_id),
            "polygon": polygon,
        })

    seen_anchors = set()
    assignments = []
    for anchor in anchors:
        if not isinstance(anchor, dict):
            raise ValueError("Each anchor must be an object")
        ap_id = _identifier(anchor.get("ap_id"), "ap_id")
        floorplan_id = _identifier(anchor.get("floorplan_id"), "floorplan_id")
        if anchor.get("coordinate_space", "normalized") != "normalized":
            raise ValueError("Zone assignment accepts normalized anchor coordinates only")
        position = _point(anchor, "anchor")
        identity = (ap_id, floorplan_id)
        if identity in seen_anchors:
            raise ValueError("An AP may have only one anchor per floor plan")
        seen_anchors.add(identity)
        matches = [
            zone for zone in parsed_zones
            if zone["floorplan_id"] == floorplan_id and _contains(zone["polygon"], position)
        ]
        assignments.append({
            "ap_id": ap_id,
            "floorplan_id": floorplan_id,
            "x": position[0],
            "y": position[1],
            "zone_ids": [zone["zone_id"] for zone in matches],
            "zone_names": [zone["name"] for zone in matches],
            "status": "assigned" if len(matches) == 1 else "ambiguous" if len(matches) > 1 else "outside_any_zone",
        })

    return {
        "zone_count": len(parsed_zones),
        "anchor_count": len(assignments),
        "assigned_count": sum(item["status"] == "assigned" for item in assignments),
        "ambiguous_count": sum(item["status"] == "ambiguous" for item in assignments),
        "outside_zone_count": sum(item["status"] == "outside_any_zone" for item in assignments),
        "assignments": assignments,
        "note": (
            "Zone boundaries are treated as inside. Overlapping polygons can produce ambiguous assignments; "
            "coordinates and room polygons must use the same normalized floor-plan coordinate space."
        ),
    }


FEATURE = {
    "id": "F148",
    "slug": "floorplan_zone_assignment",
    "name": "Floor-plan zone assignment",
    "category": "Site inventory",
    "description": "Assign AP floor-plan anchors to explicit room/zone polygons and surface out-of-zone or overlapping placements.",
    "parameters": {"zones": "zone[]", "anchors": "anchor[]"},
    "run": run,
}
