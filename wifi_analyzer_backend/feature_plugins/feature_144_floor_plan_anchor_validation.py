"""Validate AP floor-plan anchors against supplied floor plans and inventory.

Coordinates are explicit operator-supplied positions. This module does not
read floor-plan images, geolocate APs, or infer indoor positions.
"""
from __future__ import annotations

import math


def _identifier(value: object, field: str) -> str:
    result = str(value or "").strip()
    if not result or len(result) > 128:
        raise ValueError(f"{field} must be a non-empty identifier up to 128 characters")
    return result


def _coordinate(value: object, field: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be numeric")
    try:
        result = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"{field} must be numeric")
    if not math.isfinite(result):
        raise ValueError(f"{field} must be finite")
    return result


def run(payload: dict) -> dict:
    floorplans = payload.get("floorplans", [])
    access_points = payload.get("access_points", [])
    anchors = payload.get("anchors", [])
    if not all(isinstance(value, list) for value in (floorplans, access_points, anchors)):
        raise ValueError("floorplans, access_points and anchors must be lists")
    if len(floorplans) > 512 or len(access_points) > 2048 or len(anchors) > 4096:
        raise ValueError("floor-plan snapshot exceeds the supported record limit")

    plans = {}
    for plan in floorplans:
        if not isinstance(plan, dict):
            raise ValueError("Each floor plan must be an object")
        floorplan_id = _identifier(plan.get("floorplan_id"), "floorplan_id")
        if floorplan_id in plans:
            raise ValueError("floorplan_id values must be unique")
        width = plan.get("width_px")
        height = plan.get("height_px")
        if width is not None:
            width = _coordinate(width, "width_px")
            if width <= 0:
                raise ValueError("width_px must be positive")
        if height is not None:
            height = _coordinate(height, "height_px")
            if height <= 0:
                raise ValueError("height_px must be positive")
        plans[floorplan_id] = {
            "floorplan_id": floorplan_id,
            "site_id": str(plan.get("site_id") or "unassigned"),
            "name": str(plan.get("name") or floorplan_id),
            "width_px": width,
            "height_px": height,
        }

    aps = {}
    for ap in access_points:
        if not isinstance(ap, dict):
            raise ValueError("Each access point must be an object")
        ap_id = _identifier(ap.get("ap_id"), "ap_id")
        if ap_id in aps:
            raise ValueError("ap_id values must be unique")
        aps[ap_id] = {
            "ap_id": ap_id,
            "site_id": str(ap.get("site_id") or "unassigned"),
            "name": str(ap.get("name") or ap_id),
        }

    normalized = []
    unresolved = []
    cross_site = []
    seen = set()
    coordinate_groups = {}
    for index, anchor in enumerate(anchors):
        if not isinstance(anchor, dict):
            raise ValueError("Each anchor must be an object")
        ap_id = _identifier(anchor.get("ap_id"), "ap_id")
        floorplan_id = _identifier(anchor.get("floorplan_id"), "floorplan_id")
        x = _coordinate(anchor.get("x"), "x")
        y = _coordinate(anchor.get("y"), "y")
        space = str(anchor.get("coordinate_space") or "normalized").strip().lower()
        if space not in {"normalized", "pixels"}:
            raise ValueError("coordinate_space must be normalized or pixels")
        if space == "normalized":
            if not 0 <= x <= 1 or not 0 <= y <= 1:
                raise ValueError("normalized x and y must be between 0 and 1")
        else:
            plan = plans.get(floorplan_id)
            if plan is None or plan["width_px"] is None or plan["height_px"] is None:
                raise ValueError("pixel anchors need a known floor plan with width_px and height_px")
            if not 0 <= x <= plan["width_px"] or not 0 <= y <= plan["height_px"]:
                raise ValueError("pixel coordinates must be within floor-plan bounds")

        missing = []
        if ap_id not in aps:
            missing.append("ap")
        if floorplan_id not in plans:
            missing.append("floorplan")
        if missing:
            unresolved.append({"ap_id": ap_id, "floorplan_id": floorplan_id, "missing": missing, "anchor_index": index})
            continue
        if aps[ap_id]["site_id"] != plans[floorplan_id]["site_id"]:
            cross_site.append({"ap_id": ap_id, "floorplan_id": floorplan_id,
                               "ap_site_id": aps[ap_id]["site_id"], "floorplan_site_id": plans[floorplan_id]["site_id"]})
            continue

        key = (ap_id, floorplan_id)
        if key in seen:
            raise ValueError("An AP may have only one anchor per floor plan")
        seen.add(key)
        record = {
            "ap_id": ap_id, "floorplan_id": floorplan_id,
            "x": x, "y": y, "coordinate_space": space,
            "site_id": aps[ap_id]["site_id"],
        }
        normalized.append(record)
        position = (floorplan_id, space, round(x, 6), round(y, 6))
        coordinate_groups.setdefault(position, []).append(ap_id)

    collocated = [
        {"floorplan_id": position[0], "coordinate_space": position[1],
         "x": position[2], "y": position[3], "ap_ids": sorted(set(ap_ids))}
        for position, ap_ids in sorted(coordinate_groups.items())
        if len(set(ap_ids)) > 1
    ]
    anchored_ap_ids = {item["ap_id"] for item in normalized}
    unanchored = sorted(set(aps) - anchored_ap_ids)

    return {
        "floorplan_count": len(plans),
        "inventory_access_point_count": len(aps),
        "anchor_count": len(normalized),
        "unanchored_access_points": unanchored,
        "unresolved_anchors": unresolved,
        "cross_site_anchors": cross_site,
        "collocated_anchor_groups": collocated,
        "anchors": normalized,
        "note": (
            "Coordinates are annotations against caller-provided plans. "
            "Collocated positions are reported for review and are not assumed to be errors."
        ),
    }


FEATURE = {
    "id": "F144",
    "slug": "floor_plan_anchor_validation",
    "name": "Floor-plan AP anchor validation",
    "category": "Site inventory",
    "description": "Validate AP-to-floor-plan coordinates, detect missing inventory references and surface collocated anchors without inferring locations.",
    "parameters": {"floorplans": "floorplan[]", "access_points": "access_point[]", "anchors": "anchor[]"},
    "run": run,
}
