"""Multi-Link Operation summary: Summarise supplied Wi-Fi 7 MLO link records by active state, band and signal."""
from __future__ import annotations
import math
import statistics
from datetime import datetime

FEATURE = None

def run(p: dict) -> dict:
    links = p.get("links", [])
    if not isinstance(links, list):
        raise ValueError("'links' must be a list")
    bands = {}
    active = 0
    output = []
    for link in links:
        if not isinstance(link, dict):
            raise ValueError("Each link must be an object")
        band = str(link.get("band") or "unknown")
        bands[band] = bands.get(band, 0) + 1
        is_active = link.get("active") is True
        active += int(is_active)
        rssi = link.get("rssi_dbm")
        if rssi is not None:
            try:
                rssi = float(rssi)
            except (TypeError, ValueError):
                raise ValueError("rssi_dbm must be numeric when supplied")
            if not math.isfinite(rssi):
                raise ValueError("rssi_dbm must be finite")
        output.append({"link_id": link.get("link_id"), "band": band, "channel": link.get("channel"),
                       "active": is_active, "rssi_dbm": rssi})
    return {"link_count": len(output), "active_link_count": active, "links_by_band": bands, "links": output}

FEATURE = {
    "id": "F118",
    "slug": "multi_link_operation_summary",
    "name": "Multi-Link Operation summary",
    "category": "PHY analysis",
    "description": "Summarise supplied Wi-Fi 7 MLO link records by active state, band and signal.",
    "parameters": {"links":"link[]"},
    "run": run,
}
