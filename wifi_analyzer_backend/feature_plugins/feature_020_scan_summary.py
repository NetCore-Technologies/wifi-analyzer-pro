"""Scan summary: Summarise network counts, bands, security and average measured RSSI."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    items = networks(p)
    bands = Counter(str(n.get("band", "unknown")) for n in items)
    security = Counter(security_name(n) for n in items)
    signals = [number(n.get("rssi")) for n in items if n.get("rssi") is not None]
    return {"count": len(items), "bands": dict(bands), "security": dict(security),
            "average_rssi": round(sum(signals)/len(signals), 1) if signals else None}

FEATURE = {
    "id": "F020",
    "slug": 'scan_summary',
    "name": 'Scan summary',
    "category": 'Scan data',
    "description": 'Summarise network counts, bands, security and average measured RSSI.',
    "parameters": {},
    "run": run,
}
