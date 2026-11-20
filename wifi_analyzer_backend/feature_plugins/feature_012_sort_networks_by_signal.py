"""Sort by signal: Sort detected access points from strongest to weakest RSSI."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    items = networks(p)
    items.sort(key=lambda n: number(n.get("rssi"), -200), reverse=True)
    return {"networks": items, "count": len(items)}

FEATURE = {
    "id": "F012",
    "slug": 'sort_networks_by_signal',
    "name": 'Sort by signal',
    "category": 'Scan data',
    "description": 'Sort detected access points from strongest to weakest RSSI.',
    "parameters": {},
    "run": run,
}
