"""Strongest networks: Return the top N strongest networks."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    items = sorted(networks(p), key=lambda n: number(n.get("rssi"), -200), reverse=True)
    limit = max(1, min(100, int(number(p.get("limit"), 10))))
    return {"networks": items[:limit], "count": min(limit, len(items))}

FEATURE = {
    "id": "F021",
    "slug": 'strongest_networks',
    "name": 'Strongest networks',
    "category": 'Scan data',
    "description": 'Return the top N strongest networks.',
    "parameters": {'limit': 'integer'},
    "run": run,
}
