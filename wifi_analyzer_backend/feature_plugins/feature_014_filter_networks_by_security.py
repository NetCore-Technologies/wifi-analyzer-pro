"""Filter by security: Filter networks by a security label, case-insensitively."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    wanted = str(p.get("security", "WPA2")).lower()
    items = [n for n in networks(p) if wanted in security_name(n).lower()]
    return {"security": wanted, "networks": items, "count": len(items)}

FEATURE = {
    "id": "F014",
    "slug": 'filter_networks_by_security',
    "name": 'Filter by security',
    "category": 'Scan data',
    "description": 'Filter networks by a security label, case-insensitively.',
    "parameters": {'security': 'string'},
    "run": run,
}
