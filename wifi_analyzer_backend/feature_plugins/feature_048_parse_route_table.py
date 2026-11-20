"""Parse Linux IPv4 default route: Extract gateway and interface from ip route output."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    text=str(p.get("text","")); m=re.search(r"(?m)^default(?: via (\S+))?(?: .*? dev (\S+))?",text)
    return {"gateway":m.group(1) if m else None,"interface":m.group(2) if m else None}

FEATURE = {
    "id": "F048",
    "slug": 'parse_route_table',
    "name": 'Parse Linux IPv4 default route',
    "category": 'Parsers',
    "description": 'Extract gateway and interface from ip route output.',
    "parameters": {'text': 'ip route output'},
    "run": run,
}
