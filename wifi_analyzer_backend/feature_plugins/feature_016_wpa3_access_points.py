"""WPA3 access points: List networks advertising WPA3 or SAE."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    items = [n for n in networks(p) if "wpa3" in security_name(n).lower() or "sae" in security_name(n).lower()]
    return {"networks": items, "count": len(items)}

FEATURE = {
    "id": "F016",
    "slug": 'wpa3_access_points',
    "name": 'WPA3 access points',
    "category": 'Security',
    "description": 'List networks advertising WPA3 or SAE.',
    "parameters": {},
    "run": run,
}
