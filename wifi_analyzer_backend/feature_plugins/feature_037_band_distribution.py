"""Band distribution: Count BSS entries in each Wi-Fi band."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    counts = Counter(str(n.get("band", "unknown")) for n in networks(p))
    return {"bands": dict(counts)}

FEATURE = {
    "id": "F037",
    "slug": 'band_distribution',
    "name": 'Band distribution',
    "category": 'RF planning',
    "description": 'Count BSS entries in each Wi-Fi band.',
    "parameters": {},
    "run": run,
}
