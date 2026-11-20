"""Compare scans: Compare current and previous scans by BSSID."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    current = {str(n.get("bssid", "")).upper(): n for n in p.get("current", []) if isinstance(n, dict)}
    previous = {str(n.get("bssid", "")).upper(): n for n in p.get("previous", []) if isinstance(n, dict)}
    return {"added": [current[k] for k in current.keys() - previous.keys()],
            "removed": [previous[k] for k in previous.keys() - current.keys()],
            "changed": [{"before": previous[k], "after": current[k]} for k in current.keys() & previous.keys() if current[k] != previous[k]]}

FEATURE = {
    "id": "F019",
    "slug": 'scan_delta',
    "name": 'Compare scans',
    "category": 'Scan history',
    "description": 'Compare current and previous scans by BSSID.',
    "parameters": {'current': 'network[]', 'previous': 'network[]'},
    "run": run,
}
