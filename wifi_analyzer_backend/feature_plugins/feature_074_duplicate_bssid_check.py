"""Duplicate BSSID check: Detect duplicate BSSID records in one scan."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    seen=Counter(str(n.get("bssid","")).upper() for n in networks(p) if n.get("bssid"))
    duplicates={k:v for k,v in seen.items() if v>1}
    return {"duplicates":duplicates,"count":len(duplicates)}

FEATURE = {
    "id": "F074",
    "slug": 'duplicate_bssid_check',
    "name": 'Duplicate BSSID check',
    "category": 'Security',
    "description": 'Detect duplicate BSSID records in one scan.',
    "parameters": {},
    "run": run,
}
