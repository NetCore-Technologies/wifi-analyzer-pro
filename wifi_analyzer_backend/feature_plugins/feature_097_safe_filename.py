"""Safe filename: Normalise a name for a local export filename."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    raw=safe_text(p.get("name","wifi-report"),120).strip(); safe=re.sub(r"[^A-Za-z0-9._-]+","-",raw).strip(".-_") or "wifi-report"
    return {"filename":safe[:80]}

FEATURE = {
    "id": "F097",
    "slug": 'safe_filename',
    "name": 'Safe filename',
    "category": 'Utilities',
    "description": 'Normalise a name for a local export filename.',
    "parameters": {'name': 'string'},
    "run": run,
}
