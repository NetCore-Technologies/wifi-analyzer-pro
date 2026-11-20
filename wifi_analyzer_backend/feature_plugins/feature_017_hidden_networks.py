"""Hidden SSIDs: List BSS entries that do not disclose an SSID."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    items = [n for n in networks(p) if not safe_text(n.get("ssid"), 32)]
    return {"networks": items, "count": len(items)}

FEATURE = {
    "id": "F017",
    "slug": 'hidden_networks',
    "name": 'Hidden SSIDs',
    "category": 'Scan data',
    "description": 'List BSS entries that do not disclose an SSID.',
    "parameters": {},
    "run": run,
}
