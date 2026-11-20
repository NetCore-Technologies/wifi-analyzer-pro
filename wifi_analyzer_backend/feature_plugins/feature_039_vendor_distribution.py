"""Vendor distribution: Count networks by locally known OUI vendor prefix."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    items = networks(p); counts = Counter()
    known = {"B8:27:EB":"Raspberry Pi", "DC:A6:32":"Raspberry Pi", "F0:18:98":"Apple", "00:1A:11":"Google", "60:F1:89":"Xiaomi", "B4:86:55":"Samsung", "DC:A4:CA":"Espressif", "AC:FD:CE":"TP-Link"}
    for n in items:
        try: vendor = known.get(mac_address(n.get("bssid"))[:8], "Unknown")
        except ValueError: vendor = "Unknown"
        counts[vendor] += 1
    return {"vendors": dict(counts)}

FEATURE = {
    "id": "F039",
    "slug": 'vendor_distribution',
    "name": 'Vendor distribution',
    "category": 'Discovery',
    "description": 'Count networks by locally known OUI vendor prefix.',
    "parameters": {},
    "run": run,
}
