"""Deduplicate scan: Keep one record per BSSID, preferring the strongest observation."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    chosen = {}
    for item in networks(p):
        key = str(item.get("bssid", "")).upper()
        if not key:
            key = f"{item.get('ssid','')}|{item.get('channel','')}"
        if key not in chosen or number(item.get("rssi"), -200) > number(chosen[key].get("rssi"), -200):
            chosen[key] = item
    return {"networks": list(chosen.values()), "removed": len(networks(p)) - len(chosen)}

FEATURE = {
    "id": "F018",
    "slug": 'deduplicate_scan',
    "name": 'Deduplicate scan',
    "category": 'Scan data',
    "description": 'Keep one record per BSSID, preferring the strongest observation.',
    "parameters": {},
    "run": run,
}
