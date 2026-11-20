"""Strongest BSSID per SSID: Select the strongest BSSID observation for each SSID."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    chosen = {}
    for net in networks(p):
        ssid = safe_text(net.get("ssid"), 32) or "<hidden>"
        if ssid not in chosen or number(net.get("rssi"), -200) > number(chosen[ssid].get("rssi"), -200): chosen[ssid] = net
    return {"networks": list(chosen.values()), "count": len(chosen)}

FEATURE = {
    "id": "F024",
    "slug": 'strongest_per_ssid',
    "name": 'Strongest BSSID per SSID',
    "category": 'Scan data',
    "description": 'Select the strongest BSSID observation for each SSID.',
    "parameters": {},
    "run": run,
}
