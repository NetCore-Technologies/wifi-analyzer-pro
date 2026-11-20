"""Randomised MAC indicator: Flag MAC addresses whose locally-administered bit is set."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    mac = mac_address(p.get("mac", p.get("bssid")))
    return {"mac": mac, "likely_randomized_or_local": bool(int(mac[:2], 16) & 0x02)}

FEATURE = {
    "id": "F027",
    "slug": 'randomized_mac_detect',
    "name": 'Randomised MAC indicator',
    "category": 'Security',
    "description": 'Flag MAC addresses whose locally-administered bit is set.',
    "parameters": {'mac': 'MAC address'},
    "run": run,
}
