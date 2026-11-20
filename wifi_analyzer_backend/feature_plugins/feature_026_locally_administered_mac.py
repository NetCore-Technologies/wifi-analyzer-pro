"""Locally administered MAC check: Inspect the locally-administered and multicast bits in a MAC address."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    mac = mac_address(p.get("mac", p.get("bssid")))
    first = int(mac[:2], 16)
    return {"mac": mac, "locally_administered": bool(first & 0x02), "multicast": bool(first & 0x01)}

FEATURE = {
    "id": "F026",
    "slug": 'locally_administered_mac',
    "name": 'Locally administered MAC check',
    "category": 'Security',
    "description": 'Inspect the locally-administered and multicast bits in a MAC address.',
    "parameters": {'mac': 'MAC address'},
    "run": run,
}
