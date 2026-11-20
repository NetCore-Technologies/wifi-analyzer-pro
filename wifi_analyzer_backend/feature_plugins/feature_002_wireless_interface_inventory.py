"""Wireless interface inventory: Find Linux wireless interfaces without assuming a specific adapter name."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    import os
    found = []
    root = "/sys/class/net"
    if os.path.isdir(root):
        for name in sorted(os.listdir(root)):
            if os.path.exists(os.path.join(root, name, "wireless")) or os.path.islink(os.path.join(root, name, "phy80211")):
                found.append(name)
    return {"interfaces": found, "count": len(found)}

FEATURE = {
    "id": "F002",
    "slug": 'wireless_interface_inventory',
    "name": 'Wireless interface inventory',
    "category": 'Discovery',
    "description": 'Find Linux wireless interfaces without assuming a specific adapter name.',
    "parameters": {},
    "run": run,
}
