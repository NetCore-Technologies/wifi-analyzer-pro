"""Group by SSID: Group BSS records by visible SSID, preserving hidden entries separately."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    grouped = defaultdict(list)
    for net in networks(p):
        grouped[safe_text(net.get("ssid"), 32) or "<hidden>"].append(net)
    return {"groups": {k: v for k, v in sorted(grouped.items())}, "ssid_count": len(grouped)}

FEATURE = {
    "id": "F023",
    "slug": 'group_by_ssid',
    "name": 'Group by SSID',
    "category": 'Scan data',
    "description": 'Group BSS records by visible SSID, preserving hidden entries separately.',
    "parameters": {},
    "run": run,
}
