"""Normalise BSSID: Validate and canonicalise a BSSID/MAC address."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    return {"bssid": mac_address(p.get("bssid", p.get("mac")))}

FEATURE = {
    "id": "F004",
    "slug": 'normalise_bssid',
    "name": 'Normalise BSSID',
    "category": 'Scan data',
    "description": 'Validate and canonicalise a BSSID/MAC address.',
    "parameters": {'bssid': 'string'},
    "run": run,
}
