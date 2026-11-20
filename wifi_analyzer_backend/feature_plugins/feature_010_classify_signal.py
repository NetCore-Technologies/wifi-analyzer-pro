"""Signal strength class: Classify RSSI using conservative signal-strength bands."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    rssi = number(p.get("rssi"), -200)
    label = "excellent" if rssi >= -50 else "good" if rssi >= -60 else "fair" if rssi >= -70 else "weak" if rssi >= -80 else "very_weak"
    return {"rssi": rssi, "classification": label}

FEATURE = {
    "id": "F010",
    "slug": 'classify_signal',
    "name": 'Signal strength class',
    "category": 'RF analysis',
    "description": 'Classify RSSI using conservative signal-strength bands.',
    "parameters": {'rssi': 'number'},
    "run": run,
}
