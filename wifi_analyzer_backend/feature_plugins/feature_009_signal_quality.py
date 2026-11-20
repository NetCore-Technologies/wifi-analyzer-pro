"""Signal quality score: Calculate a bounded 0–100 RSSI quality score."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    q = signal_quality(p.get("rssi"))
    return {"rssi": p.get("rssi"), "quality": q}

FEATURE = {
    "id": "F009",
    "slug": 'signal_quality',
    "name": 'Signal quality score',
    "category": 'RF analysis',
    "description": 'Calculate a bounded 0–100 RSSI quality score.',
    "parameters": {'rssi': 'number'},
    "run": run,
}
