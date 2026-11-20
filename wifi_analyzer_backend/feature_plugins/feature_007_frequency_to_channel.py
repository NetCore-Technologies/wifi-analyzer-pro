"""Frequency to channel: Convert a Wi-Fi frequency in MHz to its channel number."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    freq = number(p.get("frequency_mhz"))
    return {"frequency_mhz": freq, "channel": frequency_to_channel(freq), "band": band_from_frequency(freq)}

FEATURE = {
    "id": "F007",
    "slug": 'frequency_to_channel',
    "name": 'Frequency to channel',
    "category": 'RF analysis',
    "description": 'Convert a Wi-Fi frequency in MHz to its channel number.',
    "parameters": {'frequency_mhz': 'number'},
    "run": run,
}
