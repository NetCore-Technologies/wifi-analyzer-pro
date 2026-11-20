"""Classify frequency band: Map a frequency in MHz to 2.4, 5 or 6 GHz."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    freq = number(p.get("frequency_mhz"))
    return {"frequency_mhz": freq, "band": band_from_frequency(freq)}

FEATURE = {
    "id": "F006",
    "slug": 'classify_frequency_band',
    "name": 'Classify frequency band',
    "category": 'RF analysis',
    "description": 'Map a frequency in MHz to 2.4, 5 or 6 GHz.',
    "parameters": {'frequency_mhz': 'number'},
    "run": run,
}
