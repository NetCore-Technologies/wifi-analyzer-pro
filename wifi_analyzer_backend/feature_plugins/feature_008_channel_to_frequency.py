"""Channel to frequency: Convert a channel to MHz when its band is specified."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    band = str(p.get("band", "2.4GHz"))
    channel = int(number(p.get("channel"), -1))
    freq = channel_to_frequency(channel, band)
    return {"channel": channel, "band": band, "frequency_mhz": freq or None}

FEATURE = {
    "id": "F008",
    "slug": 'channel_to_frequency',
    "name": 'Channel to frequency',
    "category": 'RF analysis',
    "description": 'Convert a channel to MHz when its band is specified.',
    "parameters": {'channel': 'number', 'band': '2.4GHz|5GHz|6GHz'},
    "run": run,
}
