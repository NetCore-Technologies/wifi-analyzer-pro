"""Channel congestion map: Count nearby BSS and adjacent 2.4 GHz channel overlap."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    items = networks(p)
    return {"congestion": congestion_map(items)}

FEATURE = {
    "id": "F028",
    "slug": 'channel_congestion',
    "name": 'Channel congestion map',
    "category": 'RF planning',
    "description": 'Count nearby BSS and adjacent 2.4 GHz channel overlap.',
    "parameters": {},
    "run": run,
}
