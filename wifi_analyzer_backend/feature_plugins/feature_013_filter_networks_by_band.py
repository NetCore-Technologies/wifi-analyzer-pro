"""Filter by band: Filter the current scan by 2.4, 5 or 6 GHz."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    band = str(p.get("band", "2.4GHz"))
    items = [n for n in networks(p) if n.get("band") == band]
    return {"band": band, "networks": items, "count": len(items)}

FEATURE = {
    "id": "F013",
    "slug": 'filter_networks_by_band',
    "name": 'Filter by band',
    "category": 'Scan data',
    "description": 'Filter the current scan by 2.4, 5 or 6 GHz.',
    "parameters": {'band': '2.4GHz|5GHz|6GHz'},
    "run": run,
}
