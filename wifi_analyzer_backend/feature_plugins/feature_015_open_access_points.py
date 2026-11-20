"""Open access points: List networks that advertise no link-layer security."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    weak = ("open", "none", "unsecured")
    items = [n for n in networks(p) if security_name(n).lower() in weak]
    return {"networks": items, "count": len(items)}

FEATURE = {
    "id": "F015",
    "slug": 'open_access_points',
    "name": 'Open access points',
    "category": 'Security',
    "description": 'List networks that advertise no link-layer security.',
    "parameters": {},
    "run": run,
}
