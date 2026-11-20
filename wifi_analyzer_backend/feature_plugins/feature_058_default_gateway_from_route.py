"""Default gateway lookup: Extract the first default gateway from supplied route output."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    text=str(p.get("text","")); m=re.search(r"(?m)^default(?: via ([0-9a-fA-F:.]+))?",text)
    return {"gateway":m.group(1) if m else None,"found":bool(m and m.group(1))}

FEATURE = {
    "id": "F058",
    "slug": 'default_gateway_from_route',
    "name": 'Default gateway lookup',
    "category": 'Diagnostics',
    "description": 'Extract the first default gateway from supplied route output.',
    "parameters": {'text': 'route output'},
    "run": run,
}
