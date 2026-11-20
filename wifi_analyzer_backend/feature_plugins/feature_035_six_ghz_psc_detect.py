"""6 GHz PSC check: Check whether a 6 GHz channel is a Preferred Scanning Channel."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    ch = int(number(p.get("channel"), 0))
    psc = 5 <= ch <= 229 and (ch - 5) % 16 == 0
    return {"channel": ch, "psc": psc}

FEATURE = {
    "id": "F035",
    "slug": 'six_ghz_psc_detect',
    "name": '6 GHz PSC check',
    "category": 'RF planning',
    "description": 'Check whether a 6 GHz channel is a Preferred Scanning Channel.',
    "parameters": {'channel': 'integer'},
    "run": run,
}
