"""2.4 GHz overlap analysis: Estimate co-channel and adjacent-channel overlap using 20 MHz channel spacing."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    counts = congestion_map([n for n in networks(p) if n.get("band", "2.4GHz") == "2.4GHz"])["2.4GHz"]
    return {"channels": [{"channel": ch, "overlap_count": counts.get(ch, 0)} for ch in range(1, 14)], "note": "BSS counts are a relative indicator, not measured airtime utilisation"}

FEATURE = {
    "id": "F029",
    "slug": 'overlap_24ghz',
    "name": '2.4 GHz overlap analysis',
    "category": 'RF planning',
    "description": 'Estimate co-channel and adjacent-channel overlap using 20 MHz channel spacing.',
    "parameters": {},
    "run": run,
}
