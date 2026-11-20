"""Channel quality score: Calculate relative channel score from observed congestion counts."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    band, channel = str(p.get("band", "2.4GHz")), int(number(p.get("channel"), 1))
    counts = congestion_map(networks(p)).get(band, {})
    count = counts.get(channel, 0)
    return {"band": band, "channel": channel, "observed_count": count, "relative_score": max(0, 100 - min(100, count * 12)), "not_airtime": True}

FEATURE = {
    "id": "F033",
    "slug": 'channel_quality',
    "name": 'Channel quality score',
    "category": 'RF planning',
    "description": 'Calculate relative channel score from observed congestion counts.',
    "parameters": {'band': 'string', 'channel': 'integer'},
    "run": run,
}
