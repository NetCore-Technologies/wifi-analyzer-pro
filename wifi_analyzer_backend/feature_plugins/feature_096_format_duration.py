"""Format duration: Format elapsed seconds as days, hours, minutes and seconds."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    total=max(0,int(number(p.get("seconds")))); days,rem=divmod(total,86400); hours,rem=divmod(rem,3600); minutes,secs=divmod(rem,60)
    return {"formatted":(f"{days}d " if days else "")+f"{hours}h {minutes}m {secs}s"}

FEATURE = {
    "id": "F096",
    "slug": 'format_duration',
    "name": 'Format duration',
    "category": 'Utilities',
    "description": 'Format elapsed seconds as days, hours, minutes and seconds.',
    "parameters": {'seconds': 'number'},
    "run": run,
}
