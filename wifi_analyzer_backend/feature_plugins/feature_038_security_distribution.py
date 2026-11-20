"""Security distribution: Count observed networks by advertised security label."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    return {"security": dict(Counter(security_name(n) for n in networks(p)))}

FEATURE = {
    "id": "F038",
    "slug": 'security_distribution',
    "name": 'Security distribution',
    "category": 'Security',
    "description": 'Count observed networks by advertised security label.',
    "parameters": {},
    "run": run,
}
