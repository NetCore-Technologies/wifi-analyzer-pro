"""WPA2/WPA3 transition mode: Identify networks advertising both SAE and PSK transition security."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    items=[n for n in networks(p) if "wpa2/wpa3" in security_name(n).lower() or ("sae" in security_name(n).lower() and "psk" in security_name(n).lower())]
    return {"networks":items,"count":len(items)}

FEATURE = {
    "id": "F077",
    "slug": 'transition_mode_detect',
    "name": 'WPA2/WPA3 transition mode',
    "category": 'Security',
    "description": 'Identify networks advertising both SAE and PSK transition security.',
    "parameters": {},
    "run": run,
}
