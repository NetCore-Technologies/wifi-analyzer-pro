"""Validate network record: Validate essential fields and report missing/invalid observations."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    n=p.get("network",{}); errors=[]
    if not isinstance(n,dict): raise ValueError("'network' must be an object")
    if not safe_text(n.get("ssid"),32) and not n.get("bssid"): errors.append("SSID or BSSID is required")
    try: mac_address(n.get("bssid"))
    except ValueError:
        if n.get("bssid"): errors.append("BSSID is not a valid MAC address")
    if n.get("rssi") is not None and not -127 <= number(n.get("rssi"),-200) <= 0: errors.append("RSSI should be between -127 and 0 dBm")
    return {"valid":not errors,"errors":errors}

FEATURE = {
    "id": "F054",
    "slug": 'validate_network_record',
    "name": 'Validate network record',
    "category": 'Data quality',
    "description": 'Validate essential fields and report missing/invalid observations.',
    "parameters": {'network': 'object'},
    "run": run,
}
