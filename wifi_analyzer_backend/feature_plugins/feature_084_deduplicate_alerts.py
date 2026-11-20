"""Deduplicate alerts: Remove repeated alerts by type, BSSID and message."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    seen=set(); result=[]
    for a in p.get("alerts",[]):
        if not isinstance(a,dict): continue
        key=(a.get("type"),a.get("bssid"),a.get("message"))
        if key not in seen: seen.add(key); result.append(a)
    return {"alerts":result,"removed":len(p.get("alerts",[]))-len(result)}

FEATURE = {
    "id": "F084",
    "slug": 'deduplicate_alerts',
    "name": 'Deduplicate alerts',
    "category": 'Alerts',
    "description": 'Remove repeated alerts by type, BSSID and message.',
    "parameters": {'alerts': 'object[]'},
    "run": run,
}
