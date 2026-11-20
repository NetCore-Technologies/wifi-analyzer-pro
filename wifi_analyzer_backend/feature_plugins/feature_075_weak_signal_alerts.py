"""Weak signal alerts: Generate alerts for networks below a configurable RSSI threshold."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    threshold=number(p.get("threshold_dbm"),-80)
    items=[{"ssid":safe_text(n.get("ssid"),32) or "<hidden>","bssid":n.get("bssid"),"rssi":n.get("rssi")} for n in networks(p) if n.get("rssi") is not None and number(n.get("rssi"))<threshold]
    return {"threshold_dbm":threshold,"alerts":items,"count":len(items)}

FEATURE = {
    "id": "F075",
    "slug": 'weak_signal_alerts',
    "name": 'Weak signal alerts',
    "category": 'Alerts',
    "description": 'Generate alerts for networks below a configurable RSSI threshold.',
    "parameters": {'threshold_dbm': 'number'},
    "run": run,
}
