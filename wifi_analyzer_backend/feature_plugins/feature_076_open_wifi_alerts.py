"""Open Wi-Fi alerts: Create alert records for open access points."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    items=[{"severity":"warning","type":"open_wifi","ssid":safe_text(n.get("ssid"),32) or "<hidden>","bssid":n.get("bssid"),"message":"Open network advertised"} for n in networks(p) if security_name(n).lower() in ("open","none","unsecured")]
    return {"alerts":items,"count":len(items)}

FEATURE = {
    "id": "F076",
    "slug": 'open_wifi_alerts',
    "name": 'Open Wi-Fi alerts',
    "category": 'Alerts',
    "description": 'Create alert records for open access points.',
    "parameters": {},
    "run": run,
}
