"""Anonymise scan: Redact SSIDs and BSSIDs before exporting a scan."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    items=networks(p)
    for i,n in enumerate(items,1):
        n["ssid"]=f"Network-{i}" if n.get("ssid") else "<hidden>"
        n["bssid"]=f"02:00:00:00:{(i>>8)&255:02X}:{i&255:02X}"
        n.pop("vendor",None)
    return {"networks":items,"anonymised":True}

FEATURE = {
    "id": "F080",
    "slug": 'anonymise_scan',
    "name": 'Anonymise scan',
    "category": 'Privacy',
    "description": 'Redact SSIDs and BSSIDs before exporting a scan.',
    "parameters": {},
    "run": run,
}
