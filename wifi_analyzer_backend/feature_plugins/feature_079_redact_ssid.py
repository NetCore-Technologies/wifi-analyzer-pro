"""Redact SSID: Replace visible SSIDs with stable labels for sharing."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    items=networks(p); names={}
    for n in items:
        ssid=safe_text(n.get("ssid"),32)
        if ssid and ssid not in names: names[ssid]=f"Network-{len(names)+1}"
        n["ssid"]=names.get(ssid,"<hidden>")
    return {"networks":items,"redacted_names":len(names)}

FEATURE = {
    "id": "F079",
    "slug": 'redact_ssid',
    "name": 'Redact SSID',
    "category": 'Privacy',
    "description": 'Replace visible SSIDs with stable labels for sharing.',
    "parameters": {},
    "run": run,
}
