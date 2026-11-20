"""Redact MAC address: Mask the final three octets of a MAC address for sharing."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    mac=mac_address(p.get("mac",p.get("bssid")))
    return {"redacted":mac[:8]+":XX:XX:XX"}

FEATURE = {
    "id": "F078",
    "slug": 'redact_mac',
    "name": 'Redact MAC address',
    "category": 'Privacy',
    "description": 'Mask the final three octets of a MAC address for sharing.',
    "parameters": {'mac': 'MAC address'},
    "run": run,
}
