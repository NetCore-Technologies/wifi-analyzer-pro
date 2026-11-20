"""Normalise SSID: Remove control characters and preserve hidden SSIDs as an empty string."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    value = safe_text(p.get("ssid"), 32)
    return {"ssid": value, "hidden": not bool(value), "utf8_bytes": len(value.encode("utf-8"))}

FEATURE = {
    "id": "F005",
    "slug": 'normalise_ssid',
    "name": 'Normalise SSID',
    "category": 'Scan data',
    "description": 'Remove control characters and preserve hidden SSIDs as an empty string.',
    "parameters": {'ssid': 'string'},
    "run": run,
}
