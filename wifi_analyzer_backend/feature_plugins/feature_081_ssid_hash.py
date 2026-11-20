"""Stable SSID hash: Create a non-reversible SHA-256 fingerprint of an SSID."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    import hashlib
    ssid=safe_text(p.get("ssid"),32)
    return {"sha256":hashlib.sha256(ssid.encode("utf-8")).hexdigest(),"empty":not bool(ssid)}

FEATURE = {
    "id": "F081",
    "slug": 'ssid_hash',
    "name": 'Stable SSID hash',
    "category": 'Privacy',
    "description": 'Create a non-reversible SHA-256 fingerprint of an SSID.',
    "parameters": {'ssid': 'string'},
    "run": run,
}
