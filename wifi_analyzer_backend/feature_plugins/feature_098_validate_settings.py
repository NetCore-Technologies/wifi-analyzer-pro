"""Validate application settings: Validate polling and scan settings before saving."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    errors=[]; interval=number(p.get("refresh_interval_seconds"),10); timeout=number(p.get("scan_timeout_seconds"),15); max_history=int(number(p.get("max_history"),300))
    if not 0<=interval<=3600: errors.append("refresh_interval_seconds must be between 0 and 3600")
    if not 1<=timeout<=120: errors.append("scan_timeout_seconds must be between 1 and 120")
    if not 10<=max_history<=10000: errors.append("max_history must be between 10 and 10000")
    return {"valid":not errors,"errors":errors,"normalised":{"refresh_interval_seconds":interval,"scan_timeout_seconds":timeout,"max_history":max_history}}

FEATURE = {
    "id": "F098",
    "slug": 'validate_settings',
    "name": 'Validate application settings',
    "category": 'Utilities',
    "description": 'Validate polling and scan settings before saving.',
    "parameters": {'refresh_interval_seconds': 'number', 'scan_timeout_seconds': 'number', 'max_history': 'integer'},
    "run": run,
}
