"""Validate scan payload: Check a list of network records and return valid/invalid counts."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    raw = p.get("networks", [])
    if not isinstance(raw, list):
        raise ValueError("'networks' must be a list")
    checked=[]
    for index, n in enumerate(raw):
        errors=[]
        if not isinstance(n, dict):
            checked.append({"index": index, "bssid": None, "valid": False, "errors": ["record_must_be_object"]})
            continue
        if n.get("bssid"):
            try: mac_address(n["bssid"])
            except ValueError: errors.append("invalid_bssid")
        if n.get("rssi") is not None and not -127 <= number(n.get("rssi"),-200) <= 0: errors.append("invalid_rssi")
        if not n.get("ssid") and not n.get("bssid"): errors.append("ssid_or_bssid_required")
        checked.append({"index": index, "bssid":n.get("bssid"),"valid":not errors,"errors":errors})
    return {"valid_count":sum(x["valid"] for x in checked),"invalid_count":sum(not x["valid"] for x in checked),"records":checked}

FEATURE = {
    "id": "F055",
    "slug": 'validate_scan',
    "name": 'Validate scan payload',
    "category": 'Data quality',
    "description": 'Check a list of network records and return valid/invalid counts.',
    "parameters": {},
    "run": run,
}
