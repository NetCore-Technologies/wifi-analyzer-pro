"""Recommend channel width: Suggest a conservative channel width using observations from the selected band."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    band = str(p.get("band", "5GHz"))
    if band not in ("2.4GHz", "5GHz", "6GHz"):
        raise ValueError("band must be 2.4GHz, 5GHz or 6GHz")
    count = sum(1 for item in networks(p) if item.get("band") == band)
    width = "20MHz" if band == "2.4GHz" else ("20/40MHz" if count > 20 else "40/80MHz")
    return {"band": band, "suggested_width": width, "observed_networks": count, "note": "Heuristic only; validate client support, DFS and local regulations"}

FEATURE = {
    "id": "F036",
    "slug": 'recommend_channel_width',
    "name": 'Recommend channel width',
    "category": 'RF planning',
    "description": 'Suggest a conservative channel width using observations from the selected band.',
    "parameters": {'band': '2.4GHz|5GHz|6GHz'},
    "run": run,
}
