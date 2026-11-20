"""Trim signal history window: Return only the most recent N signal history samples."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    samples=p.get("history",[]); limit=max(1,min(10000,int(number(p.get("limit"),120))))
    return {"history":samples[-limit:] if isinstance(samples,list) else [],"count":min(limit,len(samples)) if isinstance(samples,list) else 0}

FEATURE = {
    "id": "F091",
    "slug": 'history_window',
    "name": 'Trim signal history window',
    "category": 'History',
    "description": 'Return only the most recent N signal history samples.',
    "parameters": {'history': 'array', 'limit': 'integer'},
    "run": run,
}
