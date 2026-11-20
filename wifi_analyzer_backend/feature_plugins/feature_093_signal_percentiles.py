"""Signal percentiles: Calculate RSSI p10, median and p90 for the provided sample set."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    vals=[number(v) for v in p.get("samples_dbm",[]) if v is not None]
    return {"count":len(vals),"p10":percentile(vals,10),"p50":percentile(vals,50),"p90":percentile(vals,90)}

FEATURE = {
    "id": "F093",
    "slug": 'signal_percentiles',
    "name": 'Signal percentiles',
    "category": 'History',
    "description": 'Calculate RSSI p10, median and p90 for the provided sample set.',
    "parameters": {'samples_dbm': 'number[]'},
    "run": run,
}
