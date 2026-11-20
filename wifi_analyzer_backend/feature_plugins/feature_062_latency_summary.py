"""Latency summary: Summarise latency samples with min, median, p95 and max."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    values=[number(v,-1) for v in p.get("samples_ms",[]) if number(v,-1)>=0]
    if not values: return {"count":0,"min_ms":None,"median_ms":None,"p95_ms":None,"max_ms":None}
    return {"count":len(values),"min_ms":min(values),"median_ms":statistics.median(values),"p95_ms":percentile(values,95),"max_ms":max(values)}

FEATURE = {
    "id": "F062",
    "slug": 'latency_summary',
    "name": 'Latency summary',
    "category": 'Diagnostics',
    "description": 'Summarise latency samples with min, median, p95 and max.',
    "parameters": {'samples_ms': 'number[]'},
    "run": run,
}
