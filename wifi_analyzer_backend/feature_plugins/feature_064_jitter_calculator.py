"""Jitter calculator: Calculate mean absolute consecutive RTT variation."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    values=[number(v,-1) for v in p.get("samples_ms",[]) if number(v,-1)>=0]
    diffs=[abs(values[i]-values[i-1]) for i in range(1,len(values))]
    return {"jitter_ms":round(sum(diffs)/len(diffs),2) if diffs else None,"samples":len(values)}

FEATURE = {
    "id": "F064",
    "slug": 'jitter_calculator',
    "name": 'Jitter calculator',
    "category": 'Diagnostics',
    "description": 'Calculate mean absolute consecutive RTT variation.',
    "parameters": {'samples_ms': 'number[]'},
    "run": run,
}
