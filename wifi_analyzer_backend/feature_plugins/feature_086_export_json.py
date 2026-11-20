"""Export JSON: Serialise current networks and optional metadata as formatted JSON."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    payload={"generated_at":p.get("generated_at"),"networks":networks(p),"metadata":p.get("metadata",{})}
    return {"content":json.dumps(payload,ensure_ascii=False,indent=2,default=str),"mime_type":"application/json"}

FEATURE = {
    "id": "F086",
    "slug": 'export_json',
    "name": 'Export JSON',
    "category": 'Reports',
    "description": 'Serialise current networks and optional metadata as formatted JSON.',
    "parameters": {},
    "run": run,
}
