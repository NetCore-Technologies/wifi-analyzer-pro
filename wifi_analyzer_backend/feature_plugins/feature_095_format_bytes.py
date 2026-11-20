"""Format bytes: Format a byte count using IEC units."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    value=max(0,number(p.get("bytes"))); units=["B","KiB","MiB","GiB","TiB"]; idx=0
    while value>=1024 and idx<len(units)-1: value/=1024; idx+=1
    return {"formatted":f"{value:.2f} {units[idx]}"}

FEATURE = {
    "id": "F095",
    "slug": 'format_bytes',
    "name": 'Format bytes',
    "category": 'Utilities',
    "description": 'Format a byte count using IEC units.',
    "parameters": {'bytes': 'integer'},
    "run": run,
}
