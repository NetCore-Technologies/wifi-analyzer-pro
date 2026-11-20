"""Parse ping output: Extract transmitted, received, loss and RTT summary from ping text."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    text=str(p.get("text","")); m=re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received,?\s*(\d+(?:\.\d+)?)% packet loss",text,re.I)
    times=[float(v) for v in re.findall(r"time[=<]([0-9.]+)\s*ms",text)]
    return {"transmitted":int(m.group(1)) if m else None,"received":int(m.group(2)) if m else None,"loss_percent":float(m.group(3)) if m else None,"rtt_min_ms":min(times) if times else None,"rtt_avg_ms":sum(times)/len(times) if times else None,"rtt_max_ms":max(times) if times else None,"samples":len(times)}

FEATURE = {
    "id": "F052",
    "slug": 'parse_ping_output',
    "name": 'Parse ping output',
    "category": 'Parsers',
    "description": 'Extract transmitted, received, loss and RTT summary from ping text.',
    "parameters": {'text': 'ping output'},
    "run": run,
}
