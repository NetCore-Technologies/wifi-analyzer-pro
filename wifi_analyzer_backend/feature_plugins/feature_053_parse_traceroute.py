"""Parse traceroute output: Extract hop number, host and RTT samples from traceroute text."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    hops=[]
    for line in str(p.get("text","" )).splitlines():
        m=re.match(r"\s*(\d+)\s+(.*)",line)
        if not m: continue
        body=m.group(2); times=[float(x) for x in re.findall(r"([0-9.]+)\s*ms",body)]
        host=re.search(r"([\w.-]+)\s+\(([0-9a-fA-F:.]+)\)",body)
        hops.append({"hop":int(m.group(1)),"host":host.group(1) if host else None,"ip":host.group(2) if host else None,"rtt_ms":times,"timed_out":"*" in body and not times})
    return {"hops":hops,"count":len(hops)}

FEATURE = {
    "id": "F053",
    "slug": 'parse_traceroute',
    "name": 'Parse traceroute output',
    "category": 'Parsers',
    "description": 'Extract hop number, host and RTT samples from traceroute text.',
    "parameters": {'text': 'traceroute output'},
    "run": run,
}
