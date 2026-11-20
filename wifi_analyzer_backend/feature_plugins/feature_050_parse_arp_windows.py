"""Parse Windows ARP table: Parse arp -a IPv4 entries on Windows."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    result=[]
    for line in str(p.get("text", "")).splitlines():
        m=re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})\s+(dynamic|static)",line,re.I)
        if m: result.append({"ip":m.group(1),"mac":m.group(2).replace("-", ":").upper(),"type":m.group(3).lower()})
    return {"devices":result,"count":len(result)}

FEATURE = {
    "id": "F050",
    "slug": 'parse_arp_windows',
    "name": 'Parse Windows ARP table',
    "category": 'Parsers',
    "description": 'Parse arp -a IPv4 entries on Windows.',
    "parameters": {'text': 'Windows arp -a output'},
    "run": run,
}
