"""Parse Linux ARP/neighbour table: Parse common arp -an output into IP/MAC pairs."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    result=[]
    for line in str(p.get("text", "")).splitlines():
        m=re.search(r"\((\d+\.\d+\.\d+\.\d+)\).*?([0-9a-f]{2}(?::[0-9a-f]{2}){5})",line,re.I)
        if m: result.append({"ip":m.group(1),"mac":m.group(2).upper()})
    return {"devices":result,"count":len(result)}

FEATURE = {
    "id": "F049",
    "slug": 'parse_arp_linux',
    "name": 'Parse Linux ARP/neighbour table',
    "category": 'Parsers',
    "description": 'Parse common arp -an output into IP/MAC pairs.',
    "parameters": {'text': 'arp -an output'},
    "run": run,
}
