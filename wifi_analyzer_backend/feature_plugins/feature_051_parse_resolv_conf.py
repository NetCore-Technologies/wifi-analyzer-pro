"""Parse resolv.conf: Extract valid nameserver IPs from resolv.conf text."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    found=[]
    for value in re.findall(r"(?m)^\s*nameserver\s+(\S+)",str(p.get("text",""))):
        try: found.append(str(ipaddress.ip_address(value)))
        except ValueError: continue
    return {"dns_servers":list(dict.fromkeys(found))}

FEATURE = {
    "id": "F051",
    "slug": 'parse_resolv_conf',
    "name": 'Parse resolv.conf',
    "category": 'Parsers',
    "description": 'Extract valid nameserver IPs from resolv.conf text.',
    "parameters": {'text': 'resolv.conf text'},
    "run": run,
}
