"""Reverse DNS lookup: Resolve a supplied IP address using the system resolver."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    import socket
    address=str(ipaddress.ip_address(str(p.get("ip",""))))
    try:
        host=socket.gethostbyaddr(address)[0]
        return {"ip":address,"hostname":host,"resolved":True}
    except (OSError, socket.timeout): return {"ip":address,"hostname":None,"resolved":False}

FEATURE = {
    "id": "F060",
    "slug": 'reverse_dns_lookup',
    "name": 'Reverse DNS lookup',
    "category": 'Diagnostics',
    "description": 'Resolve a supplied IP address using the system resolver.',
    "parameters": {'ip': 'IP address'},
    "run": run,
}
