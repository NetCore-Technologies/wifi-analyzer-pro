"""IP in subnet check: Check whether an address belongs to a supplied subnet."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    net=ip_network(str(p.get("subnet",""))); addr=ipaddress.ip_address(str(p.get("ip","")))
    return {"ip":str(addr),"subnet":str(net),"contains":addr in net}

FEATURE = {
    "id": "F057",
    "slug": 'ip_in_subnet',
    "name": 'IP in subnet check',
    "category": 'Diagnostics',
    "description": 'Check whether an address belongs to a supplied subnet.',
    "parameters": {'ip': 'IP address', 'subnet': 'CIDR'},
    "run": run,
}
