"""Subnet summary: Summarise an IPv4 or IPv6 interface/CIDR."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    raw=str(p.get("cidr",p.get("ip","")))
    net=ip_network(raw)
    return {"network":str(net),"version":net.version,"prefix_length":net.prefixlen,"num_addresses":net.num_addresses,"is_private":net.is_private,"is_global":net.is_global,"first_address":str(net.network_address),"last_address":str(net.broadcast_address) if net.version==4 else str(net[-1])}

FEATURE = {
    "id": "F056",
    "slug": 'subnet_summary',
    "name": 'Subnet summary',
    "category": 'Diagnostics',
    "description": 'Summarise an IPv4 or IPv6 interface/CIDR.',
    "parameters": {'cidr': 'IP/prefix'},
    "run": run,
}
