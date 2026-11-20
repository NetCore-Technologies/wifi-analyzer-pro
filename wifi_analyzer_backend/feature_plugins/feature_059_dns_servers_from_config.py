"""DNS server extraction: Collect DNS resolver addresses from resolv.conf or supplied list."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    values=p.get("dns_servers") if isinstance(p.get("dns_servers"),list) else re.findall(r"(?m)^\s*nameserver\s+(\S+)",str(p.get("text","")))
    result=[]
    for value in values:
        try: result.append(str(ipaddress.ip_address(value)))
        except ValueError: continue
    return {"dns_servers":list(dict.fromkeys(result))}

FEATURE = {
    "id": "F059",
    "slug": 'dns_servers_from_config',
    "name": 'DNS server extraction',
    "category": 'Diagnostics',
    "description": 'Collect DNS resolver addresses from resolv.conf or supplied list.',
    "parameters": {},
    "run": run,
}
