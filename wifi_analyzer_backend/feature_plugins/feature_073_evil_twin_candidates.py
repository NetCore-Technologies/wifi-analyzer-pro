"""Evil-twin similarity check: Find different BSSIDs advertising the same non-empty SSID."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    groups=defaultdict(list)
    for n in networks(p):
        ssid=safe_text(n.get("ssid"),32)
        if ssid: groups[ssid].append(n)
    matches=[]
    for ssid,items in groups.items():
        bssids={str(n.get("bssid","" )).upper() for n in items if n.get("bssid")}
        if len(bssids)>1: matches.append({"ssid":ssid,"bssids":sorted(bssids),"count":len(bssids),"note":"Multi-AP SSIDs are normal; compare against your trusted BSSID inventory"})
    return {"groups":matches,"count":len(matches)}

FEATURE = {
    "id": "F073",
    "slug": 'evil_twin_candidates',
    "name": 'Evil-twin similarity check',
    "category": 'Security',
    "description": 'Find different BSSIDs advertising the same non-empty SSID.',
    "parameters": {},
    "run": run,
}
