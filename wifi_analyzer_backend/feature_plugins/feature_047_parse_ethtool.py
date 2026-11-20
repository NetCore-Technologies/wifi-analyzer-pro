"""Parse ethtool link details: Parse speed, duplex, link state and autonegotiation from ethtool output."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    text=str(p.get("text","")); result={}
    for key,pat,cast in [("speed_mbps",r"Speed:\s*(\d+)Mb/s",int),("duplex",r"Duplex:\s*(Full|Half)",str),("link_detected",r"Link detected:\s*(yes|no)",str),("autonegotiation",r"Auto-negotiation:\s*(on|off)",str)]:
        m=re.search(pat,text,re.I)
        if m: result[key]=cast(m.group(1).lower() if cast is str else m.group(1))
    if "link_detected" in result: result["link_detected"]=result["link_detected"]=="yes"
    return result

FEATURE = {
    "id": "F047",
    "slug": 'parse_ethtool',
    "name": 'Parse ethtool link details',
    "category": 'Parsers',
    "description": 'Parse speed, duplex, link state and autonegotiation from ethtool output.',
    "parameters": {'text': 'ethtool output'},
    "run": run,
}
