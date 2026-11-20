"""Parse iw station dump: Extract station counters from iw station dump output."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    text=str(p.get("text","")); result={}
    patterns={"signal_dbm":r"signal:\s*(-?[0-9.]+) dBm","tx_bitrate_mbps":r"tx bitrate:\s*([0-9.]+) MBit/s","rx_bitrate_mbps":r"rx bitrate:\s*([0-9.]+) MBit/s","tx_retries":r"tx retries:\s*(\d+)","tx_failed":r"tx failed:\s*(\d+)","rx_bytes":r"rx bytes:\s*(\d+)","tx_bytes":r"tx bytes:\s*(\d+)"}
    for key,pat in patterns.items():
        m=re.search(pat,text,re.I)
        if m: result[key]=float(m.group(1)) if "." in m.group(1) else int(m.group(1))
    return result

FEATURE = {
    "id": "F045",
    "slug": 'parse_station_dump',
    "name": 'Parse iw station dump',
    "category": 'Parsers',
    "description": 'Extract station counters from iw station dump output.',
    "parameters": {'text': 'iw station dump'},
    "run": run,
}
