"""Parse iw link: Extract connected SSID, BSSID, frequency and signal from iw link."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    text=str(p.get("text","")); patterns={"ssid":r"SSID: (.+)","bssid":r"Connected to ([0-9a-f:]{17})","frequency_mhz":r"freq:\s*(\d+)","signal_dbm":r"signal:\s*(-?[0-9.]+) dBm","tx_bitrate_mbps":r"tx bitrate:\s*([0-9.]+) MBit/s"}; result={}
    for key,pat in patterns.items():
        m=re.search(pat,text,re.I)
        if m: result[key]=m.group(1).strip() if key=="ssid" else m.group(1).upper() if key=="bssid" else number(m.group(1))
    if "frequency_mhz" in result: result["band"]=band_from_frequency(result["frequency_mhz"])
    return result

FEATURE = {
    "id": "F046",
    "slug": 'parse_iw_link',
    "name": 'Parse iw link',
    "category": 'Parsers',
    "description": 'Extract connected SSID, BSSID, frequency and signal from iw link.',
    "parameters": {'text': 'iw link output'},
    "run": run,
}
