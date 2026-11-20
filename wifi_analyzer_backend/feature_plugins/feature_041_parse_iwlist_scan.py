"""Parse iwlist scan output: Parse common iwlist scan cells."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    result=[]
    for block in re.split(r"Cell \d+ -", str(p.get("text", "")))[1:]:
        def m(pattern):
            match=re.search(pattern,block,re.I); return match.group(1).strip() if match else ""
        ssid=m(r'ESSID:"([^"\n]*)"'); mac=m(r"Address: ([0-9a-f:]{17})"); fm=m(r"Frequency:([0-9.]+)"); ch=m(r"Channel:(\d+)"); sig=m(r"Signal level=(-?\d+)")
        freq=round(number(fm)*1000) if fm else 0
        result.append({"ssid":ssid,"bssid":mac.upper(),"frequency_mhz":freq,"channel":int(ch) if ch else frequency_to_channel(freq),"band":band_from_frequency(freq),"rssi":int(sig) if sig else None,"security":"WPA2" if "WPA2" in block.upper() else "WPA" if "WPA:" in block.upper() else "Open"})
    return {"networks":result,"count":len(result)}

FEATURE = {
    "id": "F041",
    "slug": 'parse_iwlist_scan',
    "name": 'Parse iwlist scan output',
    "category": 'Parsers',
    "description": 'Parse common iwlist scan cells.',
    "parameters": {'text': 'iwlist scan output'},
    "run": run,
}
