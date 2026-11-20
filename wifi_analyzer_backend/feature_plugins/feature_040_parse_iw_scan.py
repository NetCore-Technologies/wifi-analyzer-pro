"""Parse iw scan output: Parse Linux iw BSS blocks into structured network observations."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    text = str(p.get("text", "")); blocks = re.split(r"(?m)^BSS ([0-9a-f:]{17})", text, flags=re.I); result=[]
    for i in range(1, len(blocks), 2):
        bssid, body = blocks[i].upper(), blocks[i+1] if i+1 < len(blocks) else ""
        fm = re.search(r"(?m)^\s*freq: (\d+)", body); freq = int(fm.group(1)) if fm else 0
        sm = re.search(r"(?m)^\s*signal: (-?[0-9.]+) dBm", body); rssi = float(sm.group(1)) if sm else None
        ss = re.search(r"(?m)^\s*SSID: ?(.*)$", body)
        auth = "WPA3" if "SAE" in body.upper() else "WPA2" if "RSN:" in body.upper() else "WPA" if "WPA:" in body.upper() else "Open"
        result.append({"bssid":bssid,"ssid":safe_text(ss.group(1).strip() if ss else "",32),"frequency_mhz":freq,"channel":frequency_to_channel(freq),"band":band_from_frequency(freq),"rssi":rssi,"security":auth})
    return {"networks": result, "count": len(result)}

FEATURE = {
    "id": "F040",
    "slug": 'parse_iw_scan',
    "name": 'Parse iw scan output',
    "category": 'Parsers',
    "description": 'Parse Linux iw BSS blocks into structured network observations.',
    "parameters": {'text': 'iw scan output'},
    "run": run,
}
