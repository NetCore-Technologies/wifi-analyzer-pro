"""Parse Windows netsh scan output: Parse netsh wlan show networks mode=bssid text."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    result=[]
    for block in re.split(r"SSID \d+ :", str(p.get("text", "")))[1:]:
        sm=re.search(r"^\s*(.*)",block); ssid=safe_text(sm.group(1).strip() if sm else "",32)
        bm=re.search(r"BSSID \d+\s*:\s*([0-9a-f:-]{17})",block,re.I); cm=re.search(r"Channel\s*:\s*(\d+)",block); pm=re.search(r"Signal\s*:\s*(\d+)%",block); am=re.search(r"Authentication\s*:\s*(.+)",block)
        ch=int(cm.group(1)) if cm else 0; band="2.4GHz" if ch and ch<=14 else "5GHz"
        result.append({"ssid":ssid,"bssid":bm.group(1).replace("-",":").upper() if bm else "","channel":ch,"band":band,"rssi":round(int(pm.group(1))/2-100,1) if pm else None,"security":safe_text(am.group(1).strip() if am else "unknown",48)})
    return {"networks":result,"count":len(result)}

FEATURE = {
    "id": "F042",
    "slug": 'parse_netsh_scan',
    "name": 'Parse Windows netsh scan output',
    "category": 'Parsers',
    "description": 'Parse netsh wlan show networks mode=bssid text.',
    "parameters": {'text': 'netsh scan output'},
    "run": run,
}
