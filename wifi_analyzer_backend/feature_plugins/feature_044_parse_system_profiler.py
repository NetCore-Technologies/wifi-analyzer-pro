"""Parse macOS system_profiler JSON: Extract nearby wireless networks from system_profiler JSON."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    data=json.loads(str(p.get("text","{}"))); result=[]
    for iface in data.get("SPAirPortDataType",[]):
        for n in iface.get("spairport_airport_other_local_wireless_networks",[]):
            cm=re.search(r"\d+",str(n.get("spairport_network_channel",""))); ch=int(cm.group()) if cm else 0
            sig=str(n.get("spairport_signal_noise","")); rm=re.search(r"-?\d+",sig); rssi=int(rm.group()) if rm else None
            result.append({"ssid":safe_text(n.get("_name",""),32),"bssid":str(n.get("spairport_network_bssid","" )).upper(),"channel":ch,"band":"2.4GHz" if ch<=14 else "5GHz","rssi":rssi,"security":safe_text(n.get("spairport_security_mode","unknown"),48)})
    return {"networks":result,"count":len(result)}

FEATURE = {
    "id": "F044",
    "slug": 'parse_system_profiler',
    "name": 'Parse macOS system_profiler JSON',
    "category": 'Parsers',
    "description": 'Extract nearby wireless networks from system_profiler JSON.',
    "parameters": {'text': 'system_profiler JSON'},
    "run": run,
}
