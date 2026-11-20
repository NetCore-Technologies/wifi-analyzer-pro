"""Parse macOS airport scan output: Parse the legacy airport -s tabular output."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    lines=str(p.get("text","")).splitlines()[1:]; result=[]
    for line in lines:
        parts=re.split(r"\s{2,}",line.strip())
        if len(parts)<7: continue
        chm=re.match(r"(\d+)",parts[3]); ch=int(chm.group(1)) if chm else 0
        result.append({"ssid":safe_text(parts[0],32),"bssid":parts[1].upper(),"rssi":number(parts[2]),"channel":ch,"band":"2.4GHz" if ch<=14 else "5GHz","security":parts[-1]})
    return {"networks":result,"count":len(result)}

FEATURE = {
    "id": "F043",
    "slug": 'parse_airport_scan',
    "name": 'Parse macOS airport scan output',
    "category": 'Parsers',
    "description": 'Parse the legacy airport -s tabular output.',
    "parameters": {'text': 'airport -s output'},
    "run": run,
}
