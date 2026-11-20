"""Rogue AP candidates: Flag same-SSID BSSIDs that are not in a supplied trusted BSSID list."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    trusted={str(x).upper() for x in p.get("trusted_bssids",[])}; candidates=[]
    for n in networks(p):
        b=str(n.get("bssid","")).upper(); ssid=safe_text(n.get("ssid"),32)
        if ssid and b and b not in trusted and any(t.get("ssid")==ssid for t in p.get("trusted_networks",[]) if isinstance(t,dict)):
            candidates.append({"ssid":ssid,"bssid":b,"rssi":n.get("rssi"),"reason":"SSID matches a trusted network but BSSID is not trusted"})
    return {"candidates":candidates,"count":len(candidates),"note":"Candidate only; SSID similarity does not prove an evil twin"}

FEATURE = {
    "id": "F072",
    "slug": 'rogue_ap_candidates',
    "name": 'Rogue AP candidates',
    "category": 'Security',
    "description": 'Flag same-SSID BSSIDs that are not in a supplied trusted BSSID list.',
    "parameters": {'networks': 'network[]', 'trusted_bssids': 'string[]', 'trusted_networks': 'network[]'},
    "run": run,
}
