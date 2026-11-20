"""Security strength rank: Rank a network security mode from open through WPA3."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    value=str(p.get("security","unknown")).lower()
    rank=5 if "wpa3" in value or "sae" in value else 4 if "wpa2" in value else 3 if "wpa" in value else 2 if "wep" in value else 1 if value in ("open","none","unsecured") else 0
    return {"security":value,"rank":rank,"label":{5:"strong",4:"good",3:"legacy",2:"weak",1:"unsafe",0:"unknown"}[rank]}

FEATURE = {
    "id": "F070",
    "slug": 'security_rank',
    "name": 'Security strength rank',
    "category": 'Security',
    "description": 'Rank a network security mode from open through WPA3.',
    "parameters": {'security': 'string'},
    "run": run,
}
