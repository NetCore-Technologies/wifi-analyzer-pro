"""Security warnings: Generate transparent warnings for open, WEP and legacy WPA observations."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    warnings=[]
    for n in networks(p):
        sec=security_name(n).lower(); reasons=[]
        if sec in ("open","none","unsecured"): reasons.append("No Wi-Fi link encryption advertised")
        if "wep" in sec: reasons.append("WEP is obsolete and insecure")
        if sec == "wpa" or sec.startswith("wpa "): reasons.append("Legacy WPA/TKIP may be weak")
        if reasons: warnings.append({"ssid":safe_text(n.get("ssid"),32) or "<hidden>","bssid":n.get("bssid"),"warnings":reasons})
    return {"warnings":warnings,"count":len(warnings)}

FEATURE = {
    "id": "F071",
    "slug": 'security_warnings',
    "name": 'Security warnings',
    "category": 'Security',
    "description": 'Generate transparent warnings for open, WEP and legacy WPA observations.',
    "parameters": {},
    "run": run,
}
