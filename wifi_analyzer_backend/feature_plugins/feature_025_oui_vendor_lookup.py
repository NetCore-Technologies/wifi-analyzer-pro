"""OUI vendor lookup: Resolve common locally bundled OUI prefixes without making a network call."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    mac = mac_address(p.get("bssid", p.get("mac")))
    oui = mac[:8]
    vendors = {"B8:27:EB":"Raspberry Pi", "DC:A6:32":"Raspberry Pi", "E4:5F:01":"Raspberry Pi", "00:17:88":"Signify/Philips Hue", "F0:18:98":"Apple", "AC:BC:32":"Apple", "00:1A:11":"Google", "60:F1:89":"Xiaomi", "B4:86:55":"Samsung", "DC:A4:CA":"Espressif", "24:6F:28":"Espressif", "AC:FD:CE":"TP-Link", "50:C7:BF":"TP-Link", "00:0C:29":"VMware"}
    return {"bssid": mac, "oui": oui, "vendor": vendors.get(oui, "Unknown / not in local OUI subset"), "source": "bundled subset"}

FEATURE = {
    "id": "F025",
    "slug": 'oui_vendor_lookup',
    "name": 'OUI vendor lookup',
    "category": 'Discovery',
    "description": 'Resolve common locally bundled OUI prefixes without making a network call.',
    "parameters": {'bssid': 'MAC address'},
    "run": run,
}
