"""Scan fingerprint: Fingerprint a canonicalised scan for integrity/change tracking."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    import hashlib
    items=sorted(networks(p),key=lambda n:(str(n.get("bssid","")),str(n.get("ssid",""))))
    canonical=[{k:n.get(k) for k in ("ssid","bssid","band","channel","rssi","security")} for n in items]
    digest=hashlib.sha256(json.dumps(canonical,sort_keys=True,separators=(",",":"),default=str).encode()).hexdigest()
    return {"sha256":digest,"records":len(items)}

FEATURE = {
    "id": "F082",
    "slug": 'scan_fingerprint',
    "name": 'Scan fingerprint',
    "category": 'Privacy',
    "description": 'Fingerprint a canonicalised scan for integrity/change tracking.',
    "parameters": {},
    "run": run,
}
