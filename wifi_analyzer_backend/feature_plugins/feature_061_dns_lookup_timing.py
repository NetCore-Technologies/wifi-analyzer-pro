"""DNS lookup timing: Time a hostname lookup using the system resolver."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    import socket,time
    host=str(p.get("host","example.com"));
    if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}",host): raise ValueError("Invalid hostname")
    start=time.perf_counter()
    try:
        answers=socket.getaddrinfo(host,None)
        return {"host":host,"duration_ms":round((time.perf_counter()-start)*1000,2),"addresses":list(dict.fromkeys(x[4][0] for x in answers))}
    except OSError as exc: return {"host":host,"duration_ms":round((time.perf_counter()-start)*1000,2),"error":str(exc)}

FEATURE = {
    "id": "F061",
    "slug": 'dns_lookup_timing',
    "name": 'DNS lookup timing',
    "category": 'Diagnostics',
    "description": 'Time a hostname lookup using the system resolver.',
    "parameters": {'host': 'hostname'},
    "run": run,
}
