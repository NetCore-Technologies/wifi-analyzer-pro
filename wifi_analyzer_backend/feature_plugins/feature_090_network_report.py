"""Network health report: Build a concise evidence-based report from supplied live observations."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    items=networks(p); signals=[number(n.get("rssi")) for n in items if n.get("rssi") is not None]
    open_count=sum(security_name(n).lower()=="open" for n in items)
    return {"network_count":len(items),"average_rssi":round(statistics.mean(signals),1) if signals else None,"weak_signal_count":sum(v<-75 for v in signals),"open_network_count":open_count,"band_counts":dict(Counter(n.get("band","unknown") for n in items)),"data_quality":"measured inputs only; unobserved metrics omitted"}

FEATURE = {
    "id": "F090",
    "slug": 'network_report',
    "name": 'Network health report',
    "category": 'Reports',
    "description": 'Build a concise evidence-based report from supplied live observations.',
    "parameters": {},
    "run": run,
}
