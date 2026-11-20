"""Prometheus scan metrics: Export counts and RSSI gauges in Prometheus text format."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    items=networks(p); counts=Counter(str(n.get("band","unknown")) for n in items)
    lines=["wifi_analyzer_networks_total "+str(len(items))]
    for band,count in sorted(counts.items()): lines.append(f'wifi_analyzer_networks_by_band{{band="{band}"}} {count}')
    for n in items:
        if n.get("rssi") is not None:
            label = str(n.get("bssid", "unknown"))
            label = label.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
            lines.append(f'wifi_analyzer_rssi_dbm{{bssid="{label}"}} {number(n.get("rssi"))}')
    return {"content":"\n".join(lines)+"\n","mime_type":"text/plain; version=0.0.4"}

FEATURE = {
    "id": "F089",
    "slug": 'prometheus_metrics',
    "name": 'Prometheus scan metrics',
    "category": 'Integrations',
    "description": 'Export counts and RSSI gauges in Prometheus text format.',
    "parameters": {},
    "run": run,
}
