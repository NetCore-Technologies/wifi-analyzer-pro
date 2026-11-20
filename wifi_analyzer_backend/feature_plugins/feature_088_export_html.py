"""Export HTML report: Generate an escaped standalone HTML table report from scan observations."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    rows=[]
    for n in networks(p): rows.append("<tr>"+"".join(f"<td>{html_escape(n.get(k,''))}</td>" for k in ("ssid","bssid","band","channel","rssi","security"))+"</tr>")
    content="<!doctype html><meta charset=utf-8><title>Wi-Fi scan report</title><h1>Wi-Fi scan report</h1><table><thead><tr><th>SSID</th><th>BSSID</th><th>Band</th><th>Channel</th><th>RSSI</th><th>Security</th></tr></thead><tbody>"+"".join(rows)+"</tbody></table>"
    return {"content":content,"mime_type":"text/html","rows":len(rows)}

FEATURE = {
    "id": "F088",
    "slug": 'export_html',
    "name": 'Export HTML report',
    "category": 'Reports',
    "description": 'Generate an escaped standalone HTML table report from scan observations.',
    "parameters": {},
    "run": run,
}
