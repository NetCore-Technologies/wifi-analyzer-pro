"""Interface throughput: Calculate RX/TX throughput in Mbps from byte-counter snapshots."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    before=p.get("before",{}); after=p.get("after",{}); seconds=number(p.get("interval_seconds"))
    if seconds<=0: raise ValueError("interval_seconds must be positive")
    def delta(k):
        a=max(0,number(before.get(k))); b=max(0,number(after.get(k))); return max(0,b-a)
    return {"rx_mbps":round(delta("rx_bytes")*8/seconds/1e6,3),"tx_mbps":round(delta("tx_bytes")*8/seconds/1e6,3),"interval_seconds":seconds}

FEATURE = {
    "id": "F066",
    "slug": 'interface_throughput',
    "name": 'Interface throughput',
    "category": 'Diagnostics',
    "description": 'Calculate RX/TX throughput in Mbps from byte-counter snapshots.',
    "parameters": {'before': 'object', 'after': 'object', 'interval_seconds': 'number'},
    "run": run,
}
