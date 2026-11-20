"""Packet error rate: Compute RX/TX error ratio from interface packet counters."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    stats=p.get("stats",{}); rx=max(0,number(stats.get("rx_packets"))); tx=max(0,number(stats.get("tx_packets"))); errors=max(0,number(stats.get("rx_errors")))+max(0,number(stats.get("tx_errors")))
    total=rx+tx
    return {"errors":int(errors),"packets":int(total),"error_percent":round(errors*100/total,4) if total else None}

FEATURE = {
    "id": "F067",
    "slug": 'packet_error_rate',
    "name": 'Packet error rate',
    "category": 'Diagnostics',
    "description": 'Compute RX/TX error ratio from interface packet counters.',
    "parameters": {'stats': 'object'},
    "run": run,
}
