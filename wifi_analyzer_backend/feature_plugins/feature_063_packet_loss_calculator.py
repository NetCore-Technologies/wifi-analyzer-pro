"""Packet loss calculator: Calculate packet loss percentage from sent and received counters."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    sent=max(0,int(number(p.get("sent")))); received=max(0,int(number(p.get("received"))))
    if received>sent: raise ValueError("received cannot exceed sent")
    return {"sent":sent,"received":received,"lost":sent-received,"loss_percent":round((sent-received)*100/sent,2) if sent else None}

FEATURE = {
    "id": "F063",
    "slug": 'packet_loss_calculator',
    "name": 'Packet loss calculator',
    "category": 'Diagnostics',
    "description": 'Calculate packet loss percentage from sent and received counters.',
    "parameters": {'sent': 'integer', 'received': 'integer'},
    "run": run,
}
