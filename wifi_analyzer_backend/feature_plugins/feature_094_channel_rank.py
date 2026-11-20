"""Rank channels: Rank observed channel occupancy within a requested band."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    band=str(p.get("band","2.4GHz")); counts=congestion_map(networks(p)).get(band,{})
    ordered=sorted(counts.items(),key=lambda item:(item[1],item[0]))
    return {"band":band,"channels":[{"channel":ch,"count":count,"rank":idx+1} for idx,(ch,count) in enumerate(ordered)]}

FEATURE = {
    "id": "F094",
    "slug": 'channel_rank',
    "name": 'Rank channels',
    "category": 'RF planning',
    "description": 'Rank observed channel occupancy within a requested band.',
    "parameters": {'band': '2.4GHz|5GHz|6GHz'},
    "run": run,
}
