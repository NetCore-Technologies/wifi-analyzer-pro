"""Interface counter delta: Calculate monotonic counter deltas and handle counter resets."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    before=p.get("before",{}); after=p.get("after",{}); result={}
    for key in set(before)|set(after):
        a=max(0,int(number(before.get(key)))); b=max(0,int(number(after.get(key))))
        result[key]={"delta":b-a if b>=a else b,"reset":b<a}
    return {"counters":result}

FEATURE = {
    "id": "F065",
    "slug": 'interface_counter_delta',
    "name": 'Interface counter delta',
    "category": 'Diagnostics',
    "description": 'Calculate monotonic counter deltas and handle counter resets.',
    "parameters": {'before': 'object', 'after': 'object'},
    "run": run,
}
