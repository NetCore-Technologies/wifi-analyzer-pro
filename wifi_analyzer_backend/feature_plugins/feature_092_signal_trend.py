"""Signal trend: Estimate signal trend from ordered RSSI samples using least-squares slope."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    values=[number(v) for v in p.get("samples_dbm",[]) if v is not None]
    n=len(values)
    if n<2: return {"slope_dbm_per_sample":None,"trend":"insufficient_data","samples":n}
    xs=list(range(n)); mx=(n-1)/2; my=sum(values)/n
    denom=sum((x-mx)**2 for x in xs); slope=sum((x-mx)*(y-my) for x,y in zip(xs,values))/denom if denom else 0
    return {"slope_dbm_per_sample":round(slope,3),"trend":"improving" if slope>0.2 else "declining" if slope<-0.2 else "stable","samples":n}

FEATURE = {
    "id": "F092",
    "slug": 'signal_trend',
    "name": 'Signal trend',
    "category": 'History',
    "description": 'Estimate signal trend from ordered RSSI samples using least-squares slope.',
    "parameters": {'samples_dbm': 'number[]'},
    "run": run,
}
