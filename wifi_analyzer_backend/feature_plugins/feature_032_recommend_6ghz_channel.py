"""Recommend 6 GHz channel: Rank 6 GHz preferred scanning channels by observed occupancy."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    observed = [n for n in networks(p) if n.get("band") == "6GHz"]
    if not observed:
        return {"recommended_channel": None, "ranking": [], "status": "insufficient_observations", "basis": "no 6 GHz BSS observations supplied"}
    counts = congestion_map(observed)["6GHz"]
    candidates = list(range(5, 230, 16))
    ranked = sorted((counts.get(ch, 0), ch) for ch in candidates)
    return {"recommended_channel": ranked[0][1], "ranking": [{"channel": ch, "count": score} for score,ch in ranked], "status": "ranked", "basis": "observed channel counts; channel availability depends on regulatory domain"}

FEATURE = {
    "id": "F032",
    "slug": 'recommend_6ghz_channel',
    "name": 'Recommend 6 GHz channel',
    "category": 'RF planning',
    "description": 'Rank 6 GHz preferred scanning channels by observed occupancy.',
    "parameters": {},
    "run": run,
}
