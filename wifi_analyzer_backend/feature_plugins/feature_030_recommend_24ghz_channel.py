"""Recommend 2.4 GHz channel: Rank channels 1, 6 and 11 by observed adjacent BSS count."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    observed = [n for n in networks(p) if n.get("band") == "2.4GHz"]
    if not observed:
        return {"recommended_channel": None, "ranking": [], "status": "insufficient_observations", "basis": "no 2.4 GHz BSS observations supplied"}
    counts = congestion_map(observed)["2.4GHz"]
    ranked = sorted((sum(counts.get(ch, 0) for ch in range(max(1,ch-2), min(14,ch+3)+1)), ch) for ch in (1,6,11))
    return {"recommended_channel": ranked[0][1], "ranking": [{"channel": ch, "score": score} for score,ch in ranked], "status": "ranked", "basis": "observed BSS overlap counts"}

FEATURE = {
    "id": "F030",
    "slug": 'recommend_24ghz_channel',
    "name": 'Recommend 2.4 GHz channel',
    "category": 'RF planning',
    "description": 'Rank channels 1, 6 and 11 by observed adjacent BSS count.',
    "parameters": {},
    "run": run,
}
