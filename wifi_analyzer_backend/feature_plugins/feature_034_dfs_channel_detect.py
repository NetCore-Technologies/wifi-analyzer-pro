"""DFS channel check: Identify common 5 GHz DFS channels."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    ch = int(number(p.get("channel"), 0))
    is_dfs = 52 <= ch <= 144
    return {"channel": ch, "dfs": is_dfs, "note": "DFS rules and channel availability vary by country"}

FEATURE = {
    "id": "F034",
    "slug": 'dfs_channel_detect',
    "name": 'DFS channel check',
    "category": 'RF planning',
    "description": 'Identify common 5 GHz DFS channels.',
    "parameters": {'channel': 'integer'},
    "run": run,
}
