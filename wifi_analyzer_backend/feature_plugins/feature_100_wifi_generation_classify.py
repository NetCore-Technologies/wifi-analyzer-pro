"""Wi-Fi generation classifier: Infer the highest advertised PHY generation from supplied PHY capability flags."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    flags = p.get("capabilities", p)
    generation = "Wi-Fi 7" if flags.get("eht") else "Wi-Fi 6/6E" if flags.get("he") else "Wi-Fi 5" if flags.get("vht") else "Wi-Fi 4" if flags.get("ht") else "unknown / legacy"
    band = str(p.get("band", "unknown"))
    if generation == "Wi-Fi 6/6E" and band == "6GHz": generation = "Wi-Fi 6E"
    return {"generation": generation, "band": band, "evidence": [k for k in ("eht","he","vht","ht") if flags.get(k)]}

FEATURE = {
    "id": "F100",
    "slug": 'wifi_generation_classify',
    "name": 'Wi-Fi generation classifier',
    "category": 'RF analysis',
    "description": 'Infer the highest advertised PHY generation from supplied PHY capability flags.',
    "parameters": {'capabilities': 'object', 'band': 'string'},
    "run": run,
}
