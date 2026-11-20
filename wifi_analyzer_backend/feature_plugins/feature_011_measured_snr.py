"""Measured SNR: Calculate SNR only when a real noise measurement was supplied."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    rssi, noise = p.get("rssi"), p.get("noise")
    if rssi is None or noise is None:
        return {"snr_db": None, "available": False, "reason": "RSSI and noise measurements are both required"}
    return {"snr_db": round(number(rssi) - number(noise), 1), "available": True}

FEATURE = {
    "id": "F011",
    "slug": 'measured_snr',
    "name": 'Measured SNR',
    "category": 'RF analysis',
    "description": 'Calculate SNR only when a real noise measurement was supplied.',
    "parameters": {'rssi': 'number', 'noise': 'number'},
    "run": run,
}
