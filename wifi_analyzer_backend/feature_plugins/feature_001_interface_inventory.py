"""Interface inventory: List local interfaces, addresses, status and MTU."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    import psutil
    output = []
    for name, addrs in psutil.net_if_addrs().items():
        stats = psutil.net_if_stats().get(name)
        output.append({"name": name, "is_up": bool(stats.isup) if stats else None,
                       "speed_mbps": stats.speed if stats else None,
                       "mtu": stats.mtu if stats else None,
                       "addresses": [{"family": str(a.family), "address": a.address,
                                      "netmask": a.netmask, "broadcast": a.broadcast} for a in addrs]})
    return {"interfaces": output}

FEATURE = {
    "id": "F001",
    "slug": 'interface_inventory',
    "name": 'Interface inventory',
    "category": 'Discovery',
    "description": 'List local interfaces, addresses, status and MTU.',
    "parameters": {},
    "run": run,
}
