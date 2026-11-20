"""Alert severity classifier: Assign a severity for common Wi-Fi alert types."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    kind=str(p.get("type","info")).lower(); severity={"evil_twin":"critical","rogue_ap":"high","open_wifi":"medium","weak_signal":"low","scan_failed":"medium","packet_loss":"high","offline":"medium"}.get(kind,"info")
    return {"type":kind,"severity":severity}

FEATURE = {
    "id": "F083",
    "slug": 'alert_severity',
    "name": 'Alert severity classifier',
    "category": 'Alerts',
    "description": 'Assign a severity for common Wi-Fi alert types.',
    "parameters": {'type': 'string'},
    "run": run,
}
