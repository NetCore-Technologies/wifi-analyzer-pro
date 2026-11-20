"""Alert threshold evaluator: Compare a numeric metric with a configured warning/critical threshold."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    value=number(p.get("value")); warning=number(p.get("warning")); critical=number(p.get("critical"),warning)
    if critical<warning: warning,critical=critical,warning
    status="critical" if value>=critical else "warning" if value>=warning else "normal"
    return {"value":value,"warning":warning,"critical":critical,"status":status}

FEATURE = {
    "id": "F085",
    "slug": 'alert_threshold',
    "name": 'Alert threshold evaluator',
    "category": 'Alerts',
    "description": 'Compare a numeric metric with a configured warning/critical threshold.',
    "parameters": {'value': 'number', 'warning': 'number', 'critical': 'number'},
    "run": run,
}
