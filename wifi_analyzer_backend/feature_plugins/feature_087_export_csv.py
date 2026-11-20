"""Export CSV: Export network records as RFC-compliant CSV."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    import csv,io
    items=networks(p); fields=["ssid","bssid","band","channel","frequency","rssi","noise","snr","security"]
    stream=io.StringIO(newline=""); writer=csv.DictWriter(stream,fieldnames=fields,extrasaction="ignore",lineterminator="\n"); writer.writeheader()
    for n in items: writer.writerow(n)
    return {"content":stream.getvalue(),"mime_type":"text/csv","rows":len(items)}

FEATURE = {
    "id": "F087",
    "slug": 'export_csv',
    "name": 'Export CSV',
    "category": 'Reports',
    "description": 'Export network records as RFC-compliant CSV.',
    "parameters": {},
    "run": run,
}
