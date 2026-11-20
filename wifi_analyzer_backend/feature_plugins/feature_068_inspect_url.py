"""URL inspection: Validate a URL scheme and return parsed host, port and path without fetching it."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    from urllib.parse import urlsplit
    url=str(p.get("url","")); parsed=urlsplit(url)
    if parsed.scheme not in ("http","https") or not parsed.hostname: raise ValueError("Only absolute HTTP or HTTPS URLs are supported")
    if parsed.username or parsed.password: raise ValueError("URLs containing credentials are rejected")
    return {"scheme":parsed.scheme,"host":parsed.hostname,"port":parsed.port or (443 if parsed.scheme=="https" else 80),"path":parsed.path or "/","query_present":bool(parsed.query)}

FEATURE = {
    "id": "F068",
    "slug": 'inspect_url',
    "name": 'URL inspection',
    "category": 'Diagnostics',
    "description": 'Validate a URL scheme and return parsed host, port and path without fetching it.',
    "parameters": {'url': 'HTTP(S) URL'},
    "run": run,
}
