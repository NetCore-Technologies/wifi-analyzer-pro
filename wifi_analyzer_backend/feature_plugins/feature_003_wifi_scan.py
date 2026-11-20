"""Wi-Fi scan execution: Run the existing platform scanner, or validate supplied scan observations in a test/import workflow."""
from __future__ import annotations
import csv, datetime, html, ipaddress, json, math, re, statistics
from collections import Counter, defaultdict
from .common import networks, number, mac_address, band_from_frequency, frequency_to_channel, channel_to_frequency, signal_quality, security_name, congestion_map, safe_text, percentile, ip_network, html_escape

def run(p: dict) -> dict:
    if not isinstance(p, dict):
        raise ValueError("Feature input must be a JSON object")
    if "networks" in p:
        items = networks(p)
        return {"networks": items, "count": len(items), "source": str(p.get("source", "provided"))}
    # A PyInstaller one-file build runs the entry script as __main__, not as
    # an importable top-level server module. Reuse that already-loaded backend.
    import sys
    backend = sys.modules.get("__main__")
    if backend is None or not hasattr(backend, "scan"):
        try:
            from wifi_analyzer_backend import server as backend
        except ImportError:
            import server as backend
    items = backend.scan()
    return {"networks": items, "count": len(items), "source": "demo" if backend.DEMO_MODE else "live", "interface": backend.get_wifi_iface()}

FEATURE = {
    "id": "F003",
    "slug": 'wifi_scan',
    "name": 'Wi-Fi scan execution',
    "category": 'Discovery',
    "description": 'Run the existing platform scanner, or validate supplied scan observations in a test/import workflow.',
    "parameters": {'networks': 'optional network[]'},
    "run": run,
}
