"""Sticky-client candidates: Flag weak client associations when supplied AP-side observations show a stronger same-SSID alternative."""
from __future__ import annotations
import math
import statistics
from datetime import datetime

FEATURE = None

def run(p: dict) -> dict:
    clients = p.get("clients", [])
    if not isinstance(clients, list):
        raise ValueError("'clients' must be a list")
    weak = number(p.get("weak_rssi_dbm", -72), -72)
    improvement_min = number(p.get("min_improvement_db", 10), 10)
    if not -100 <= weak <= 0 or not 0 <= improvement_min <= 60:
        raise ValueError("RSSI threshold or improvement threshold is out of range")
    candidates = []
    for client in clients:
        if not isinstance(client, dict) or not client.get("client_mac"):
            raise ValueError("Each client requires client_mac")
        try:
            current_rssi = float(client["connected_rssi_dbm"])
        except (KeyError, TypeError, ValueError):
            continue
        if not math.isfinite(current_rssi) or current_rssi > weak:
            continue
        alternatives = client.get("alternatives", [])
        if not isinstance(alternatives, list):
            raise ValueError("Client alternatives must be a list")
        better = []
        for alternative in alternatives:
            if not isinstance(alternative, dict):
                continue
            try:
                rssi = float(alternative["rssi_dbm"])
            except (KeyError, TypeError, ValueError):
                continue
            delta = round(rssi - current_rssi, 1)
            if math.isfinite(rssi) and delta >= improvement_min and str(alternative.get("bssid") or "").upper() != str(client.get("connected_bssid") or "").upper():
                better.append({"bssid": alternative.get("bssid"), "rssi_dbm": rssi, "improvement_db": delta})
        if better:
            better.sort(key=lambda item: -item["improvement_db"])
            candidates.append({"client_mac": str(client["client_mac"]).upper(), "ssid": client.get("ssid"),
                               "connected_bssid": client.get("connected_bssid"), "connected_rssi_dbm": current_rssi,
                               "alternatives": better})
    return {"candidates": candidates, "count": len(candidates),
            "note": "Requires controller/AP-side client RSSI for each candidate BSSID; scan-side RSSI is not a substitute."}

FEATURE = {
    "id": "F106",
    "slug": "sticky_client_candidates",
    "name": "Sticky-client candidates",
    "category": "Roaming",
    "description": "Flag weak client associations when supplied AP-side observations show a stronger same-SSID alternative.",
    "parameters": {"clients":"client[]","weak_rssi_dbm":"number","min_improvement_db":"number"},
    "run": run,
}
