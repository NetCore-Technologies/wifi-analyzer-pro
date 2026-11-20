"""Client association inventory: Join AP/controller client associations to advertised BSS records and report unmatched associations."""
from __future__ import annotations
import math
import re
import statistics
from datetime import datetime, timezone

def _mac(value):
    raw = str(value or "").replace("-", ":").upper()
    if not re.fullmatch(r"[0-9A-F]{2}(?::[0-9A-F]{2}){5}", raw):
        raise ValueError("Each client/AP record needs a valid MAC address")
    return raw

def run(p: dict) -> dict:
    clients, aps = p.get("clients", []), p.get("access_points", [])
    if not isinstance(clients, list) or not isinstance(aps, list):
        raise ValueError("clients and access_points must be lists")
    ap_index = {}
    for ap in aps:
        if not isinstance(ap, dict):
            raise ValueError("Each AP must be an object")
        key = _mac(ap.get("bssid"))
        if key in ap_index:
            raise ValueError("Duplicate AP BSSID in inventory")
        ap_index[key] = ap
    records, unmatched = [], []
    seen = set()
    counts = {}
    for client in clients:
        if not isinstance(client, dict):
            raise ValueError("Each client must be an object")
        mac = _mac(client.get("client_mac", client.get("mac")))
        if mac in seen:
            raise ValueError("Duplicate client MAC in association snapshot")
        seen.add(mac)
        raw_bssid = client.get("bssid")
        bssid = _mac(raw_bssid) if raw_bssid else None
        ap = ap_index.get(bssid) if bssid else None
        if not ap:
            unmatched.append(mac)
        else:
            counts[bssid] = counts.get(bssid, 0) + 1
        records.append({"client_mac": mac, "bssid": bssid, "ssid": client.get("ssid") or (ap or {}).get("ssid"),
                        "ap_name": (ap or {}).get("name"), "band": (ap or {}).get("band"),
                        "association_match": ap is not None})
    return {"clients": records, "client_count": len(records), "matched_count": len(records)-len(unmatched),
            "unmatched_clients": unmatched, "clients_per_bssid": counts}

FEATURE = {
    "id": "F121",
    "slug": "client_association_inventory",
    "name": "Client association inventory",
    "category": "Client operations",
    "description": "Join AP/controller client associations to advertised BSS records and report unmatched associations.",
    "parameters": {"clients":"client[]","access_points":"AP[]"},
    "run": run,
}
