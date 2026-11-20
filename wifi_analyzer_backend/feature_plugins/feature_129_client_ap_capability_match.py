"""Client/AP capability compatibility: Compare advertised client and AP band/feature sets and list unsupported client requirements."""
from __future__ import annotations
import math
import re
import statistics
from datetime import datetime, timezone

def run(p: dict) -> dict:
    clients, aps = p.get("clients", []), p.get("access_points", [])
    if not isinstance(clients, list) or not isinstance(aps, list):
        raise ValueError("clients and access_points must be lists")
    ap_index = {}
    for ap in aps:
        if not isinstance(ap, dict) or not ap.get("bssid"):
            raise ValueError("Each AP needs a bssid")
        key = str(ap["bssid"]).replace("-", ":").upper()
        ap_index[key] = ap
    results = []
    for client in clients:
        if not isinstance(client, dict) or not client.get("client_mac"):
            raise ValueError("Each client needs client_mac")
        bssid = str(client.get("bssid") or "").replace("-", ":").upper()
        ap = ap_index.get(bssid)
        if ap is None:
            results.append({"client_mac": str(client["client_mac"]).upper(), "bssid": bssid or None, "status": "ap_not_in_inventory"})
            continue
        client_bands = set(client.get("supported_bands", []))
        ap_bands = set(ap.get("supported_bands", []))
        client_features = set(client.get("required_features", []))
        ap_features = set(ap.get("supported_features", []))
        results.append({
            "client_mac": str(client["client_mac"]).upper(), "bssid": bssid,
            "common_bands": sorted(client_bands & ap_bands),
            "unsupported_client_bands": sorted(client_bands - ap_bands),
            "unsupported_required_features": sorted(client_features - ap_features),
            "status": "compatible" if client_bands & ap_bands and not (client_features - ap_features) else "review",
        })
    return {"assessments": results, "client_count": len(results),
            "note": "Requires explicit AP/client capability inventories; an absent capability is not assumed unsupported."}

FEATURE = {
    "id": "F129",
    "slug": "client_ap_capability_match",
    "name": "Client/AP capability compatibility",
    "category": "Client operations",
    "description": "Compare advertised client and AP band/feature sets and list unsupported client requirements.",
    "parameters": {"clients":"client[]","access_points":"AP[]"},
    "run": run,
}
