"""Disconnect reason summary: Classify and count IEEE 802.11 disassociation/deauthentication reason codes in supplied logs."""
from __future__ import annotations
import math
import re
import statistics
from datetime import datetime, timezone

REASONS = {
    1: "unspecified_reason", 2: "previous_authentication_no_longer_valid", 3: "station_leaving_network",
    4: "disassociated_due_to_inactivity", 5: "ap_unable_to_handle_all_stations",
    6: "class_2_frame_from_unauthenticated_station", 7: "class_3_frame_from_unassociated_station",
    8: "station_leaving_bss", 9: "station_not_authenticated", 14: "mic_failure",
    15: "four_way_handshake_timeout", 16: "group_key_handshake_timeout", 17: "information_element_mismatch",
    18: "invalid_group_cipher", 19: "invalid_pairwise_cipher", 20: "invalid_akmp",
    21: "unsupported_rsn_version", 22: "invalid_rsn_capabilities", 23: "ieee8021x_authentication_failure",
    24: "cipher_rejected_by_policy"
}

def run(p: dict) -> dict:
    events = p.get("events", [])
    if not isinstance(events, list):
        raise ValueError("'events' must be a list")
    counts, rows = {}, []
    for event in events:
        if not isinstance(event, dict):
            raise ValueError("Each event must be an object")
        try:
            code = int(event["reason_code"])
        except (KeyError, TypeError, ValueError):
            raise ValueError("Each event needs integer reason_code")
        if not 0 <= code <= 66:
            raise ValueError("reason_code must be within the IEEE reason-code range 0–66")
        label = REASONS.get(code, "reserved_or_vendor_specific")
        counts[code] = counts.get(code, 0) + 1
        rows.append({"reason_code": code, "classification": label,
                     "client_mac": event.get("client_mac"), "bssid": event.get("bssid")})
    return {"events": rows, "counts": [{"reason_code": code, "classification": REASONS.get(code, "reserved_or_vendor_specific"), "count": count} for code, count in sorted(counts.items())]}

FEATURE = {
    "id": "F138",
    "slug": "disconnect_reason_summary",
    "name": "Disconnect reason summary",
    "category": "Client operations",
    "description": "Classify and count IEEE 802.11 disassociation/deauthentication reason codes in supplied logs.",
    "parameters": {"events":"event[]"},
    "run": run,
}
