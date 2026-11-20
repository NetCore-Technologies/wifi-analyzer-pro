"""Association rejection summary: Classify IEEE 802.11 association response status codes from supplied AP/controller logs."""
from __future__ import annotations
import math
import re
import statistics
from datetime import datetime, timezone

STATUS = {
    0: "successful", 1: "unspecified_failure", 10: "unsupported_capabilities",
    11: "reassociation_without_association", 12: "association_denied_for_reason_outside_scope",
    13: "unsupported_authentication_algorithm", 14: "authentication_sequence_number_out_of_sequence",
    17: "ap_unable_to_handle_additional_stations", 18: "unsupported_data_rates",
    30: "temporarily_rejected", 31: "robust_management_frame_policy_violation",
    40: "invalid_ie", 41: "invalid_group_cipher", 42: "invalid_pairwise_cipher",
    43: "invalid_akmp", 44: "unsupported_rsn_version", 45: "invalid_rsn_capabilities"
}

def run(p: dict) -> dict:
    events = p.get("events", [])
    if not isinstance(events, list):
        raise ValueError("'events' must be a list")
    counts, rows = {}, []
    for event in events:
        if not isinstance(event, dict):
            raise ValueError("Each event must be an object")
        code = int(event.get("status_code", -1))
        if not 0 <= code <= 255:
            raise ValueError("status_code must be 0–255")
        label = STATUS.get(code, "other_or_vendor_specific")
        counts[code] = counts.get(code, 0) + 1
        rows.append({"status_code": code, "classification": label, "client_mac": event.get("client_mac")})
    return {"events": rows, "counts": [{"status_code": code, "classification": STATUS.get(code, "other_or_vendor_specific"), "count": count} for code, count in sorted(counts.items())],
            "rejection_count": sum(count for code, count in counts.items() if code != 0)}

FEATURE = {
    "id": "F139",
    "slug": "association_rejection_summary",
    "name": "Association rejection summary",
    "category": "Client operations",
    "description": "Classify IEEE 802.11 association response status codes from supplied AP/controller logs.",
    "parameters": {"events":"event[]"},
    "run": run,
}
