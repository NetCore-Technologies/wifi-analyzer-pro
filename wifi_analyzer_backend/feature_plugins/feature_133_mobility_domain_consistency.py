"""Mobility domain consistency: Find same-ESS APs with missing or inconsistent 802.11r mobility-domain identifiers."""
from __future__ import annotations
import math
import re
import statistics
from datetime import datetime, timezone

def run(p: dict) -> dict:
    aps = p.get("access_points", [])
    if not isinstance(aps, list):
        raise ValueError("'access_points' must be a list")
    groups = {}
    for ap in aps:
        if not isinstance(ap, dict) or not ap.get("ssid"):
            raise ValueError("Each AP needs ssid")
        domain = str(ap.get("mobility_domain") or "").replace(":", "").upper() or None
        if domain and not re.fullmatch(r"[0-9A-F]{4}", domain):
            raise ValueError("mobility_domain must be a four-digit hexadecimal value")
        groups.setdefault(str(ap["ssid"]), []).append({"bssid": ap.get("bssid"), "mobility_domain": domain, "ft_enabled": ap.get("dot11r_fast_transition")})
    findings = []
    for ssid, records in sorted(groups.items()):
        domains = {item["mobility_domain"] for item in records if item["mobility_domain"]}
        missing = [item["bssid"] for item in records if not item["mobility_domain"]]
        disabled = [item["bssid"] for item in records if item["ft_enabled"] is False]
        findings.append({"ssid": ssid, "ap_count": len(records), "mobility_domains": sorted(domains),
                         "inconsistent": len(domains) > 1 or bool(missing), "missing_domain_bssids": missing,
                         "ft_explicitly_disabled_bssids": disabled})
    return {"ess_groups": findings, "group_count": len(findings),
            "note": "Same SSID does not always mean the same ESS; confirm the network design before changing mobility settings."}

FEATURE = {
    "id": "F133",
    "slug": "mobility_domain_consistency",
    "name": "Mobility domain consistency",
    "category": "Roaming",
    "description": "Find same-ESS APs with missing or inconsistent 802.11r mobility-domain identifiers.",
    "parameters": {"access_points":"AP[]"},
    "run": run,
}
