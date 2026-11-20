"""DHCP lease audit: Find expired leases and duplicate IP or MAC assignments in a supplied DHCP lease snapshot."""
from __future__ import annotations
import math
import re
import statistics
from datetime import datetime, timezone

def _time(value):
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        raise ValueError("Lease expiry must be ISO-8601")
    return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result

def run(p: dict) -> dict:
    leases = p.get("leases", [])
    if not isinstance(leases, list):
        raise ValueError("'leases' must be a list")
    now = _time(p["now"]) if p.get("now") else datetime.now(timezone.utc)
    ips, macs, rows = {}, {}, []
    for lease in leases:
        if not isinstance(lease, dict) or not lease.get("ip") or not lease.get("mac"):
            raise ValueError("Each lease needs ip and mac")
        ip, mac = str(lease["ip"]), str(lease["mac"]).replace("-", ":").upper()
        try:
            import ipaddress
            ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError(f"Invalid lease IP address: {ip}")
        expiry = _time(lease.get("expires_at"))
        ips.setdefault(ip, set()).add(mac)
        macs.setdefault(mac, set()).add(ip)
        rows.append({"ip": ip, "mac": mac, "expires_at": expiry.isoformat(), "expired": expiry <= now})
    duplicate_ips = [{"ip": ip, "macs": sorted(values)} for ip, values in sorted(ips.items()) if len(values) > 1]
    duplicate_macs = [{"mac": mac, "ips": sorted(values)} for mac, values in sorted(macs.items()) if len(values) > 1]
    return {"leases": rows, "expired_leases": [row for row in rows if row["expired"]],
            "duplicate_ip_assignments": duplicate_ips, "duplicate_mac_assignments": duplicate_macs}

FEATURE = {
    "id": "F134",
    "slug": "dhcp_lease_audit",
    "name": "DHCP lease audit",
    "category": "Network operations",
    "description": "Find expired leases and duplicate IP or MAC assignments in a supplied DHCP lease snapshot.",
    "parameters": {"leases":"lease[]","now":"ISO-8601"},
    "run": run,
}
