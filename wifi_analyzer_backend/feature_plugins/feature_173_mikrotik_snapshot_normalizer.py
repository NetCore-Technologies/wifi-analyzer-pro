"""Expose the offline MikroTik RouterOS export normalizer as a read-only feature."""
from __future__ import annotations

from ..router_adapters.mikrotik import normalize_snapshot


def run(payload: dict) -> dict:
    return normalize_snapshot(payload)


FEATURE = {
    "id": "F173",
    "slug": "mikrotik_snapshot_normalizer",
    "name": "MikroTik RouterOS snapshot normalizer",
    "category": "Router integrations",
    "description": (
        "Import caller-supplied RouterOS exports into a common router, interface, wireless, "
        "registration, address, VLAN and DHCP lease schema. Offline and read-only."
    ),
    "parameters": {
        "captured_at": "timezone-aware ISO-8601 timestamp",
        "router": "optional RouterOS identity metadata",
        "resource": "optional uptime, CPU and memory statistics",
        "interfaces": "RouterOS interface records",
        "wireless": "RouterOS wireless interface records",
        "registrations": "wireless registration table records",
        "addresses": "IP interface address records",
        "vlans": "VLAN interface records",
        "dhcp_leases": "DHCP lease records",
    },
    "run": run,
}
