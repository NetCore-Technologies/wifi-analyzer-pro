"""Expose the offline UniFi Network export normalizer as a read-only feature tool."""
from __future__ import annotations

from ..router_adapters.unifi import normalize_snapshot


def run(payload: dict) -> dict:
    return normalize_snapshot(payload)


FEATURE = {
    "id": "F171",
    "slug": "unifi_snapshot_normalizer",
    "name": "UniFi controller snapshot normalizer",
    "category": "Router integrations",
    "description": (
        "Import caller-supplied UniFi Network exports into the common access-point, radio, "
        "client and network schema. Offline and read-only: it never logs into a controller."
    ),
    "parameters": {
        "captured_at": "timezone-aware ISO-8601 timestamp",
        "controller": "optional controller metadata object",
        "devices": "UniFi access-point device records",
        "clients": "UniFi client records",
        "networks": "UniFi network profile records",
    },
    "run": run,
}
