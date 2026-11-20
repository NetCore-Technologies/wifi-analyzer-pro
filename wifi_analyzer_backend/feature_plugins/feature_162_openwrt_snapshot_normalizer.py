"""Normalise a bounded OpenWrt agent snapshot into the common router inventory schema."""
from __future__ import annotations
from ..router_adapters.openwrt import normalize_snapshot

def run(payload: dict) -> dict:
    return normalize_snapshot(payload)

FEATURE = {
    "id":"F162",
    "slug":"openwrt_snapshot_normalizer",
    "name":"OpenWrt snapshot normalizer",
    "category":"Router integrations",
    "description":"Convert supplied OpenWrt board, interface, wireless, association and route records into a bounded common schema while dropping unrecognised and credential-like fields.",
    "parameters":{"captured_at":"ISO-8601","board":"object","interfaces":"interface[]","wireless":"radio[]","associations":"association[]","routes":"route[]"},
    "run":run,
}
