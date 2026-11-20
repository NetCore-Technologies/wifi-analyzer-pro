"""Validate and normalise a snapshot submission from a registered OpenWrt agent."""
from __future__ import annotations

import re

from ..router_adapters.openwrt import normalize_snapshot

_AGENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    agent_id = payload.get("agent_id")
    if not isinstance(agent_id, str) or not _AGENT_ID.fullmatch(agent_id):
        raise ValueError("agent_id must be a 1 to 64 character identifier")
    snapshot = normalize_snapshot(payload.get("snapshot"))
    return {
        "agent_id": agent_id,
        "adapter_id": "openwrt",
        "snapshot": snapshot,
        "summary": snapshot["summary"],
        "note": "The submitted data is normalised before storage; unrecognised and credential-like fields are excluded.",
    }


FEATURE = {
    "id": "F164",
    "slug": "openwrt_agent_snapshot_ingest",
    "name": "OpenWrt agent snapshot ingestion",
    "category": "Router integrations",
    "description": "Validate an identified OpenWrt agent snapshot envelope, normalise router telemetry and return only the credential-free common schema for bounded persistence.",
    "parameters": {"agent_id": "string", "snapshot": "OpenWrt snapshot"},
    "run": run,
}
