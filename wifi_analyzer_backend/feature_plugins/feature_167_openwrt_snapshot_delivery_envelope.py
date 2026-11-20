"""Validate idempotent OpenWrt snapshot-delivery envelopes before persistence."""
from __future__ import annotations

import re
import uuid

from ..router_adapters.openwrt import normalize_snapshot

_AGENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    agent_id = payload.get("agent_id")
    if not isinstance(agent_id, str) or not _AGENT_ID.fullmatch(agent_id):
        raise ValueError("agent_id must be a 1 to 64 character identifier")
    delivery_id = payload.get("delivery_id")
    if not isinstance(delivery_id, str) or len(delivery_id) > 64:
        raise ValueError("delivery_id must be a UUID string")
    try:
        delivery_id = str(uuid.UUID(delivery_id))
    except (ValueError, AttributeError, TypeError) as error:
        raise ValueError("delivery_id must be a UUID string") from error
    snapshot = normalize_snapshot(payload.get("snapshot"))
    return {
        "agent_id": agent_id,
        "delivery_id": delivery_id,
        "snapshot": snapshot,
        "summary": snapshot["summary"],
        "note": (
            "The stable delivery ID makes retries idempotent for the retained delivery window. "
            "Only normalised, credential-free snapshot fields are persisted."
        ),
    }


FEATURE = {
    "id": "F167",
    "slug": "openwrt_snapshot_delivery_envelope",
    "name": "OpenWrt idempotent snapshot delivery",
    "category": "Router integrations",
    "description": "Validate a stable UUID delivery ID and bounded OpenWrt snapshot before idempotent, retry-safe persistence by a credential-scoped agent.",
    "parameters": {"agent_id": "string", "delivery_id": "UUID", "snapshot": "OpenWrt snapshot"},
    "run": run,
}
