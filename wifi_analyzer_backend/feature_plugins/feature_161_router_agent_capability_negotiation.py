"""Negotiate a local router-agent capability contract without opening a network session."""
from __future__ import annotations

from ..router_adapters.registry import negotiate


def run(payload: dict) -> dict:
    return negotiate(payload)


FEATURE = {
    "id": "F161",
    "slug": "router_agent_capability_negotiation",
    "name": "Router agent capability negotiation",
    "category": "Router integrations",
    "description": "Match a router agent's advertised and requested capabilities against a versioned read-only adapter manifest, rejecting unsupported operations and writes.",
    "parameters": {
        "adapter_id": "string",
        "agent_version": "major.minor.patch",
        "advertised_capabilities": "string[]",
        "requested_capabilities": "string[]",
        "requested_permissions": "string[]",
    },
    "run": run,
}
