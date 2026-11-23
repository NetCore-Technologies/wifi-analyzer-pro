"""Classify stored router-agent heartbeats using server-side timestamps."""
from __future__ import annotations

from datetime import datetime, timezone


MAX_AGENTS = 256


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone offset")
    return parsed.astimezone(timezone.utc)


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    agents = payload.get("agents", [])
    if not isinstance(agents, list) or len(agents) > MAX_AGENTS:
        raise ValueError(f"agents must be a list containing no more than {MAX_AGENTS} records")
    now = _parse_time(payload.get("now"), "now")
    stale_after = payload.get("stale_after_seconds", 180)
    if isinstance(stale_after, bool) or not isinstance(stale_after, int) or not 10 <= stale_after <= 86400:
        raise ValueError("stale_after_seconds must be an integer between 10 and 86400")

    seen = set()
    results = []
    for index, agent in enumerate(agents):
        if not isinstance(agent, dict):
            raise ValueError(f"agents[{index}] must be an object")
        agent_id = agent.get("agent_id")
        if not isinstance(agent_id, str) or not agent_id.strip() or len(agent_id) > 64:
            raise ValueError(f"agents[{index}].agent_id is invalid")
        if agent_id in seen:
            raise ValueError("agent_id values must be unique")
        seen.add(agent_id)
        last_seen = _parse_time(agent.get("last_seen_at"), f"agents[{index}].last_seen_at")
        age = (now - last_seen).total_seconds()
        reported = agent.get("status", "unknown")
        if not isinstance(reported, str) or reported not in {"healthy", "degraded", "unhealthy"}:
            raise ValueError(f"agents[{index}].status is invalid")
        if age < -60:
            effective = "future_timestamp"
        elif age > stale_after:
            effective = "stale"
        else:
            effective = reported
        error_code = agent.get("error_code")
        if error_code is not None and (not isinstance(error_code, str) or len(error_code) > 40):
            raise ValueError(f"agents[{index}].error_code is invalid")
        capabilities = agent.get("capabilities", [])
        if not isinstance(capabilities, list) or len(capabilities) > 64:
            raise ValueError(f"agents[{index}].capabilities must be a bounded list")
        results.append({
            "agent_id": agent_id,
            "adapter_id": agent.get("adapter_id"),
            "site_id": agent.get("site_id"),
            "agent_version": agent.get("agent_version"),
            "reported_status": reported,
            "health_status": effective,
            "last_seen_at": last_seen.isoformat(),
            "age_seconds": round(max(0.0, age), 3),
            "error_code": agent.get("error_code"),
            "capabilities": sorted(set(item for item in capabilities if isinstance(item, str))),
        })
    results.sort(key=lambda item: item["agent_id"])
    counts = {key: sum(item["health_status"] == key for item in results)
              for key in ("healthy", "degraded", "unhealthy", "stale", "future_timestamp")}
    return {
        "captured_at": now.isoformat(),
        "stale_after_seconds": stale_after,
        "summary": {"agent_count": len(results), "status_counts": counts},
        "agents": results,
        "note": (
            "Freshness is measured from server-recorded heartbeat time. A stale agent may be powered off, "
            "disconnected or blocked; this report does not distinguish those causes."
        ),
    }


FEATURE = {
    "id": "F163",
    "slug": "router_agent_health_report",
    "name": "Router agent health report",
    "category": "Router integrations",
    "description": "Classify authenticated router-agent heartbeats as healthy, degraded, unhealthy, stale or future-dated using server-side timestamps.",
    "parameters": {"agents": "agent[]", "now": "ISO-8601", "stale_after_seconds": "integer"},
    "run": run,
}
