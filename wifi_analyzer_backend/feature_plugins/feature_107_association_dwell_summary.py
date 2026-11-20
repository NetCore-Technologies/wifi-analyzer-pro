"""Association dwell summary: Calculate per-client and per-BSSID association dwell durations from supplied timestamp intervals."""
from __future__ import annotations
import math
import statistics
from datetime import datetime

FEATURE = None

def run(p: dict) -> dict:
    sessions = p.get("sessions", [])
    if not isinstance(sessions, list):
        raise ValueError("'sessions' must be a list")
    groups = {}
    for session in sessions:
        if not isinstance(session, dict) or not session.get("client_mac") or not session.get("bssid"):
            raise ValueError("Each session needs client_mac and bssid")
        try:
            start = datetime.fromisoformat(str(session["connected_at"]).replace("Z", "+00:00"))
            end = datetime.fromisoformat(str(session["disconnected_at"]).replace("Z", "+00:00"))
        except (KeyError, TypeError, ValueError):
            raise ValueError("Session timestamps must be ISO-8601 values")
        duration = (end - start).total_seconds()
        if duration < 0:
            raise ValueError("disconnected_at must not precede connected_at")
        key = (str(session["client_mac"]).upper(), str(session["bssid"]).upper())
        groups.setdefault(key, []).append(duration)
    result = []
    for (client, bssid), durations in sorted(groups.items()):
        result.append({"client_mac": client, "bssid": bssid, "session_count": len(durations),
                       "total_seconds": round(sum(durations), 2), "average_seconds": round(statistics.mean(durations), 2)})
    return {"associations": result, "association_count": len(result)}

FEATURE = {
    "id": "F107",
    "slug": "association_dwell_summary",
    "name": "Association dwell summary",
    "category": "Roaming",
    "description": "Calculate per-client and per-BSSID association dwell durations from supplied timestamp intervals.",
    "parameters": {"sessions":"session[]"},
    "run": run,
}
