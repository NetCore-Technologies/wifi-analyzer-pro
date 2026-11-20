"""Persistent, bounded router-agent heartbeat metadata with no credential storage."""
from __future__ import annotations

import json
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from ..site_history import default_history_path
from .registry import list_manifests


MAX_AGENTS = 256
MAX_CAPABILITIES = 64
_AGENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
_VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_CAPABILITY = re.compile(r"^[a-z][a-z0-9_.-]{0,79}$")
_STATUSES = {"healthy", "degraded", "unhealthy"}
_ERROR_CODES = {
    "SCAN_UNAVAILABLE",
    "RADIO_UNAVAILABLE",
    "NETWORK_TIMEOUT",
    "CAPABILITY_MISMATCH",
    "UPSTREAM_UNAVAILABLE",
}


class RouterAgentHealthStore:
    """Store one latest heartbeat per agent; raw payloads and credentials are never saved."""

    def __init__(self, path=None):
        self.path = path or default_history_path()

    @contextmanager
    def _connection(self):
        parent = os.path.dirname(str(self.path)) or "."
        existed = os.path.exists(parent)
        os.makedirs(parent, mode=0o700, exist_ok=True)
        if os.name != "nt" and not existed:
            try:
                os.chmod(parent, 0o700)
            except OSError:
                pass
        connection = sqlite3.connect(str(self.path), timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS router_agent_heartbeats (
                agent_id TEXT PRIMARY KEY,
                adapter_id TEXT NOT NULL,
                agent_version TEXT NOT NULL,
                status TEXT NOT NULL,
                error_code TEXT,
                last_seen_at TEXT NOT NULL,
                capabilities TEXT NOT NULL
            )
            """
        )
        try:
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
            if os.name != "nt" and os.path.exists(self.path):
                try:
                    os.chmod(self.path, 0o600)
                except OSError:
                    pass

    def record_heartbeat(self, payload: dict) -> dict:
        if not isinstance(payload, dict):
            raise ValueError("heartbeat must be an object")
        agent_id = payload.get("agent_id")
        if not isinstance(agent_id, str) or not _AGENT_ID.fullmatch(agent_id):
            raise ValueError("agent_id must be a 1 to 64 character identifier")
        adapter_id = payload.get("adapter_id")
        if not isinstance(adapter_id, str) or not adapter_id.strip():
            raise ValueError("adapter_id is required")
        adapter_id = adapter_id.strip().lower()
        manifest = next((item for item in list_manifests() if item["adapter_id"] == adapter_id), None)
        if manifest is None:
            raise ValueError("adapter_id is not installed")
        version = payload.get("agent_version")
        if not isinstance(version, str) or not _VERSION.fullmatch(version):
            raise ValueError("agent_version must use numeric major.minor.patch version syntax")
        status = payload.get("status", "healthy")
        if not isinstance(status, str) or status not in _STATUSES:
            raise ValueError(f"status must be one of {sorted(_STATUSES)}")
        error_code = payload.get("error_code")
        if error_code is not None and (not isinstance(error_code, str) or error_code not in _ERROR_CODES):
            raise ValueError(f"error_code must be one of {sorted(_ERROR_CODES)}")
        capabilities = payload.get("capabilities", [])
        if not isinstance(capabilities, list) or len(capabilities) > MAX_CAPABILITIES:
            raise ValueError(f"capabilities must be a list containing no more than {MAX_CAPABILITIES} values")
        seen = set()
        for capability in capabilities:
            if not isinstance(capability, str) or not _CAPABILITY.fullmatch(capability):
                raise ValueError("capabilities must use lowercase capability identifiers")
            if capability in seen:
                raise ValueError("capabilities must be unique")
            seen.add(capability)
        supported = set(manifest["capabilities"])
        accepted = sorted(seen & supported)
        rejected = sorted(seen - supported)
        timestamp = datetime.now(timezone.utc).isoformat()

        with self._connection() as connection:
            existing = connection.execute(
                "SELECT agent_id FROM router_agent_heartbeats WHERE agent_id = ?",
                (agent_id,),
            ).fetchone()
            if existing is None:
                count = connection.execute(
                    "SELECT COUNT(*) AS count FROM router_agent_heartbeats"
                ).fetchone()["count"]
                if count >= MAX_AGENTS:
                    raise ValueError(f"agent registry is full ({MAX_AGENTS} agents)")
            connection.execute(
                """
                INSERT INTO router_agent_heartbeats
                    (agent_id, adapter_id, agent_version, status, error_code, last_seen_at, capabilities)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                    adapter_id = excluded.adapter_id,
                    agent_version = excluded.agent_version,
                    status = excluded.status,
                    error_code = excluded.error_code,
                    last_seen_at = excluded.last_seen_at,
                    capabilities = excluded.capabilities
                """,
                (agent_id, adapter_id, version, status, error_code, timestamp,
                 json.dumps(accepted, separators=(",", ":"))),
            )
        return {
            "agent_id": agent_id,
            "adapter_id": adapter_id,
            "agent_version": version,
            "status": status,
            "error_code": error_code,
            "last_seen_at": timestamp,
            "capabilities": accepted,
            "rejected_capabilities": rejected,
            "created": existing is None,
        }

    def list_agents(self) -> list[dict]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT agent_id, adapter_id, agent_version, status, error_code,
                       last_seen_at, capabilities
                FROM router_agent_heartbeats ORDER BY agent_id
                """
            ).fetchall()
        return [
            {
                "agent_id": row["agent_id"],
                "adapter_id": row["adapter_id"],
                "agent_version": row["agent_version"],
                "status": row["status"],
                "error_code": row["error_code"],
                "last_seen_at": row["last_seen_at"],
                "capabilities": json.loads(row["capabilities"]),
            }
            for row in rows
        ]
