"""Persistent, bounded router-agent heartbeat metadata with no credential storage."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from ..site_history import default_history_path
from .registry import list_manifests


MAX_AGENTS = 256
MAX_CAPABILITIES = 64
MAX_SNAPSHOTS_PER_AGENT = 100
MAX_STORED_SNAPSHOT_BYTES = 512 * 1024
MAX_STORED_SNAPSHOTS_TOTAL = 1000
MAX_DELIVERIES_PER_AGENT = 500
MAX_DELIVERIES_TOTAL = 5000
DEFAULT_AGENT_TOKEN_TTL_DAYS = 90
MAX_AGENT_TOKEN_TTL_DAYS = 365
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


class DuplicateAgentSnapshotError(ValueError):
    """Raised when an agent submits an already stored capture timestamp."""


class DuplicateAgentDeliveryError(ValueError):
    """Raised when a delivery ID is replayed with different payload contents."""


class AgentCredentialConflictError(ValueError):
    """Raised when an agent already has an active credential."""


class AgentAuthenticationError(PermissionError):
    """Raised when an agent bearer credential is invalid, expired or revoked."""


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
            CREATE TABLE IF NOT EXISTS agent_router_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                adapter_id TEXT NOT NULL,
                captured_at TEXT NOT NULL,
                received_at TEXT NOT NULL,
                payload TEXT NOT NULL,
                UNIQUE(agent_id, captured_at)
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_agent_router_snapshots_agent_id_id "
            "ON agent_router_snapshots(agent_id, id DESC)"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_snapshot_deliveries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                delivery_id TEXT NOT NULL,
                payload_hash TEXT NOT NULL,
                result_json TEXT NOT NULL,
                received_at TEXT NOT NULL,
                UNIQUE(agent_id, delivery_id)
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_agent_snapshot_deliveries_agent_id_id "
            "ON agent_snapshot_deliveries(agent_id, id DESC)"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS router_agent_credentials (
                agent_id TEXT PRIMARY KEY,
                adapter_id TEXT NOT NULL,
                agent_version TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                allowed_capabilities TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked_at TEXT
            )
            """
        )
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


    @staticmethod
    def _validate_ttl_days(ttl_days: int) -> int:
        if isinstance(ttl_days, bool) or not isinstance(ttl_days, int) or not 1 <= ttl_days <= MAX_AGENT_TOKEN_TTL_DAYS:
            raise ValueError(f"ttl_days must be an integer between 1 and {MAX_AGENT_TOKEN_TTL_DAYS}")
        return ttl_days

    @staticmethod
    def _agent_token_hash(token: str) -> str:
        if not isinstance(token, str) or not 32 <= len(token) <= 256:
            raise AgentAuthenticationError("Agent authentication required")
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def _new_agent_token() -> str:
        return "wpa_" + secrets.token_urlsafe(32)

    def enroll_agent(
        self, *, agent_id: str, adapter_id: str, agent_version: str,
        allowed_capabilities: list[str], ttl_days: int = DEFAULT_AGENT_TOKEN_TTL_DAYS,
    ) -> dict:
        if not isinstance(agent_id, str) or not _AGENT_ID.fullmatch(agent_id):
            raise ValueError("agent_id must be a 1 to 64 character identifier")
        if not isinstance(adapter_id, str) or not adapter_id.strip():
            raise ValueError("adapter_id is required")
        adapter_id = adapter_id.strip().lower()
        manifest = next((item for item in list_manifests() if item["adapter_id"] == adapter_id), None)
        if manifest is None:
            raise ValueError("adapter_id is not installed")
        if not isinstance(agent_version, str) or not _VERSION.fullmatch(agent_version):
            raise ValueError("agent_version must use numeric major.minor.patch version syntax")
        self._validate_ttl_days(ttl_days)
        if not isinstance(allowed_capabilities, list) or not 1 <= len(allowed_capabilities) <= MAX_CAPABILITIES:
            raise ValueError(f"allowed_capabilities must contain 1 to {MAX_CAPABILITIES} values")
        seen = set()
        supported = set(manifest["capabilities"])
        for capability in allowed_capabilities:
            if not isinstance(capability, str) or not _CAPABILITY.fullmatch(capability):
                raise ValueError("allowed_capabilities must use lowercase capability identifiers")
            if capability in seen:
                raise ValueError("allowed_capabilities must be unique")
            if capability not in supported:
                raise ValueError(f"Capability is not supported by {adapter_id}: {capability}")
            seen.add(capability)
        if "system.board" not in seen:
            raise ValueError("Agent enrollment must include the system.board read capability")

        now = datetime.now(timezone.utc)
        created_at = now.isoformat()
        expires_at = (now + timedelta(days=ttl_days)).isoformat()
        token = self._new_agent_token()
        token_hash = self._agent_token_hash(token)
        with self._connection() as connection:
            existing = connection.execute(
                "SELECT revoked_at, expires_at FROM router_agent_credentials WHERE agent_id = ?",
                (agent_id,),
            ).fetchone()
            if existing is not None and existing["revoked_at"] is None:
                try:
                    existing_expiry = datetime.fromisoformat(existing["expires_at"])
                except (TypeError, ValueError):
                    existing_expiry = now
                if existing_expiry > now:
                    raise AgentCredentialConflictError("Agent already has an active credential; rotate it instead")
            connection.execute(
                """
                INSERT INTO router_agent_credentials
                    (agent_id, adapter_id, agent_version, token_hash, allowed_capabilities,
                     created_at, expires_at, revoked_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
                ON CONFLICT(agent_id) DO UPDATE SET
                    adapter_id = excluded.adapter_id,
                    agent_version = excluded.agent_version,
                    token_hash = excluded.token_hash,
                    allowed_capabilities = excluded.allowed_capabilities,
                    created_at = excluded.created_at,
                    expires_at = excluded.expires_at,
                    revoked_at = NULL
                """,
                (agent_id, adapter_id, agent_version, token_hash,
                 json.dumps(sorted(seen), separators=(",", ":")), created_at, expires_at),
            )
            connection.execute("DELETE FROM router_agent_heartbeats WHERE agent_id = ?", (agent_id,))
        return {
            "agent_id": agent_id, "adapter_id": adapter_id, "agent_version": agent_version,
            "allowed_capabilities": sorted(seen), "created_at": created_at,
            "expires_at": expires_at, "token": token,
        }

    def rotate_agent_credential(self, agent_id: str, *, ttl_days: int = DEFAULT_AGENT_TOKEN_TTL_DAYS) -> dict:
        if not isinstance(agent_id, str) or not _AGENT_ID.fullmatch(agent_id):
            raise ValueError("agent_id must be a 1 to 64 character identifier")
        self._validate_ttl_days(ttl_days)
        now = datetime.now(timezone.utc)
        created_at = now.isoformat()
        expires_at = (now + timedelta(days=ttl_days)).isoformat()
        token = self._new_agent_token()
        token_hash = self._agent_token_hash(token)
        with self._connection() as connection:
            credential = connection.execute(
                "SELECT adapter_id, agent_version, allowed_capabilities, revoked_at "
                "FROM router_agent_credentials WHERE agent_id = ?",
                (agent_id,),
            ).fetchone()
            if credential is None:
                raise ValueError("Agent credential was not found")
            if credential["revoked_at"] is not None:
                raise AgentAuthenticationError("Revoked agent credentials cannot be rotated; enrol the agent again")
            connection.execute(
                "UPDATE router_agent_credentials SET token_hash = ?, created_at = ?, expires_at = ? WHERE agent_id = ?",
                (token_hash, created_at, expires_at, agent_id),
            )
        return {
            "agent_id": agent_id, "adapter_id": credential["adapter_id"],
            "agent_version": credential["agent_version"],
            "allowed_capabilities": json.loads(credential["allowed_capabilities"]),
            "created_at": created_at, "expires_at": expires_at, "token": token,
        }

    def revoke_agent_credential(self, agent_id: str) -> dict:
        if not isinstance(agent_id, str) or not _AGENT_ID.fullmatch(agent_id):
            raise ValueError("agent_id must be a 1 to 64 character identifier")
        revoked_at = datetime.now(timezone.utc).isoformat()
        with self._connection() as connection:
            cursor = connection.execute(
                "UPDATE router_agent_credentials SET revoked_at = ? WHERE agent_id = ? AND revoked_at IS NULL",
                (revoked_at, agent_id),
            )
            if cursor.rowcount == 0:
                raise ValueError("Active agent credential was not found")
        return {"agent_id": agent_id, "revoked_at": revoked_at, "revoked": True}

    def list_agent_credentials(self) -> list[dict]:
        now = datetime.now(timezone.utc)
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT agent_id, adapter_id, agent_version, allowed_capabilities,
                       created_at, expires_at, revoked_at
                FROM router_agent_credentials ORDER BY agent_id LIMIT ?
                """,
                (MAX_AGENTS,),
            ).fetchall()
        results = []
        for row in rows:
            try:
                expiry = datetime.fromisoformat(row["expires_at"])
            except (TypeError, ValueError):
                expiry = now
            status = "revoked" if row["revoked_at"] is not None else ("expired" if expiry <= now else "active")
            results.append({
                "agent_id": row["agent_id"], "adapter_id": row["adapter_id"],
                "agent_version": row["agent_version"],
                "allowed_capabilities": json.loads(row["allowed_capabilities"]),
                "created_at": row["created_at"], "expires_at": row["expires_at"],
                "revoked_at": row["revoked_at"], "status": status,
            })
        return results

    def _require_agent_credential(self, connection, agent_id: str, token: str):
        token_hash = self._agent_token_hash(token)
        credential = connection.execute(
            """
            SELECT adapter_id, token_hash, allowed_capabilities, expires_at, revoked_at
            FROM router_agent_credentials WHERE agent_id = ?
            """,
            (agent_id,),
        ).fetchone()
        if credential is None or credential["revoked_at"] is not None:
            raise AgentAuthenticationError("Agent authentication required")
        try:
            expires_at = datetime.fromisoformat(credential["expires_at"])
        except (TypeError, ValueError):
            raise AgentAuthenticationError("Agent authentication required")
        if expires_at <= datetime.now(timezone.utc):
            raise AgentAuthenticationError("Agent authentication required")
        if not hmac.compare_digest(credential["token_hash"], token_hash):
            raise AgentAuthenticationError("Agent authentication required")
        return credential

    def record_heartbeat(self, payload: dict, *, token: str) -> dict:
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
        accepted = []
        rejected = []
        timestamp = datetime.now(timezone.utc).isoformat()

        with self._connection() as connection:
            credential = self._require_agent_credential(connection, agent_id, token)
            if credential["adapter_id"] != adapter_id:
                raise AgentAuthenticationError("Agent authentication required")
            allowed = set(json.loads(credential["allowed_capabilities"]))
            accepted = sorted(seen & supported & allowed)
            rejected = sorted(seen - set(accepted))
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


    def record_snapshot(
        self, agent_id: str, snapshot: dict, *, token: str, delivery_id: str | None = None
    ) -> dict:
        if not isinstance(agent_id, str) or not _AGENT_ID.fullmatch(agent_id):
            raise ValueError("agent_id must be a 1 to 64 character identifier")
        if not isinstance(snapshot, dict) or snapshot.get("adapter_id") != "openwrt":
            raise ValueError("snapshot must be a normalised OpenWrt snapshot")
        if delivery_id is not None:
            if not isinstance(delivery_id, str) or len(delivery_id) > 64:
                raise ValueError("delivery_id must be a UUID string")
            try:
                delivery_id = str(uuid.UUID(delivery_id))
            except (ValueError, AttributeError, TypeError) as error:
                raise ValueError("delivery_id must be a UUID string") from error

        captured_at = snapshot.get("captured_at")
        if not isinstance(captured_at, str) or not captured_at.strip():
            raise ValueError("snapshot.captured_at must be a timezone-aware ISO-8601 timestamp")
        try:
            parsed = datetime.fromisoformat(captured_at.strip().replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError("snapshot.captured_at must be a timezone-aware ISO-8601 timestamp") from error
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("snapshot.captured_at must include a timezone offset")
        captured_at = parsed.astimezone(timezone.utc).isoformat()
        try:
            encoded = json.dumps(snapshot, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False)
        except (TypeError, ValueError) as error:
            raise ValueError("snapshot must contain JSON-compatible finite values") from error
        if len(encoded.encode("utf-8")) > MAX_STORED_SNAPSHOT_BYTES:
            raise ValueError(f"normalised snapshot exceeds the {MAX_STORED_SNAPSHOT_BYTES}-byte storage limit")
        payload_hash = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        received_at = datetime.now(timezone.utc).isoformat()

        try:
            with self._connection() as connection:
                credential = self._require_agent_credential(connection, agent_id, token)
                agent = connection.execute(
                    "SELECT adapter_id, capabilities FROM router_agent_heartbeats WHERE agent_id = ?",
                    (agent_id,),
                ).fetchone()
                if agent is None:
                    raise ValueError("agent must send an authenticated heartbeat before submitting snapshots")
                if agent["adapter_id"] != snapshot["adapter_id"] or credential["adapter_id"] != snapshot["adapter_id"]:
                    raise AgentAuthenticationError("Agent authentication required")
                if "inventory.snapshot" not in json.loads(credential["allowed_capabilities"]):
                    raise ValueError("Agent credential does not include the inventory.snapshot capability")
                if "inventory.snapshot" not in json.loads(agent["capabilities"]):
                    raise ValueError("agent has not negotiated the inventory.snapshot capability")

                if delivery_id is not None:
                    existing_delivery = connection.execute(
                        """
                        SELECT payload_hash, result_json
                        FROM agent_snapshot_deliveries
                        WHERE agent_id = ? AND delivery_id = ?
                        """,
                        (agent_id, delivery_id),
                    ).fetchone()
                    if existing_delivery is not None:
                        if not hmac.compare_digest(existing_delivery["payload_hash"], payload_hash):
                            raise DuplicateAgentDeliveryError(
                                "delivery_id has already been used with different snapshot contents"
                            )
                        replayed = json.loads(existing_delivery["result_json"])
                        replayed["replayed"] = True
                        return replayed

                cursor = connection.execute(
                    """
                    INSERT INTO agent_router_snapshots
                        (agent_id, adapter_id, captured_at, received_at, payload)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (agent_id, snapshot["adapter_id"], captured_at, received_at, encoded),
                )
                snapshot_id = cursor.lastrowid
                connection.execute(
                    """
                    DELETE FROM agent_router_snapshots
                    WHERE id NOT IN (
                        SELECT id FROM agent_router_snapshots ORDER BY id DESC LIMIT ?
                    )
                    """,
                    (MAX_STORED_SNAPSHOTS_TOTAL,),
                )
                connection.execute(
                    """
                    DELETE FROM agent_router_snapshots
                    WHERE agent_id = ? AND id NOT IN (
                        SELECT id FROM agent_router_snapshots
                        WHERE agent_id = ? ORDER BY id DESC LIMIT ?
                    )
                    """,
                    (agent_id, agent_id, MAX_SNAPSHOTS_PER_AGENT),
                )
                summary = snapshot.get("summary", {})
                result = {
                    "id": snapshot_id,
                    "agent_id": agent_id,
                    "adapter_id": snapshot["adapter_id"],
                    "captured_at": captured_at,
                    "received_at": received_at,
                    "interface_count": summary.get("interface_count", 0),
                    "wireless_radio_count": summary.get("wireless_radio_count", 0),
                    "association_count": summary.get("association_count", 0),
                    "route_count": summary.get("route_count", 0),
                    "replayed": False,
                }
                if delivery_id is not None:
                    connection.execute(
                        """
                        INSERT INTO agent_snapshot_deliveries
                            (agent_id, delivery_id, payload_hash, result_json, received_at)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            agent_id,
                            delivery_id,
                            payload_hash,
                            json.dumps(result, separators=(",", ":"), sort_keys=True),
                            received_at,
                        ),
                    )
                    connection.execute(
                        """
                        DELETE FROM agent_snapshot_deliveries
                        WHERE id NOT IN (
                            SELECT id FROM agent_snapshot_deliveries ORDER BY id DESC LIMIT ?
                        )
                        """,
                        (MAX_DELIVERIES_TOTAL,),
                    )
                    connection.execute(
                        """
                        DELETE FROM agent_snapshot_deliveries
                        WHERE agent_id = ? AND id NOT IN (
                            SELECT id FROM agent_snapshot_deliveries
                            WHERE agent_id = ? ORDER BY id DESC LIMIT ?
                        )
                        """,
                        (agent_id, agent_id, MAX_DELIVERIES_PER_AGENT),
                    )
                return result
        except sqlite3.IntegrityError as error:
            message = str(error)
            if "agent_snapshot_deliveries.agent_id, agent_snapshot_deliveries.delivery_id" in message:
                raise DuplicateAgentDeliveryError("Snapshot delivery was already accepted") from error
            if "UNIQUE constraint failed" in message:
                raise DuplicateAgentSnapshotError(
                    "A snapshot for this agent and capture timestamp already exists"
                ) from error
            raise

    def list_latest_snapshots(self) -> list[dict]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT s.id, s.agent_id, s.adapter_id, s.captured_at, s.received_at, s.payload
                FROM agent_router_snapshots AS s
                WHERE s.id = (
                    SELECT MAX(latest.id) FROM agent_router_snapshots AS latest
                    WHERE latest.agent_id = s.agent_id
                )
                ORDER BY s.agent_id LIMIT ?
                """,
                (MAX_AGENTS,),
            ).fetchall()
        results = []
        for row in rows:
            summary = json.loads(row["payload"]).get("summary", {})
            results.append({
                "id": row["id"], "agent_id": row["agent_id"], "adapter_id": row["adapter_id"],
                "captured_at": row["captured_at"], "received_at": row["received_at"],
                "interface_count": summary.get("interface_count", 0),
                "wireless_radio_count": summary.get("wireless_radio_count", 0),
                "association_count": summary.get("association_count", 0),
                "route_count": summary.get("route_count", 0),
            })
        return results

    def get_recent_snapshots(self, agent_id: str, *, limit: int = 2) -> list[dict]:
        if not isinstance(agent_id, str) or not _AGENT_ID.fullmatch(agent_id):
            raise ValueError("agent_id must be a 1 to 64 character identifier")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 5:
            raise ValueError("snapshot limit must be an integer between 1 and 5")
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT id, agent_id, adapter_id, captured_at, received_at, payload
                FROM agent_router_snapshots WHERE agent_id = ?
                ORDER BY id DESC LIMIT ?
                """,
                (agent_id, limit),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "agent_id": row["agent_id"],
                "adapter_id": row["adapter_id"],
                "captured_at": row["captured_at"],
                "received_at": row["received_at"],
                "snapshot": json.loads(row["payload"]),
            }
            for row in reversed(rows)
        ]

    def get_latest_snapshot(self, agent_id: str) -> dict | None:
        if not isinstance(agent_id, str) or not _AGENT_ID.fullmatch(agent_id):
            raise ValueError("agent_id must be a 1 to 64 character identifier")
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT id, agent_id, adapter_id, captured_at, received_at, payload
                FROM agent_router_snapshots WHERE agent_id = ?
                ORDER BY id DESC LIMIT 1
                """,
                (agent_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "id": row["id"], "agent_id": row["agent_id"], "adapter_id": row["adapter_id"],
            "captured_at": row["captured_at"], "received_at": row["received_at"],
            "snapshot": json.loads(row["payload"]),
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
