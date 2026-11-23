"""Durable, bounded outbox for forwarding hash-chained security audit events."""
from __future__ import annotations

import json
import os
import re
import sqlite3
import stat
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .site_history import default_history_path

MAX_INGEST_BATCH = 200
MAX_DELIVERY_BATCH = 5
MAX_PENDING_EVENTS = 50_000
MAX_EVENT_BYTES = 32 * 1024
MAX_ATTEMPTS = 12
DEFAULT_RETENTION_DAYS = 90
MIN_RETENTION_DAYS = 7
MAX_RETENTION_DAYS = 3650
STATUSES = {"pending", "sending", "retry_wait", "delivered", "dead_letter"}
ERROR_CODES = {
    "dns_resolution_failed",
    "dns_policy_blocked",
    "delivery_connection_failed",
    "delivery_tls_failed",
    "delivery_timeout",
    "egress_policy_blocked",
    "delivery_http_error",
    "delivery_response_too_large",
    "delivery_transport_error",
    "delivery_request_too_large",
    "delivery_package_invalid",
    "delivery_worker_error",
    "redirect_refused",
    "lease_lost",
}
EVENT_ID = re.compile(r"^[a-f0-9]{32}$")
HASH = re.compile(r"^[a-f0-9]{64}$")
IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.-]{1,95}$")


class SiemQueueFullError(RuntimeError):
    """The bounded SIEM outbox is full; the source cursor has not advanced."""


class SiemDeliveryNotFoundError(KeyError):
    """The event is no longer available under the supplied lease."""


def _timestamp(value: object, field: str) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp") from error
    else:
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone offset")
    return parsed.astimezone(timezone.utc)


def _now_text(value: object = None) -> str:
    return _timestamp(value or datetime.now(timezone.utc), "now").isoformat(timespec="seconds")


def default_siem_path() -> Path:
    override = os.environ.get("WIFI_ANALYZER_SIEM_DB")
    if override:
        return Path(override).expanduser()
    return default_history_path().with_name("security-siem-outbox.sqlite3")


def _canonical(value: object) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError, RecursionError) as error:
        raise ValueError("SIEM payload must contain finite JSON-compatible values") from error


def _normalise_event(value: object) -> tuple[int, str, str, str]:
    if not isinstance(value, dict):
        raise ValueError("each audit event must be an object")
    source_id = value.get("id")
    if isinstance(source_id, bool) or not isinstance(source_id, int) or source_id < 1:
        raise ValueError("audit event id must be a positive integer")
    event_id = value.get("event_id")
    if not isinstance(event_id, str) or not EVENT_ID.fullmatch(event_id):
        raise ValueError("audit event_id must be a 32-character lowercase hexadecimal value")
    occurred_at = _timestamp(value.get("occurred_at"), "audit event occurred_at").isoformat(timespec="seconds")
    action = value.get("action")
    if not isinstance(action, str) or not IDENTIFIER.fullmatch(action):
        raise ValueError("audit event action is invalid")
    outcome = value.get("outcome")
    if outcome not in {"success", "denied", "failure"}:
        raise ValueError("audit event outcome is invalid")
    actor = value.get("actor")
    if actor is not None:
        if not isinstance(actor, dict):
            raise ValueError("audit event actor must be an object or null")
        actor = {
            "id": actor.get("id"),
            "username": actor.get("username"),
            "role": actor.get("role"),
        }
    target = {
        "type": value.get("target_type"),
        "id": value.get("target_id"),
    }
    metadata = value.get("metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError("audit event metadata must be an object")

    event = {
        "event_id": event_id,
        "sequence": source_id,
        "occurred_at": occurred_at,
        "request_id": value.get("request_id"),
        "actor": actor,
        "action": action,
        "target": target,
        "outcome": outcome,
        "metadata": metadata,
        "previous_hash": value.get("previous_hash"),
        "event_hash": value.get("event_hash"),
    }
    if event["request_id"] is not None and (
        not isinstance(event["request_id"], str) or len(event["request_id"]) > 80
    ):
        raise ValueError("audit event request_id is invalid")
    if target["type"] is not None and (
        not isinstance(target["type"], str) or not IDENTIFIER.fullmatch(target["type"])
    ):
        raise ValueError("audit event target type is invalid")
    if target["id"] is not None and (
        not isinstance(target["id"], str) or len(target["id"]) > 128
    ):
        raise ValueError("audit event target id is invalid")
    if not isinstance(event["previous_hash"], str) or not HASH.fullmatch(event["previous_hash"]):
        raise ValueError("audit event previous_hash is invalid")
    if not isinstance(event["event_hash"], str) or not HASH.fullmatch(event["event_hash"]):
        raise ValueError("audit event event_hash is invalid")
    if actor is not None:
        if (
            actor["id"] is not None
            and (not isinstance(actor["id"], str) or not re.fullmatch(r"[a-f0-9]{32}", actor["id"]))
        ):
            raise ValueError("audit event actor id is invalid")
        if (
            actor["username"] is not None
            and (not isinstance(actor["username"], str) or len(actor["username"]) > 64)
        ):
            raise ValueError("audit event actor username is invalid")
        if actor["role"] is not None and actor["role"] not in {
            "owner", "admin", "network_admin", "analyst", "viewer",
        }:
            raise ValueError("audit event actor role is invalid")

    envelope = {
        "schema_version": "1.0",
        "source": "wifi-analyzer-pro",
        "audit_event": event,
    }
    body = _canonical(envelope)
    if len(body.encode("utf-8")) > MAX_EVENT_BYTES:
        raise ValueError(f"SIEM event exceeds the {MAX_EVENT_BYTES}-byte limit")
    return source_id, event_id, occurred_at, body


class SecuritySiemStore:
    """Persist a source cursor and at-least-once delivery queue in a local SQLite DB."""

    def __init__(
        self,
        path: str | os.PathLike[str] | None = None,
        *,
        retention_days: int = DEFAULT_RETENTION_DAYS,
        max_pending_events: int = MAX_PENDING_EVENTS,
    ):
        if isinstance(retention_days, bool) or not isinstance(retention_days, int) or not MIN_RETENTION_DAYS <= retention_days <= MAX_RETENTION_DAYS:
            raise ValueError(f"retention_days must be between {MIN_RETENTION_DAYS} and {MAX_RETENTION_DAYS}")
        if isinstance(max_pending_events, bool) or not isinstance(max_pending_events, int) or not 1 <= max_pending_events <= 1_000_000:
            raise ValueError("max_pending_events must be between 1 and 1000000")
        self.path = Path(path).expanduser() if path else default_siem_path()
        self.retention_days = retention_days
        self.max_pending_events = max_pending_events
        self._ensure_schema()

    @contextmanager
    def _db(self):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.path.is_symlink():
            raise OSError("SIEM outbox database must not be a symbolic link")
        db = sqlite3.connect(str(self.path), timeout=15)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=15000")
        db.execute("PRAGMA journal_mode=WAL")
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()
            if os.name != "nt" and self.path.exists():
                try:
                    os.chmod(self.path, 0o600)
                except OSError:
                    pass

    def _ensure_schema(self) -> None:
        with self._db() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS security_siem_state (
                    state_id INTEGER PRIMARY KEY CHECK (state_id = 1),
                    source_cursor_id INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                )
            """)
            db.execute(
                "INSERT OR IGNORE INTO security_siem_state(state_id, source_cursor_id, updated_at) "
                "VALUES(1, 0, ?)",
                (_now_text(),),
            )
            db.execute("""
                CREATE TABLE IF NOT EXISTS security_siem_outbox (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_id INTEGER NOT NULL UNIQUE,
                    event_id TEXT NOT NULL UNIQUE,
                    occurred_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending','sending','retry_wait','delivered','dead_letter')),
                    attempts INTEGER NOT NULL DEFAULT 0,
                    available_at TEXT NOT NULL,
                    lease_id TEXT,
                    lease_expires_at TEXT,
                    last_error_code TEXT,
                    http_status INTEGER,
                    delivered_at TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            db.execute("""
                CREATE INDEX IF NOT EXISTS idx_security_siem_due
                ON security_siem_outbox(status, available_at, id)
            """)
            db.execute("""
                CREATE INDEX IF NOT EXISTS idx_security_siem_retention
                ON security_siem_outbox(status, created_at)
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS security_siem_outbox_meta (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    schema_version INTEGER NOT NULL
                )
            """)
            db.execute(
                "INSERT OR IGNORE INTO security_siem_outbox_meta(singleton, schema_version) VALUES(1, 1)"
            )
            meta = db.execute(
                "SELECT schema_version FROM security_siem_outbox_meta WHERE singleton=1"
            ).fetchone()
            if meta is None or meta["schema_version"] != 1:
                raise RuntimeError("Unsupported security SIEM outbox schema version")

    def cursor_id(self) -> int:
        with self._db() as db:
            row = db.execute(
                "SELECT source_cursor_id FROM security_siem_state WHERE state_id=1"
            ).fetchone()
        return int(row["source_cursor_id"])

    def ingest(self, events: list[dict], *, now: object = None) -> dict:
        if not isinstance(events, list) or len(events) > MAX_INGEST_BATCH:
            raise ValueError(f"events must be a list containing no more than {MAX_INGEST_BATCH} records")
        moment = _now_text(now)
        prepared = [_normalise_event(event) for event in events]
        if not prepared:
            return {
                "ingested_count": 0,
                "duplicate_count": 0,
                "source_cursor_id": self.cursor_id(),
                "queue_full": False,
            }
        prepared.sort(key=lambda item: item[0])
        source_ids = [item[0] for item in prepared]
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("audit source IDs must be unique within an ingest batch")

        ingested = duplicate = 0
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            cursor_row = db.execute(
                "SELECT source_cursor_id FROM security_siem_state WHERE state_id=1"
            ).fetchone()
            cursor = int(cursor_row["source_cursor_id"])
            active_row = db.execute("""
                SELECT COUNT(*) AS total FROM security_siem_outbox
                WHERE status IN ('pending','sending','retry_wait')
            """).fetchone()
            active_count = int(active_row["total"])
            for source_id, event_id, occurred_at, body in prepared:
                if source_id <= cursor:
                    duplicate += 1
                    continue
                result = db.execute("""
                    INSERT OR IGNORE INTO security_siem_outbox (
                        source_id, event_id, occurred_at, payload_json, status,
                        attempts, available_at, created_at
                    ) VALUES (?, ?, ?, ?, 'pending', 0, ?, ?)
                """, (source_id, event_id, occurred_at, body, moment, moment))
                if result.rowcount == 1:
                    ingested += 1
                else:
                    duplicate += 1
            if active_count + ingested > self.max_pending_events:
                raise SiemQueueFullError(
                    "SIEM outbox capacity has been reached; audit export cursor was not advanced"
                )
            next_cursor = max(cursor, source_ids[-1])
            db.execute(
                "UPDATE security_siem_state SET source_cursor_id=?, updated_at=? WHERE state_id=1",
                (next_cursor, moment),
            )
        return {
            "ingested_count": ingested,
            "duplicate_count": duplicate,
            "source_cursor_id": next_cursor,
            "queue_full": False,
        }

    def claim_due(
        self,
        worker_id: str,
        *,
        now: object = None,
        lease_seconds: int = 120,
        limit: int = 5,
    ) -> dict:
        if not isinstance(worker_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}", worker_id):
            raise ValueError("worker_id must be a 1 to 64 character identifier")
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int) or not 15 <= lease_seconds <= 3600:
            raise ValueError("lease_seconds must be between 15 and 3600")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_DELIVERY_BATCH:
            raise ValueError(f"limit must be between 1 and {MAX_DELIVERY_BATCH}")
        moment = _timestamp(now, "now") if now is not None else datetime.now(timezone.utc)
        now_text = moment.isoformat(timespec="seconds")
        lease_until = (moment + timedelta(seconds=lease_seconds)).isoformat(timespec="seconds")
        jobs = []
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("""
                UPDATE security_siem_outbox
                SET status='retry_wait', lease_id=NULL, lease_expires_at=NULL,
                    available_at=?, last_error_code='lease_expired'
                WHERE status='sending' AND lease_expires_at <= ?
            """, (now_text, now_text))
            db.execute("""
                UPDATE security_siem_outbox
                SET status='dead_letter', last_error_code='attempt_limit_reached'
                WHERE status IN ('pending','retry_wait') AND attempts >= ?
            """, (MAX_ATTEMPTS,))
            rows = db.execute("""
                SELECT id, source_id, event_id, occurred_at, payload_json, attempts
                FROM security_siem_outbox
                WHERE status IN ('pending','retry_wait') AND available_at <= ?
                ORDER BY source_id ASC LIMIT ?
            """, (now_text, limit)).fetchall()
            for row in rows:
                lease_id = uuid.uuid4().hex
                db.execute("""
                    UPDATE security_siem_outbox
                    SET status='sending', attempts=attempts+1, lease_id=?, lease_expires_at=?
                    WHERE id=?
                """, (lease_id, lease_until, row["id"]))
                jobs.append({
                    "id": row["id"],
                    "source_id": row["source_id"],
                    "event_id": row["event_id"],
                    "occurred_at": row["occurred_at"],
                    "payload": json.loads(row["payload_json"]),
                    "attempts": row["attempts"] + 1,
                    "lease_id": lease_id,
                    "lease_expires_at": lease_until,
                })
        return {"worker_id": worker_id, "claimed_count": len(jobs), "jobs": jobs}

    def get_leased(self, event_row_id: int, lease_id: str, *, now: object = None) -> dict | None:
        if isinstance(event_row_id, bool) or not isinstance(event_row_id, int) or event_row_id < 1:
            raise ValueError("event_row_id must be a positive integer")
        if not isinstance(lease_id, str) or not re.fullmatch(r"[a-f0-9]{32}", lease_id):
            raise ValueError("lease_id must be a 32-character hexadecimal value")
        moment = _timestamp(now, "now") if now is not None else datetime.now(timezone.utc)
        with self._db() as db:
            row = db.execute("""
                SELECT id, source_id, event_id, occurred_at, payload_json, attempts,
                       lease_id, lease_expires_at, status
                FROM security_siem_outbox WHERE id=?
            """, (event_row_id,)).fetchone()
        if (
            row is None or row["status"] != "sending" or row["lease_id"] != lease_id
            or _timestamp(row["lease_expires_at"], "lease_expires_at") <= moment
        ):
            return None
        return {
            "id": row["id"],
            "source_id": row["source_id"],
            "event_id": row["event_id"],
            "occurred_at": row["occurred_at"],
            "payload": json.loads(row["payload_json"]),
            "attempts": row["attempts"],
            "lease_id": row["lease_id"],
            "lease_expires_at": row["lease_expires_at"],
        }

    def renew_lease(self, event_row_id: int, lease_id: str, *, now: object = None, lease_seconds: int = 120) -> dict:
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int) or not 15 <= lease_seconds <= 3600:
            raise ValueError("lease_seconds must be between 15 and 3600")
        moment = _timestamp(now, "now") if now is not None else datetime.now(timezone.utc)
        updated = (moment + timedelta(seconds=lease_seconds)).isoformat(timespec="seconds")
        with self._db() as db:
            result = db.execute("""
                UPDATE security_siem_outbox SET lease_expires_at=?
                WHERE id=? AND status='sending' AND lease_id=? AND lease_expires_at > ?
            """, (updated, event_row_id, lease_id, moment.isoformat(timespec="seconds")))
            if result.rowcount != 1:
                raise SiemDeliveryNotFoundError(event_row_id)
        return {"id": event_row_id, "lease_id": lease_id, "lease_expires_at": updated}

    def complete(self, event_row_id: int, lease_id: str, *, http_status: int, now: object = None) -> dict:
        if isinstance(http_status, bool) or not isinstance(http_status, int) or not 200 <= http_status < 300:
            raise ValueError("http_status must be a successful 2xx code")
        moment = _now_text(now)
        with self._db() as db:
            result = db.execute("""
                UPDATE security_siem_outbox
                SET status='delivered', delivered_at=?, http_status=?, lease_id=NULL,
                    lease_expires_at=NULL, last_error_code=NULL
                WHERE id=? AND status='sending' AND lease_id=?
            """, (moment, http_status, event_row_id, lease_id))
            if result.rowcount != 1:
                raise SiemDeliveryNotFoundError(event_row_id)
            row = db.execute(
                "SELECT id, source_id, event_id, status, delivered_at, http_status "
                "FROM security_siem_outbox WHERE id=?",
                (event_row_id,),
            ).fetchone()
        return dict(row)

    def fail(self, event_row_id: int, lease_id: str, error_code: str, *, now: object = None) -> dict:
        if error_code not in ERROR_CODES:
            raise ValueError("unsupported SIEM delivery error code")
        moment = _timestamp(now, "now") if now is not None else datetime.now(timezone.utc)
        now_text = moment.isoformat(timespec="seconds")
        with self._db() as db:
            row = db.execute("""
                SELECT attempts FROM security_siem_outbox
                WHERE id=? AND status='sending' AND lease_id=?
            """, (event_row_id, lease_id)).fetchone()
            if row is None:
                raise SiemDeliveryNotFoundError(event_row_id)
            attempts = int(row["attempts"])
            if attempts >= MAX_ATTEMPTS:
                status = "dead_letter"
                available_at = now_text
            else:
                status = "retry_wait"
                delay = min(3600, 5 * (2 ** max(0, attempts - 1)))
                available_at = (moment + timedelta(seconds=delay)).isoformat(timespec="seconds")
            result = db.execute("""
                UPDATE security_siem_outbox
                SET status=?, available_at=?, last_error_code=?, lease_id=NULL,
                    lease_expires_at=NULL
                WHERE id=? AND status='sending' AND lease_id=?
            """, (status, available_at, error_code, event_row_id, lease_id))
            if result.rowcount != 1:
                raise SiemDeliveryNotFoundError(event_row_id)
        return {
            "id": event_row_id,
            "status": status,
            "attempts": attempts,
            "last_error_code": error_code,
            "available_at": available_at,
        }

    def summary(self) -> dict:
        with self._db() as db:
            cursor = db.execute(
                "SELECT source_cursor_id FROM security_siem_state WHERE state_id=1"
            ).fetchone()
            counts = {
                row["status"]: row["total"]
                for row in db.execute(
                    "SELECT status, COUNT(*) AS total FROM security_siem_outbox GROUP BY status"
                ).fetchall()
            }
            pending_row = db.execute("""
                SELECT COUNT(*) AS total FROM security_siem_outbox
                WHERE status IN ('pending','sending','retry_wait')
            """).fetchone()
        return {
            "source_cursor_id": int(cursor["source_cursor_id"]),
            "pending_count": int(pending_row["total"]),
            "status_counts": {status: int(counts.get(status, 0)) for status in sorted(STATUSES)},
            "retention_days": self.retention_days,
            "max_pending_events": self.max_pending_events,
        }

    def list_events(self, *, status: str | None = None, limit: int = 50) -> list[dict]:
        if status is not None and status not in STATUSES:
            raise ValueError("invalid SIEM export status")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        where = " WHERE status=?" if status else ""
        values = (status, limit) if status else (limit,)
        with self._db() as db:
            rows = db.execute("""
                SELECT id, source_id, event_id, occurred_at, status, attempts,
                       available_at, last_error_code, http_status, delivered_at
                FROM security_siem_outbox
            """ + where + " ORDER BY source_id DESC LIMIT ?", values).fetchall()
        return [dict(row) for row in rows]

    def prune(self, *, now: object = None) -> dict:
        moment = _timestamp(now, "now") if now is not None else datetime.now(timezone.utc)
        cutoff = (moment - timedelta(days=self.retention_days)).isoformat(timespec="seconds")
        with self._db() as db:
            result = db.execute("""
                DELETE FROM security_siem_outbox
                WHERE status IN ('delivered','dead_letter') AND created_at < ?
            """, (cutoff,))
        return {"deleted_count": result.rowcount, "retention_days": self.retention_days}


__all__ = [
    "DEFAULT_RETENTION_DAYS",
    "ERROR_CODES",
    "MAX_ATTEMPTS",
    "MAX_DELIVERY_BATCH",
    "MAX_EVENT_BYTES",
    "MAX_INGEST_BATCH",
    "MAX_PENDING_EVENTS",
    "SecuritySiemStore",
    "SiemDeliveryNotFoundError",
    "SiemQueueFullError",
    "default_siem_path",
]
