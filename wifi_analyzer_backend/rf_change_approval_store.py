"""Durable two-person RF change approvals with immutable packets and serialised transitions."""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

SITE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
ACTOR_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{1,127}$")
MAX_PER_SITE = 250
MAX_PACKET_BYTES = 2 * 1024 * 1024


def _site(value):
    if not isinstance(value, str) or not SITE_RE.fullmatch(value.strip()):
        raise ValueError("site_id must be a valid identifier")
    return value.strip()


def _actor(value):
    if not isinstance(value, str) or not ACTOR_RE.fullmatch(value.strip()):
        raise ValueError("actor must be a valid username")
    return value.strip().lower()


def _request_id(value):
    try:
        return str(uuid.UUID(value))
    except (TypeError, ValueError, AttributeError) as error:
        raise ValueError("request_id must be a valid UUID") from error


def _now():
    return datetime.now(timezone.utc)


def _canonical(value):
    try:
        encoded = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError("packet must contain finite JSON-compatible values") from error
    raw = encoded.encode("utf-8")
    if len(raw) > MAX_PACKET_BYTES:
        raise ValueError(f"packet exceeds the {MAX_PACKET_BYTES}-byte storage limit")
    return encoded, hashlib.sha256(raw).hexdigest()


class RfChangeApprovalStore:
    def __init__(self, path=None, *, max_per_site=MAX_PER_SITE):
        if isinstance(max_per_site, bool) or not isinstance(max_per_site, int) or not 1 <= max_per_site <= MAX_PER_SITE:
            raise ValueError(f"max_per_site must be an integer from 1 to {MAX_PER_SITE}")
        self.path = Path(path).expanduser() if path else (
            Path(os.getenv("XDG_STATE_HOME", str(Path.home() / ".local" / "state"))).expanduser()
            / "wifi-analyzer-pro" / "rf-change-approvals.sqlite3"
        )
        self.max_per_site = max_per_site

    @contextmanager
    def _db(self):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt":
            try:
                os.chmod(self.path.parent, 0o700)
            except OSError:
                pass
        db = sqlite3.connect(str(self.path), timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        db.execute("PRAGMA busy_timeout = 10000")
        db.execute("PRAGMA journal_mode = WAL")
        db.executescript("""
            CREATE TABLE IF NOT EXISTS rf_change_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NOT NULL UNIQUE,
                site_id TEXT NOT NULL,
                adapter_id TEXT NOT NULL,
                requested_by TEXT NOT NULL,
                status TEXT NOT NULL,
                required_approvals INTEGER NOT NULL,
                packet_sha256 TEXT NOT NULL,
                packet_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                state_version INTEGER NOT NULL DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS idx_rf_change_site_created
                ON rf_change_requests(site_id, created_at DESC, id DESC);
            CREATE TABLE IF NOT EXISTS rf_change_approvals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NOT NULL,
                actor TEXT NOT NULL,
                decision TEXT NOT NULL,
                comment TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                UNIQUE(request_id, actor),
                FOREIGN KEY(request_id) REFERENCES rf_change_requests(request_id)
            );
            CREATE TABLE IF NOT EXISTS rf_change_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NOT NULL,
                site_id TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                previous_status TEXT,
                next_status TEXT,
                metadata_json TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                FOREIGN KEY(request_id) REFERENCES rf_change_requests(request_id)
            );
            CREATE INDEX IF NOT EXISTS idx_rf_change_events
                ON rf_change_events(request_id, id);
            CREATE TRIGGER IF NOT EXISTS rf_change_packet_immutable
            BEFORE UPDATE OF site_id, adapter_id, requested_by, required_approvals,
                packet_sha256, packet_json, created_at, expires_at
            ON rf_change_requests
            BEGIN
                SELECT RAISE(ABORT, 'RF change packet content is immutable');
            END;
            CREATE TRIGGER IF NOT EXISTS rf_change_approvals_append_only_update
            BEFORE UPDATE ON rf_change_approvals
            BEGIN
                SELECT RAISE(ABORT, 'RF change approvals are append-only');
            END;
            CREATE TRIGGER IF NOT EXISTS rf_change_approvals_append_only_delete
            BEFORE DELETE ON rf_change_approvals
            BEGIN
                SELECT RAISE(ABORT, 'RF change approvals are append-only');
            END;
            CREATE TRIGGER IF NOT EXISTS rf_change_events_append_only_update
            BEFORE UPDATE ON rf_change_events
            BEGIN
                SELECT RAISE(ABORT, 'RF change events are append-only');
            END;
            CREATE TRIGGER IF NOT EXISTS rf_change_events_append_only_delete
            BEFORE DELETE ON rf_change_events
            BEGIN
                SELECT RAISE(ABORT, 'RF change events are append-only');
            END;
        """)
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

    @staticmethod
    def _event(db, request_id, site_id, actor, action, previous, next_status, metadata=None):
        db.execute("""
            INSERT INTO rf_change_events (
                request_id, site_id, actor, action, previous_status,
                next_status, metadata_json, occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            request_id, site_id, actor, action, previous, next_status,
            json.dumps(metadata or {}, sort_keys=True, separators=(",", ":"), allow_nan=False),
            _now().isoformat(timespec="seconds"),
        ))

    @staticmethod
    def _row(db, row, *, include_packet=False):
        packet_text = row["packet_json"]
        if hashlib.sha256(packet_text.encode("utf-8")).hexdigest() != row["packet_sha256"]:
            raise RuntimeError("RF change approval packet integrity verification failed")
        approvals = db.execute(
            "SELECT actor, decision, comment, occurred_at FROM rf_change_approvals WHERE request_id = ? ORDER BY id",
            (row["request_id"],),
        ).fetchall()
        events = db.execute(
            "SELECT actor, action, previous_status, next_status, occurred_at, metadata_json FROM rf_change_events WHERE request_id = ? ORDER BY id",
            (row["request_id"],),
        ).fetchall()
        result = {
            "request_id": row["request_id"],
            "site_id": row["site_id"],
            "adapter_id": row["adapter_id"],
            "requested_by": row["requested_by"],
            "status": row["status"],
            "required_approvals": row["required_approvals"],
            "approval_count": sum(item["decision"] == "approve" for item in approvals),
            "approvals": [dict(item) for item in approvals],
            "packet_sha256": row["packet_sha256"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "updated_at": row["updated_at"],
            "state_version": row["state_version"],
            "events": [{
                "actor": item["actor"], "action": item["action"],
                "previous_status": item["previous_status"],
                "next_status": item["next_status"],
                "occurred_at": item["occurred_at"],
                "metadata": json.loads(item["metadata_json"]),
            } for item in events],
            "execution_allowed": False,
        }
        if include_packet:
            result["packet"] = json.loads(packet_text)
        return result

    def _expire_if_due(self, db, row):
        if row["status"] == "pending_approval" and _now() >= datetime.fromisoformat(row["expires_at"]):
            now = _now().isoformat(timespec="seconds")
            self._event(db, row["request_id"], row["site_id"], "system", "expired",
                        "pending_approval", "expired")
            db.execute("""
                UPDATE rf_change_requests
                SET status = 'expired', updated_at = ?, state_version = state_version + 1
                WHERE request_id = ? AND status = 'pending_approval'
            """, (now, row["request_id"]))
            return db.execute(
                "SELECT * FROM rf_change_requests WHERE request_id = ?", (row["request_id"],)
            ).fetchone()
        return row

    def create(self, site_id, packet):
        site_id = _site(site_id)
        if not isinstance(packet, dict):
            raise ValueError("packet must be a validated F208 result")
        if packet.get("status") != "approval_packet_created":
            raise ValueError("packet must be a validated F208 result")
        body = packet.get("packet")
        if not isinstance(body, dict) or body.get("site_id") != site_id:
            raise ValueError("packet site_id must match the requested site")
        if body.get("execution", {}).get("applied") is not False:
            raise ValueError("packet must explicitly represent a non-applied configuration preview")
        encoded, digest = _canonical(body)
        if packet.get("packet_sha256") != digest:
            raise ValueError("packet SHA-256 does not match its canonical content")
        created = body.get("created_at")
        expires = body.get("expires_at")
        try:
            created_at = datetime.fromisoformat(created.replace("Z", "+00:00"))
            expires_at = datetime.fromisoformat(expires.replace("Z", "+00:00"))
        except (AttributeError, TypeError, ValueError) as error:
            raise ValueError("packet timestamps must be timezone-aware ISO-8601 values") from error
        if created_at.tzinfo is None or expires_at.tzinfo is None:
            raise ValueError("packet timestamps must include timezone offsets")
        ttl = (expires_at - created_at).total_seconds()
        if not 60 <= ttl <= 86400:
            raise ValueError("expires_at must be between 1 minute and 24 hours after creation")
        if expires_at <= _now():
            raise ValueError("expires_at cannot be in the past when creating a change request")
        if body.get("required_approvals") != 2:
            raise ValueError("RF change requests require exactly two independent approvers")
        adapter = body.get("adapter_id")
        if adapter not in {"openwrt", "unifi", "mikrotik"}:
            raise ValueError("packet adapter_id is not a registered router adapter")
        requester = _actor(body.get("requested_by"))
        request_id = str(uuid.uuid4())
        now = _now().isoformat(timespec="seconds")
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            count = db.execute(
                "SELECT COUNT(*) FROM rf_change_requests WHERE site_id = ?", (site_id,)
            ).fetchone()[0]
            if count >= self.max_per_site:
                raise ValueError(f"site already has {self.max_per_site} retained RF change requests")
            db.execute("""
                INSERT INTO rf_change_requests (
                    request_id, site_id, adapter_id, requested_by, status,
                    required_approvals, packet_sha256, packet_json, created_at,
                    expires_at, updated_at, state_version
                ) VALUES (?, ?, ?, ?, 'pending_approval', 2, ?, ?, ?, ?, ?, 1)
            """, (request_id, site_id, adapter, requester, digest, encoded, created,
                  expires, now))
            self._event(db, request_id, site_id, requester, "created", None,
                        "pending_approval", {"change_count": body.get("change_count"), "packet_sha256": digest})
            row = db.execute(
                "SELECT * FROM rf_change_requests WHERE request_id = ?", (request_id,)
            ).fetchone()
            return self._row(db, row)

    def get(self, site_id, request_id, *, include_packet=True):
        site_id = _site(site_id)
        request_id = _request_id(request_id)
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM rf_change_requests WHERE site_id = ? AND request_id = ?",
                (site_id, request_id),
            ).fetchone()
            if row is None:
                return None
            row = self._expire_if_due(db, row)
            return self._row(db, row, include_packet=include_packet)

    def list_for_site(self, site_id, *, limit=50):
        site_id = _site(site_id)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("limit must be an integer from 1 to 100")
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute(
                "SELECT * FROM rf_change_requests WHERE site_id = ? ORDER BY created_at DESC, id DESC LIMIT ?",
                (site_id, limit),
            ).fetchall()
            output = []
            for row in rows:
                row = self._expire_if_due(db, row)
                output.append(self._row(db, row))
            return output

    def decide(self, site_id, request_id, *, actor, decision, comment=""):
        site_id = _site(site_id)
        request_id = _request_id(request_id)
        actor = _actor(actor)
        if decision not in {"approve", "reject"}:
            raise ValueError("decision must be approve or reject")
        if not isinstance(comment, str) or len(comment) > 1000 or any(ord(ch) < 32 and ch not in "\t\n\r" for ch in comment):
            raise ValueError("comment must contain no more than 1000 printable characters")
        comment = comment.strip()
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM rf_change_requests WHERE site_id = ? AND request_id = ?",
                (site_id, request_id),
            ).fetchone()
            if row is None:
                return None
            row = self._expire_if_due(db, row)
            if row["status"] == "expired":
                raise ValueError("approval request has expired")
            if row["status"] != "pending_approval":
                raise ValueError(f"approval request is already {row['status']}")
            if actor == row["requested_by"]:
                raise ValueError("the requester cannot approve or reject their own change request")
            if db.execute(
                "SELECT 1 FROM rf_change_approvals WHERE request_id = ? AND actor = ?",
                (request_id, actor),
            ).fetchone():
                raise ValueError("this approver has already recorded a decision")
            now = _now().isoformat(timespec="seconds")
            db.execute("""
                INSERT INTO rf_change_approvals(request_id, actor, decision, comment, occurred_at)
                VALUES (?, ?, ?, ?, ?)
            """, (request_id, actor, decision, comment, now))
            if decision == "reject":
                next_status = "rejected"
            else:
                votes = db.execute(
                    "SELECT COUNT(*) FROM rf_change_approvals WHERE request_id = ? AND decision = 'approve'",
                    (request_id,),
                ).fetchone()[0]
                next_status = "approved_not_applied" if votes >= 2 else "pending_approval"
            self._event(db, request_id, site_id, actor, decision, row["status"], next_status,
                        {"comment": comment})
            changed = db.execute("""
                UPDATE rf_change_requests
                SET status = ?, updated_at = ?, state_version = state_version + 1
                WHERE request_id = ? AND state_version = ? AND status = 'pending_approval'
            """, (next_status, now, request_id, row["state_version"]))
            if changed.rowcount != 1:
                raise RuntimeError("RF change approval state changed concurrently")
            updated = db.execute(
                "SELECT * FROM rf_change_requests WHERE request_id = ?", (request_id,)
            ).fetchone()
            return self._row(db, updated)

    def cancel(self, site_id, request_id, *, actor):
        site_id = _site(site_id)
        request_id = _request_id(request_id)
        actor = _actor(actor)
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM rf_change_requests WHERE site_id = ? AND request_id = ?",
                (site_id, request_id),
            ).fetchone()
            if row is None:
                return None
            row = self._expire_if_due(db, row)
            if row["status"] != "pending_approval":
                raise ValueError(f"only pending requests can be cancelled; current status is {row['status']}")
            if actor != row["requested_by"]:
                raise ValueError("only the original requester can cancel this request")
            now = _now().isoformat(timespec="seconds")
            self._event(db, request_id, site_id, actor, "cancelled", row["status"], "cancelled")
            db.execute("""
                UPDATE rf_change_requests SET status = 'cancelled', updated_at = ?,
                    state_version = state_version + 1
                WHERE request_id = ? AND state_version = ?
            """, (now, request_id, row["state_version"]))
            updated = db.execute(
                "SELECT * FROM rf_change_requests WHERE request_id = ?", (request_id,)
            ).fetchone()
            return self._row(db, updated)

    def invalidate(self, site_id, request_id, *, actor="system", reason):
        site_id = _site(site_id)
        request_id = _request_id(request_id)
        actor = _actor(actor)
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 256:
            raise ValueError("reason must contain 1 to 256 characters")
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM rf_change_requests WHERE site_id = ? AND request_id = ?",
                (site_id, request_id),
            ).fetchone()
            if row is None:
                return None
            row = self._expire_if_due(db, row)
            if row["status"] not in {"pending_approval", "approved_not_applied"}:
                return self._row(db, row)
            now = _now().isoformat(timespec="seconds")
            self._event(db, request_id, site_id, actor, "invalidated", row["status"], "invalidated",
                        {"reason": reason.strip()})
            db.execute("""
                UPDATE rf_change_requests SET status = 'invalidated', updated_at = ?,
                    state_version = state_version + 1
                WHERE request_id = ? AND state_version = ?
            """, (now, request_id, row["state_version"]))
            updated = db.execute(
                "SELECT * FROM rf_change_requests WHERE request_id = ?", (request_id,)
            ).fetchone()
            return self._row(db, updated)

    def record_execution_blocked(self, site_id, request_id, *, actor, reason):
        site_id = _site(site_id)
        request_id = _request_id(request_id)
        actor = _actor(actor)
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 256:
            raise ValueError("reason must contain 1 to 256 characters")
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM rf_change_requests WHERE site_id = ? AND request_id = ?",
                (site_id, request_id),
            ).fetchone()
            if row is None:
                return None
            row = self._expire_if_due(db, row)
            if row["status"] != "approved_not_applied":
                raise ValueError("only fully approved requests can enter the deployment gate")
            self._event(db, request_id, site_id, actor, "execution_blocked", row["status"], row["status"],
                        {"reason": reason.strip(), "write_adapter_available": False})
            return self._row(db, row)

    def site_ids(self, *, limit=100):
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("limit must be an integer from 1 to 100")
        with self._db() as db:
            rows = db.execute(
                "SELECT DISTINCT site_id FROM rf_change_requests ORDER BY site_id LIMIT ?", (limit,)
            ).fetchall()
        return [row["site_id"] for row in rows]
