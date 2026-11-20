"""Durable, transactional scheduled-report job queue with worker leases and retries."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

if __package__ and "." in __package__:
    from ..site_history import default_history_path
else:  # Direct execution/import through the router_adapters package.
    from site_history import default_history_path

MAX_JOBS_TOTAL = 10000
MAX_JOBS_PER_SCHEDULE = 1000
MAX_REPORT_BUNDLE_BYTES = 512 * 1024
MAX_RESULT_BYTES = 16 * 1024
MAX_CLAIM_BATCH = 50
MIN_LEASE_SECONDS = 15
MAX_LEASE_SECONDS = 3600
MAX_LIST_LIMIT = 100
MAX_ATTEMPTS = 10
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
ERROR_CODE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
JOB_STATUSES = {"pending", "leased", "retry_wait", "completed", "dead_letter", "cancelled"}
RESULT_FIELDS = {"report_id", "content_hash", "event_batch_id", "delivered_at", "http_status", "delivery_status"}


class ReportJobConflictError(ValueError):
    """Raised when an idempotency key is reused for different job content."""


class ReportJobNotFoundError(ValueError):
    """Raised when a job or worker lease does not exist or is no longer valid."""


class RouterReportJobStore:
    """SQLite outbox for report jobs; credentials and raw error messages are never stored."""

    def __init__(self, path=None):
        self.path = str(path or default_history_path().with_name("router-report-jobs.sqlite3"))

    @contextmanager
    def _connection(self):
        parent = os.path.dirname(self.path) or "."
        existed = os.path.exists(parent)
        os.makedirs(parent, mode=0o700, exist_ok=True)
        if os.name != "nt" and not existed:
            try:
                os.chmod(parent, 0o700)
            except OSError:
                pass
        connection = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS router_report_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                schedule_id TEXT NOT NULL,
                occurrence_id TEXT NOT NULL,
                report_id TEXT NOT NULL,
                job_key TEXT NOT NULL UNIQUE,
                payload_hash TEXT NOT NULL,
                report_bundle_json TEXT NOT NULL,
                scheduled_at TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN (
                    'pending','leased','retry_wait','completed','dead_letter','cancelled'
                )),
                attempts INTEGER NOT NULL DEFAULT 0,
                max_attempts INTEGER NOT NULL,
                available_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                lease_id TEXT,
                lease_owner TEXT,
                lease_expires_at TEXT,
                result_json TEXT,
                error_code TEXT,
                completed_at TEXT,
                UNIQUE(schedule_id, occurrence_id)
            )
        """)
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_router_report_jobs_due "
            "ON router_report_jobs(status, available_at, scheduled_at, id)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_router_report_jobs_schedule "
            "ON router_report_jobs(schedule_id, id DESC)"
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
    def _timestamp(value, field):
        if isinstance(value, datetime):
            parsed = value
        else:
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp")
            try:
                parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
            except ValueError as error:
                raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp") from error
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError(f"{field} must include a timezone offset")
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _identifier(value, field):
        if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
            raise ValueError(f"{field} must be a 1 to 64 character identifier")
        return value

    @staticmethod
    def _json(value, field, maximum):
        try:
            rendered = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError) as error:
            raise ValueError(f"{field} must contain JSON-compatible finite values") from error
        if len(rendered.encode("utf-8")) > maximum:
            raise ValueError(f"{field} exceeds the {maximum}-byte limit")
        return rendered

    @staticmethod
    def _job(row, include_bundle=False):
        result = {
            "id": row["id"],
            "schedule_id": row["schedule_id"],
            "occurrence_id": row["occurrence_id"],
            "report_id": row["report_id"],
            "job_key": row["job_key"],
            "payload_hash": row["payload_hash"],
            "scheduled_at": row["scheduled_at"],
            "status": row["status"],
            "attempts": row["attempts"],
            "max_attempts": row["max_attempts"],
            "available_at": row["available_at"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "lease_owner": row["lease_owner"],
            "lease_expires_at": row["lease_expires_at"],
            "error_code": row["error_code"],
            "completed_at": row["completed_at"],
            "result": json.loads(row["result_json"]) if row["result_json"] else None,
        }
        if include_bundle:
            result["report_bundle"] = json.loads(row["report_bundle_json"])
            result["lease_id"] = row["lease_id"]
        return result

    @classmethod
    def _backoff_seconds(cls, attempts):
        return min(30 * (2 ** max(0, min(attempts - 1, 7))), 3600)

    def enqueue(self, prepared_job, *, now=None):
        if not isinstance(prepared_job, dict):
            raise ValueError("prepared_job must be an object")
        schedule_id = self._identifier(prepared_job.get("schedule_id"), "schedule_id")
        occurrence_id = self._identifier(prepared_job.get("occurrence_id"), "occurrence_id")
        report_id = self._identifier(prepared_job.get("report_id"), "report_id")
        scheduled_at = self._timestamp(prepared_job.get("scheduled_at"), "scheduled_at")
        bundle = prepared_job.get("report_bundle")
        if not isinstance(bundle, dict):
            raise ValueError("report_bundle must be an object")
        if bundle.get("report_id") != report_id or bundle.get("schema_version") != "1.0":
            raise ValueError("report_bundle identity or schema_version does not match the job")
        bundle_json = self._json(bundle, "report_bundle", MAX_REPORT_BUNDLE_BYTES)
        if bundle.get("schema_version") != "1.0" or not isinstance(bundle.get("content_hash"), str):
            raise ValueError("report_bundle must be a version 1.0 hash-validated report")
        bundle_body = {key: value for key, value in bundle.items() if key != "content_hash"}
        canonical_bundle = self._json(bundle_body, "report_bundle", MAX_REPORT_BUNDLE_BYTES)
        expected_content_hash = hashlib.sha256(canonical_bundle.encode("utf-8")).hexdigest()
        if not SHA256.fullmatch(bundle["content_hash"]) or not hmac.compare_digest(
            expected_content_hash, bundle["content_hash"]
        ):
            raise ValueError("report_bundle.content_hash does not match its content")
        payload_hash = hashlib.sha256(bundle_json.encode("utf-8")).hexdigest()
        job_key = prepared_job.get("job_key")
        if not isinstance(job_key, str) or not SHA256.fullmatch(job_key):
            raise ValueError("job_key must be a 64-character lowercase SHA-256 digest")
        expected_key = hashlib.sha256(
            json.dumps([schedule_id, occurrence_id, report_id], separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if job_key != expected_key:
            raise ValueError("job_key does not match the schedule, occurrence and report identity")
        max_attempts = prepared_job.get("max_attempts", 5)
        if isinstance(max_attempts, bool) or not isinstance(max_attempts, int) or not 1 <= max_attempts <= MAX_ATTEMPTS:
            raise ValueError(f"max_attempts must be an integer from 1 to {MAX_ATTEMPTS}")
        now_value = (
            self._timestamp(now, "now") if now is not None else datetime.now(timezone.utc)
        ).isoformat()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM router_report_jobs WHERE schedule_id=? AND occurrence_id=?",
                (schedule_id, occurrence_id),
            ).fetchone()
            if existing:
                if existing["job_key"] != job_key or existing["payload_hash"] != payload_hash:
                    raise ReportJobConflictError("schedule occurrence already exists with different report content")
                return {"job": self._job(existing), "created": False, "replayed": True}
            total = connection.execute("SELECT COUNT(*) FROM router_report_jobs").fetchone()[0]
            per_schedule = connection.execute(
                "SELECT COUNT(*) FROM router_report_jobs WHERE schedule_id=?", (schedule_id,)
            ).fetchone()[0]
            if total >= MAX_JOBS_TOTAL:
                raise ValueError(f"report job store is full at {MAX_JOBS_TOTAL} jobs")
            if per_schedule >= MAX_JOBS_PER_SCHEDULE:
                raise ValueError(f"schedule exceeds {MAX_JOBS_PER_SCHEDULE} retained jobs")
            cursor = connection.execute("""
                INSERT INTO router_report_jobs (
                    schedule_id, occurrence_id, report_id, job_key, payload_hash,
                    report_bundle_json, scheduled_at, status, attempts, max_attempts,
                    available_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', 0, ?, ?, ?, ?)
            """, (
                schedule_id, occurrence_id, report_id, job_key, payload_hash, bundle_json,
                scheduled_at.isoformat(), max_attempts, scheduled_at.isoformat(), now_value, now_value,
            ))
            row = connection.execute(
                "SELECT * FROM router_report_jobs WHERE id=?", (cursor.lastrowid,)
            ).fetchone()
            return {"job": self._job(row), "created": True, "replayed": False}

    def claim_due(self, worker_id, *, now=None, lease_seconds=120, limit=10):
        worker_id = self._identifier(worker_id, "worker_id")
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int) or not MIN_LEASE_SECONDS <= lease_seconds <= MAX_LEASE_SECONDS:
            raise ValueError(f"lease_seconds must be an integer from {MIN_LEASE_SECONDS} to {MAX_LEASE_SECONDS}")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_CLAIM_BATCH:
            raise ValueError(f"limit must be an integer from 1 to {MAX_CLAIM_BATCH}")
        moment = self._timestamp(now, "now") if now is not None else datetime.now(timezone.utc)
        now_text = moment.isoformat()
        lease_expires = (moment + timedelta(seconds=lease_seconds)).isoformat()
        claimed = []
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            expired = connection.execute(
                "SELECT id, attempts, max_attempts FROM router_report_jobs "
                "WHERE status='leased' AND lease_expires_at <= ?",
                (now_text,),
            ).fetchall()
            for row in expired:
                attempts = row["attempts"]
                dead = attempts >= row["max_attempts"]
                retry_at = (
                    moment + timedelta(seconds=self._backoff_seconds(attempts))
                ).isoformat()
                connection.execute("""
                    UPDATE router_report_jobs
                    SET status=?, available_at=?, updated_at=?, lease_id=NULL,
                        lease_owner=NULL, lease_expires_at=NULL, error_code=?
                    WHERE id=? AND status='leased'
                """, (
                    "dead_letter" if dead else "retry_wait", retry_at, now_text,
                    "lease_expired", row["id"],
                ))
            due = connection.execute("""
                SELECT id FROM router_report_jobs
                WHERE status IN ('pending','retry_wait') AND available_at <= ?
                ORDER BY scheduled_at, id LIMIT ?
            """, (now_text, limit)).fetchall()
            for selected in due:
                lease_id = str(uuid.uuid4())
                connection.execute("""
                    UPDATE router_report_jobs
                    SET status='leased', attempts=attempts+1, updated_at=?,
                        lease_id=?, lease_owner=?, lease_expires_at=?, error_code=NULL
                    WHERE id=? AND status IN ('pending','retry_wait')
                """, (now_text, lease_id, worker_id, lease_expires, selected["id"]))
                row = connection.execute(
                    "SELECT * FROM router_report_jobs WHERE id=?", (selected["id"],)
                ).fetchone()
                if row and row["status"] == "leased" and row["lease_id"] == lease_id:
                    claimed.append(self._job(row, include_bundle=True))
        return {"worker_id": worker_id, "claimed_at": now_text, "jobs": claimed}

    def renew_lease(self, job_id, lease_id, *, now=None, lease_seconds=120):
        job_id = self._job_id(job_id)
        lease_id = self._lease_id(lease_id)
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int) or not MIN_LEASE_SECONDS <= lease_seconds <= MAX_LEASE_SECONDS:
            raise ValueError(f"lease_seconds must be an integer from {MIN_LEASE_SECONDS} to {MAX_LEASE_SECONDS}")
        moment = self._timestamp(now, "now") if now is not None else datetime.now(timezone.utc)
        expires = (moment + timedelta(seconds=lease_seconds)).isoformat()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute("""
                UPDATE router_report_jobs SET lease_expires_at=?, updated_at=?
                WHERE id=? AND status='leased' AND lease_id=? AND lease_expires_at>?
            """, (expires, moment.isoformat(), job_id, lease_id, moment.isoformat()))
            if cursor.rowcount != 1:
                raise ReportJobNotFoundError("job lease is missing, expired or no longer owned")
            row = connection.execute("SELECT * FROM router_report_jobs WHERE id=?", (job_id,)).fetchone()
            return self._job(row)

    @staticmethod
    def _job_id(value):
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError("job_id must be a positive integer")
        return value

    @staticmethod
    def _lease_id(value):
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f-]{36}", value):
            raise ValueError("lease_id must be a UUID")
        return value

    def complete(self, job_id, lease_id, result, *, now=None):
        job_id = self._job_id(job_id)
        lease_id = self._lease_id(lease_id)
        if not isinstance(result, dict):
            raise ValueError("result must be an object")
        safe_result = {}
        for key, value in result.items():
            if key not in RESULT_FIELDS:
                continue
            if key in {"http_status"}:
                if isinstance(value, bool) or not isinstance(value, int) or not 100 <= value <= 599:
                    raise ValueError("result.http_status must be an HTTP status integer from 100 to 599")
                safe_result[key] = value
            elif key in {"content_hash"}:
                if not isinstance(value, str) or not SHA256.fullmatch(value):
                    raise ValueError("result.content_hash must be a SHA-256 digest")
                safe_result[key] = value
            elif value is not None:
                if not isinstance(value, str) or len(value) > 128:
                    raise ValueError(f"result.{key} must be a string of at most 128 characters")
                safe_result[key] = value
        result_json = self._json(safe_result, "result", MAX_RESULT_BYTES)
        moment = self._timestamp(now, "now") if now is not None else datetime.now(timezone.utc)
        now_text = moment.isoformat()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute("""
                UPDATE router_report_jobs
                SET status='completed', result_json=?, completed_at=?, updated_at=?,
                    lease_id=NULL, lease_owner=NULL, lease_expires_at=NULL, error_code=NULL
                WHERE id=? AND status='leased' AND lease_id=? AND lease_expires_at>?
            """, (result_json, now_text, now_text, job_id, lease_id, now_text))
            if cursor.rowcount != 1:
                raise ReportJobNotFoundError("job lease is missing, expired or no longer owned")
            row = connection.execute("SELECT * FROM router_report_jobs WHERE id=?", (job_id,)).fetchone()
            return self._job(row)

    def fail(self, job_id, lease_id, error_code, *, now=None):
        job_id = self._job_id(job_id)
        lease_id = self._lease_id(lease_id)
        if not isinstance(error_code, str) or not ERROR_CODE.fullmatch(error_code):
            raise ValueError("error_code must be a stable lowercase error identifier")
        moment = self._timestamp(now, "now") if now is not None else datetime.now(timezone.utc)
        now_text = moment.isoformat()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM router_report_jobs WHERE id=? AND status='leased' "
                "AND lease_id=? AND lease_expires_at>?",
                (job_id, lease_id, now_text),
            ).fetchone()
            if row is None:
                raise ReportJobNotFoundError("job lease is missing, expired or no longer owned")
            exhausted = row["attempts"] >= row["max_attempts"]
            delay = 0 if exhausted else self._backoff_seconds(row["attempts"])
            retry_at = (moment + timedelta(seconds=delay)).isoformat()
            status = "dead_letter" if exhausted else "retry_wait"
            connection.execute("""
                UPDATE router_report_jobs
                SET status=?, available_at=?, updated_at=?, lease_id=NULL,
                    lease_owner=NULL, lease_expires_at=NULL, error_code=?
                WHERE id=? AND status='leased' AND lease_id=?
            """, (status, retry_at, now_text, error_code, job_id, lease_id))
            updated = connection.execute(
                "SELECT * FROM router_report_jobs WHERE id=?", (job_id,)
            ).fetchone()
            return {**self._job(updated), "retry_delay_seconds": delay}

    def cancel(self, job_id, *, now=None):
        job_id = self._job_id(job_id)
        moment = self._timestamp(now, "now") if now is not None else datetime.now(timezone.utc)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute("""
                UPDATE router_report_jobs
                SET status='cancelled', updated_at=?, error_code=NULL
                WHERE id=? AND status IN ('pending','retry_wait')
            """, (moment.isoformat(), job_id))
            if cursor.rowcount != 1:
                raise ReportJobNotFoundError("job is not pending or retryable")
            row = connection.execute("SELECT * FROM router_report_jobs WHERE id=?", (job_id,)).fetchone()
            return self._job(row)

    def get(self, job_id, *, include_bundle=False):
        job_id = self._job_id(job_id)
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM router_report_jobs WHERE id=?", (job_id,)).fetchone()
            return self._job(row, include_bundle=include_bundle) if row else None

    def list_jobs(self, *, status=None, schedule_id=None, limit=50):
        if status is not None and status not in JOB_STATUSES:
            raise ValueError("status is not a supported report-job state")
        if schedule_id is not None:
            schedule_id = self._identifier(schedule_id, "schedule_id")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LIST_LIMIT:
            raise ValueError(f"limit must be an integer from 1 to {MAX_LIST_LIMIT}")
        where, params = [], []
        if status is not None:
            where.append("status=?")
            params.append(status)
        if schedule_id is not None:
            where.append("schedule_id=?")
            params.append(schedule_id)
        query = "SELECT * FROM router_report_jobs"
        if where:
            query += " WHERE " + " AND ".join(where)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._connection() as connection:
            rows = connection.execute(query, params).fetchall()
            return [self._job(row) for row in rows]

    def summary(self):
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT status, COUNT(*) AS count FROM router_report_jobs GROUP BY status"
            ).fetchall()
        counts = {status: 0 for status in sorted(JOB_STATUSES)}
        counts.update({row["status"]: row["count"] for row in rows})
        return {"job_count": sum(counts.values()), "counts_by_status": counts}


__all__ = [
    "RouterReportJobStore",
    "ReportJobConflictError",
    "ReportJobNotFoundError",
]
