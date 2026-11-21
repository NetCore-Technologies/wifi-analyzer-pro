"""Durable, idempotent queue for prepared multi-subscription router webhooks."""
from __future__ import annotations

import ipaddress
import json
import os
import re
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

MAX_DELIVERIES_PER_ENQUEUE = 500
MAX_BODY_BYTES = 1024 * 1024
MAX_EVENTS_PER_DELIVERY = 500
MAX_SITE_IDS = 128
MAX_LIST_LIMIT = 100
MAX_ATTEMPTS = 20
DEFAULT_RETENTION_DAYS = 90
MIN_RETENTION_DAYS = 7
MAX_RETENTION_DAYS = 3650
TERMINAL_STATUSES = {"delivered", "dead_letter", "cancelled"}
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
SITE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
STATUSES = {"pending", "sending", "retry_wait", "delivered", "dead_letter", "cancelled"}
SIGNED_HEADERS = {
    "Content-Type", "X-WiFiAnalyzer-Key-Id", "X-WiFiAnalyzer-Timestamp",
    "X-WiFiAnalyzer-Signature", "Idempotency-Key",
}
RETRYABLE_CODES = {
    "dns_resolution_failed", "dns_policy_blocked", "delivery_connection_failed",
    "delivery_tls_failed", "delivery_timeout", "egress_policy_blocked",
    "delivery_http_error", "delivery_response_too_large", "delivery_transport_error",
    "delivery_request_too_large", "redirect_refused",
}


class WebhookDeliveryConflictError(ValueError):
    """An idempotency key was reused for a different prepared envelope."""


class WebhookDeliveryNotFoundError(KeyError):
    """A delivery does not exist or is not available under its current lease."""


def _now(value: Any = None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, str):
        try:
            result = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError("timestamp must be a timezone-aware ISO-8601 value") from error
    else:
        raise ValueError("timestamp must be a timezone-aware ISO-8601 value")
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("timestamp must include a timezone offset")
    return result.astimezone(timezone.utc)


def _site_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not SITE_ID.fullmatch(value):
        raise ValueError(f"{field} must be a 1 to 128 character site identifier")
    return value


def _endpoint(value: Any, allowed_hosts: Any) -> tuple[str, str, list[str]]:
    if not isinstance(allowed_hosts, list) or not 1 <= len(allowed_hosts) <= 50:
        raise ValueError("allowed_hosts must contain from 1 to 50 DNS hostnames")
    hosts = []
    for index, raw in enumerate(allowed_hosts):
        if not isinstance(raw, str) or not raw or len(raw) > 253:
            raise ValueError(f"allowed_hosts[{index}] must be a DNS hostname")
        try:
            host = raw.rstrip(".").lower().encode("idna").decode("ascii")
        except UnicodeError as error:
            raise ValueError(f"allowed_hosts[{index}] is not a valid IDNA hostname") from error
        if not host or "." not in host or any(not HOST_LABEL.fullmatch(label) for label in host.split(".")):
            raise ValueError(f"allowed_hosts[{index}] must be a fully-qualified DNS hostname")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError(f"allowed_hosts[{index}] must be a DNS hostname, not an IP address")
        hosts.append(host)
    if len(hosts) != len(set(hosts)):
        raise ValueError("allowed_hosts entries must be unique")
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError("endpoint must be an HTTPS URL of at most 2048 characters")
    if any(ord(char) < 32 or ord(char) == 127 or char == "\\" for char in value):
        raise ValueError("endpoint contains invalid control characters or backslashes")
    if "?" in value or "#" in value:
        raise ValueError("endpoint must not contain a query string or fragment")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise ValueError("endpoint must be a valid HTTPS URL") from error
    if parsed.scheme.lower() != "https" or not parsed.netloc or hostname is None:
        raise ValueError("endpoint must use HTTPS and contain a DNS hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("endpoint must not contain embedded credentials")
    if port not in (None, 443):
        raise ValueError("endpoint must use HTTPS port 443")
    try:
        host = hostname.rstrip(".").lower().encode("idna").decode("ascii")
    except UnicodeError as error:
        raise ValueError("endpoint hostname is invalid") from error
    if host not in hosts:
        raise ValueError("endpoint hostname is not present in the exact host allowlist")
    path = parsed.path or "/"
    if not path.startswith("/") or path.startswith("//"):
        raise ValueError("endpoint path must be absolute")
    return host, f"https://{host}{path}", sorted(hosts)


def _normalise_delivery(item: Any) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("each delivery must be an object")
    subscription_id = item.get("subscription_id")
    batch_id = item.get("batch_id")
    if not isinstance(subscription_id, str) or not IDENTIFIER.fullmatch(subscription_id):
        raise ValueError("subscription_id must be a 1 to 64 character identifier")
    if not isinstance(batch_id, str) or not IDENTIFIER.fullmatch(batch_id):
        raise ValueError("batch_id must be a 1 to 64 character identifier")
    host, endpoint, hosts = _endpoint(item.get("endpoint"), item.get("allowed_hosts"))
    if endpoint != item.get("endpoint"):
        raise ValueError("endpoint must be in canonical HTTPS form")
    headers = item.get("headers")
    if not isinstance(headers, dict) or set(headers) - SIGNED_HEADERS:
        raise ValueError("headers contain unsupported fields")
    normalized_headers = {}
    for name in SIGNED_HEADERS:
        value = headers.get(name)
        if name == "Content-Type":
            if value != "application/json":
                raise ValueError("Content-Type must be application/json")
            normalized_headers[name] = value
            continue
        if not isinstance(value, str) or not value or len(value) > 512 or any(c in value for c in "\r\n"):
            raise ValueError(f"{name} must be a bounded header value")
        normalized_headers[name] = value
    if set(normalized_headers) != SIGNED_HEADERS:
        raise ValueError("all signed webhook headers are required")
    if normalized_headers["Idempotency-Key"] != batch_id:
        raise ValueError("Idempotency-Key must match batch_id")
    if not IDENTIFIER.fullmatch(normalized_headers["X-WiFiAnalyzer-Key-Id"]):
        raise ValueError("X-WiFiAnalyzer-Key-Id is invalid")
    timestamp = normalized_headers["X-WiFiAnalyzer-Timestamp"]
    if not timestamp.isdigit() or len(timestamp) > 12:
        raise ValueError("X-WiFiAnalyzer-Timestamp must be a Unix timestamp")
    signature = normalized_headers["X-WiFiAnalyzer-Signature"]
    if not re.fullmatch(r"v1=[0-9a-f]{64}", signature):
        raise ValueError("X-WiFiAnalyzer-Signature must be a lowercase HMAC-SHA256 signature")

    body = item.get("body")
    if not isinstance(body, str) or not body or len(body.encode("utf-8")) > MAX_BODY_BYTES:
        raise ValueError(f"body must be a non-empty string no larger than {MAX_BODY_BYTES} bytes")
    try:
        body_data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError("body must contain valid JSON") from error
    if not isinstance(body_data, dict) or body_data.get("batch_id") != batch_id:
        raise ValueError("body batch_id does not match the delivery metadata")
    if body_data.get("key_id") != normalized_headers["X-WiFiAnalyzer-Key-Id"]:
        raise ValueError("body key_id does not match the signed header")
    events = body_data.get("events")
    if not isinstance(events, list) or not 1 <= len(events) <= MAX_EVENTS_PER_DELIVERY:
        raise ValueError(f"body.events must contain from 1 to {MAX_EVENTS_PER_DELIVERY} events")
    site_ids = set()
    has_unscoped_events = False
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            raise ValueError(f"body.events[{index}] must be an object")
        site_id = event.get("site_id")
        if site_id is None:
            has_unscoped_events = True
        else:
            site_ids.add(_site_id(site_id, f"body.events[{index}].site_id"))
    if len(site_ids) > MAX_SITE_IDS:
        raise ValueError(f"delivery contains more than {MAX_SITE_IDS} sites")
    event_count = item.get("event_count", len(events))
    if isinstance(event_count, bool) or not isinstance(event_count, int) or event_count != len(events):
        raise ValueError("event_count must match the signed event body")
    if item.get("status") not in (None, "prepared"):
        raise ValueError("only prepared deliveries may be queued")
    if body_data.get("schema_version") != "1.0":
        raise ValueError("unsupported signed webhook body schema")
    return {
        "subscription_id": subscription_id,
        "batch_id": batch_id,
        "endpoint": endpoint,
        "allowed_hosts": hosts,
        "headers": normalized_headers,
        "body": body,
        "event_count": event_count,
        "site_ids": sorted(site_ids),
        "has_unscoped_events": has_unscoped_events,
    }


class WebhookDeliveryStore:
    """SQLite outbox with idempotent enqueue, exclusive leases and bounded retry state."""

    def __init__(
        self,
        path: str | os.PathLike[str] | None = None,
        *,
        retention_days: int | None = None,
    ):
        if retention_days is None:
            raw_retention = os.environ.get(
                "WIFI_ANALYZER_WEBHOOK_DELIVERY_RETENTION_DAYS",
                str(DEFAULT_RETENTION_DAYS),
            )
            try:
                retention_days = int(raw_retention)
            except (TypeError, ValueError) as error:
                raise ValueError("WIFI_ANALYZER_WEBHOOK_DELIVERY_RETENTION_DAYS must be an integer") from error
        if (
            isinstance(retention_days, bool)
            or not isinstance(retention_days, int)
            or not MIN_RETENTION_DAYS <= retention_days <= MAX_RETENTION_DAYS
        ):
            raise ValueError(
                f"retention_days must be between {MIN_RETENTION_DAYS} and {MAX_RETENTION_DAYS}"
            )
        self.retention_days = retention_days
        configured = path or os.environ.get("WIFI_ANALYZER_WEBHOOK_DELIVERY_DB")
        if configured:
            self.path = Path(configured).expanduser()
        else:
            if __package__:
                from .site_history import default_history_path
            else:
                from site_history import default_history_path
            self.path = default_history_path().with_name("webhook-deliveries.sqlite3")
        self._ensure_schema()

    @contextmanager
    def _connection(self):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt":
            try:
                os.chmod(self.path.parent, 0o700)
            except OSError:
                pass
        connection = sqlite3.connect(str(self.path), timeout=15, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=15000")
        connection.execute("PRAGMA journal_mode=WAL")
        try:
            yield connection
            if os.name != "nt":
                try:
                    os.chmod(self.path, 0o600)
                except OSError:
                    pass
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _ensure_schema(self):
        with self._connection() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS webhook_deliveries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subscription_id TEXT NOT NULL,
                    batch_id TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    allowed_hosts_json TEXT NOT NULL,
                    headers_json TEXT NOT NULL,
                    body TEXT NOT NULL,
                    event_count INTEGER NOT NULL,
                    site_ids_json TEXT NOT NULL,
                    has_unscoped_events INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    attempts INTEGER NOT NULL,
                    max_attempts INTEGER NOT NULL,
                    available_at TEXT NOT NULL,
                    lease_id TEXT,
                    worker_id TEXT,
                    lease_expires_at TEXT,
                    last_error_code TEXT,
                    response_status INTEGER,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    delivered_at TEXT,
                    UNIQUE(subscription_id, batch_id)
                )
            """)
            connection.execute("CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_due ON webhook_deliveries(status, available_at, id)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_scope ON webhook_deliveries(status, id)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_retention ON webhook_deliveries(status, updated_at)")

    @staticmethod
    def _public(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "subscription_id": row["subscription_id"],
            "batch_id": row["batch_id"],
            "endpoint": row["endpoint"],
            "event_count": row["event_count"],
            "site_ids": json.loads(row["site_ids_json"]),
            "has_unscoped_events": bool(row["has_unscoped_events"]),
            "status": row["status"],
            "attempts": row["attempts"],
            "max_attempts": row["max_attempts"],
            "available_at": row["available_at"],
            "lease_expires_at": row["lease_expires_at"],
            "last_error_code": row["last_error_code"],
            "response_status": row["response_status"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "delivered_at": row["delivered_at"],
        }

    @classmethod
    def _job(cls, row: sqlite3.Row) -> dict[str, Any]:
        result = cls._public(row)
        result.update({
            "allowed_hosts": json.loads(row["allowed_hosts_json"]),
            "headers": json.loads(row["headers_json"]),
            "body": row["body"],
            "lease_id": row["lease_id"],
            "worker_id": row["worker_id"],
        })
        return result

    @staticmethod
    def _validate_scope(site_ids: Any) -> set[str] | None:
        if site_ids is None:
            return None
        if not isinstance(site_ids, list) or len(site_ids) > MAX_SITE_IDS:
            raise ValueError(f"site_ids must be a list containing no more than {MAX_SITE_IDS} values")
        if any(not isinstance(item, str) or not SITE_ID.fullmatch(item) for item in site_ids):
            raise ValueError("site_ids contains an invalid site identifier")
        if len(site_ids) != len(set(site_ids)):
            raise ValueError("site_ids must be unique")
        return set(site_ids)

    def enqueue_many(
        self,
        deliveries: Any,
        *,
        now: Any = None,
        max_attempts: int = 6,
        allowed_site_ids: list[str] | None = None,
    ) -> dict:
        if not isinstance(deliveries, list) or not 1 <= len(deliveries) <= MAX_DELIVERIES_PER_ENQUEUE:
            raise ValueError(f"deliveries must contain from 1 to {MAX_DELIVERIES_PER_ENQUEUE} prepared envelopes")
        if isinstance(max_attempts, bool) or not isinstance(max_attempts, int) or not 1 <= max_attempts <= MAX_ATTEMPTS:
            raise ValueError(f"max_attempts must be from 1 to {MAX_ATTEMPTS}")
        scope = self._validate_scope(allowed_site_ids)
        normalized = [_normalise_delivery(item) for item in deliveries]
        unique_keys = [(item["subscription_id"], item["batch_id"]) for item in normalized]
        if len(unique_keys) != len(set(unique_keys)):
            raise ValueError("the enqueue request contains duplicate subscription/batch IDs")
        if scope is not None:
            for item in normalized:
                if item["has_unscoped_events"] or not item["site_ids"] or not set(item["site_ids"]).issubset(scope):
                    raise PermissionError("one or more deliveries contain sites outside the caller's assigned scope")
        now_value = _now(now).isoformat()
        created, duplicates = [], []
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            for item in normalized:
                cursor = connection.execute("""
                    INSERT OR IGNORE INTO webhook_deliveries (
                        subscription_id, batch_id, endpoint, allowed_hosts_json,
                        headers_json, body, event_count, site_ids_json,
                        has_unscoped_events, status, attempts, max_attempts,
                        available_at, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0, ?, ?, ?, ?)
                """, (
                    item["subscription_id"], item["batch_id"], item["endpoint"],
                    json.dumps(item["allowed_hosts"], separators=(",", ":")),
                    json.dumps(item["headers"], separators=(",", ":")),
                    item["body"], item["event_count"],
                    json.dumps(item["site_ids"], separators=(",", ":")),
                    int(item["has_unscoped_events"]), max_attempts,
                    now_value, now_value, now_value,
                ))
                row = connection.execute(
                    "SELECT * FROM webhook_deliveries WHERE subscription_id=? AND batch_id=?",
                    (item["subscription_id"], item["batch_id"]),
                ).fetchone()
                if cursor.rowcount:
                    created.append(self._public(row))
                else:
                    same = (
                        row["endpoint"] == item["endpoint"]
                        and row["allowed_hosts_json"] == json.dumps(item["allowed_hosts"], separators=(",", ":"))
                        and row["headers_json"] == json.dumps(item["headers"], separators=(",", ":"))
                        and row["body"] == item["body"]
                    )
                    if not same:
                        raise WebhookDeliveryConflictError("subscription/batch idempotency key was reused with different content")
                    duplicates.append(self._public(row))
        return {
            "created_count": len(created),
            "duplicate_count": len(duplicates),
            "deliveries": created + duplicates,
        }

    def prune(self, *, now: Any = None) -> dict:
        """Delete only terminal rows older than the configured retention window."""
        moment = _now(now)
        cutoff = (moment - timedelta(days=self.retention_days)).isoformat()
        counts = {status: 0 for status in sorted(TERMINAL_STATUSES)}
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT status, COUNT(*) AS count FROM webhook_deliveries "
                "WHERE status IN ('delivered','dead_letter','cancelled') AND updated_at < ? "
                "GROUP BY status",
                (cutoff,),
            ).fetchall()
            counts.update({row["status"]: row["count"] for row in rows})
            connection.execute(
                "DELETE FROM webhook_deliveries "
                "WHERE status IN ('delivered','dead_letter','cancelled') AND updated_at < ?",
                (cutoff,),
            )
        return {
            "retention_days": self.retention_days,
            "cutoff": cutoff,
            "deleted_count": sum(counts.values()),
            "deleted_by_status": counts,
        }

    def get(self, delivery_id: Any, *, include_body: bool = False) -> dict | None:
        if isinstance(delivery_id, bool) or not isinstance(delivery_id, int) or delivery_id < 1:
            return None
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM webhook_deliveries WHERE id=?", (delivery_id,)).fetchone()
        if row is None:
            return None
        return self._job(row) if include_body else self._public(row)

    def get_leased_job(self, delivery_id: int, lease_id: str, *, now: Any = None) -> dict | None:
        moment = _now(now)
        with self._connection() as connection:
            row = connection.execute("""
                SELECT * FROM webhook_deliveries
                WHERE id=? AND status='sending' AND lease_id=? AND lease_expires_at>?
            """, (delivery_id, lease_id, moment.isoformat())).fetchone()
        return self._job(row) if row else None

    def list_deliveries(self, *, status: str | None = None, limit: int = 50, site_ids=None) -> list[dict]:
        if status is not None and status not in STATUSES:
            raise ValueError("status is not a supported webhook-delivery state")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LIST_LIMIT:
            raise ValueError(f"limit must be an integer from 1 to {MAX_LIST_LIMIT}")
        scope = self._validate_scope(site_ids)
        with self._connection() as connection:
            if status:
                rows = connection.execute("SELECT * FROM webhook_deliveries WHERE status=? ORDER BY id DESC", (status,)).fetchall()
            else:
                rows = connection.execute("SELECT * FROM webhook_deliveries ORDER BY id DESC").fetchall()
        visible = []
        for row in rows:
            sites = set(json.loads(row["site_ids_json"]))
            if scope is not None and (
                bool(row["has_unscoped_events"]) or not sites or not sites.issubset(scope)
            ):
                continue
            visible.append(self._public(row))
            if len(visible) >= limit:
                break
        return visible

    def summary(self, *, site_ids=None) -> dict:
        scope = self._validate_scope(site_ids)
        with self._connection() as connection:
            rows = connection.execute("SELECT * FROM webhook_deliveries").fetchall()
        counts = {status: 0 for status in sorted(STATUSES)}
        for row in rows:
            sites = set(json.loads(row["site_ids_json"]))
            if scope is not None and (
                bool(row["has_unscoped_events"]) or not sites or not sites.issubset(scope)
            ):
                continue
            counts[row["status"]] += 1
        return {"delivery_count": sum(counts.values()), "counts_by_status": counts}

    def claim_due(
        self, worker_id: str, *, now: Any = None, lease_seconds: int = 120,
        limit: int = 5, site_ids=None,
    ) -> dict:
        if not isinstance(worker_id, str) or not IDENTIFIER.fullmatch(worker_id):
            raise ValueError("worker_id must be a 1 to 64 character identifier")
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int) or not 15 <= lease_seconds <= 3600:
            raise ValueError("lease_seconds must be from 15 to 3600")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 20:
            raise ValueError("limit must be from 1 to 20")
        scope = self._validate_scope(site_ids)
        moment = _now(now)
        now_text = moment.isoformat()
        lease_expiry = (moment + timedelta(seconds=lease_seconds)).isoformat()
        claimed = []
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            due = connection.execute("""
                SELECT id, site_ids_json, has_unscoped_events
                FROM webhook_deliveries
                WHERE (
                    status IN ('pending','retry_wait') AND available_at<=?
                    OR status='sending' AND lease_expires_at<=?
                )
                ORDER BY available_at, id LIMIT 1000
            """, (now_text, now_text)).fetchall()
            for row in due:
                sites = set(json.loads(row["site_ids_json"]))
                if scope is not None and (
                    bool(row["has_unscoped_events"]) or not sites or not sites.issubset(scope)
                ):
                    continue
                lease_id = uuid.uuid4().hex
                connection.execute("""
                    UPDATE webhook_deliveries SET status='sending', attempts=attempts+1,
                        lease_id=?, worker_id=?, lease_expires_at=?, updated_at=?
                    WHERE id=?
                """, (lease_id, worker_id, lease_expiry, now_text, row["id"]))
                claimed_row = connection.execute(
                    "SELECT * FROM webhook_deliveries WHERE id=?", (row["id"],)
                ).fetchone()
                claimed.append(self._job(claimed_row))
                if len(claimed) >= limit:
                    break
        return {"worker_id": worker_id, "claimed_count": len(claimed), "jobs": claimed}

    def renew_lease(self, delivery_id: int, lease_id: str, *, now: Any = None, lease_seconds: int = 120) -> dict:
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int) or not 15 <= lease_seconds <= 3600:
            raise ValueError("lease_seconds must be from 15 to 3600")
        moment = _now(now)
        updated = (moment + timedelta(seconds=lease_seconds)).isoformat()
        with self._connection() as connection:
            cursor = connection.execute("""
                UPDATE webhook_deliveries SET lease_expires_at=?, updated_at=?
                WHERE id=? AND status='sending' AND lease_id=? AND lease_expires_at>?
            """, (updated, moment.isoformat(), delivery_id, lease_id, moment.isoformat()))
            if cursor.rowcount != 1:
                raise WebhookDeliveryNotFoundError("active delivery lease not found")
            row = connection.execute("SELECT * FROM webhook_deliveries WHERE id=?", (delivery_id,)).fetchone()
        return self._public(row)

    def complete(self, delivery_id: int, lease_id: str, *, http_status: int, now: Any = None) -> dict:
        if isinstance(http_status, bool) or not isinstance(http_status, int) or not 200 <= http_status < 300:
            raise ValueError("http_status must be a successful 2xx response")
        moment = _now(now)
        value = moment.isoformat()
        with self._connection() as connection:
            cursor = connection.execute("""
                UPDATE webhook_deliveries
                SET status='delivered', response_status=?, delivered_at=?, updated_at=?,
                    lease_id=NULL, worker_id=NULL, lease_expires_at=NULL, last_error_code=NULL
                WHERE id=? AND status='sending' AND lease_id=? AND lease_expires_at>?
            """, (http_status, value, value, delivery_id, lease_id, value))
            if cursor.rowcount != 1:
                raise WebhookDeliveryNotFoundError("active delivery lease not found")
            row = connection.execute("SELECT * FROM webhook_deliveries WHERE id=?", (delivery_id,)).fetchone()
        return self._public(row)

    def fail(self, delivery_id: int, lease_id: str, error_code: str, *, now: Any = None) -> dict:
        if not isinstance(error_code, str) or error_code not in RETRYABLE_CODES:
            raise ValueError("error_code is not an approved safe delivery error code")
        moment = _now(now)
        value = moment.isoformat()
        with self._connection() as connection:
            row = connection.execute("""
                SELECT attempts, max_attempts FROM webhook_deliveries
                WHERE id=? AND status='sending' AND lease_id=? AND lease_expires_at>?
            """, (delivery_id, lease_id, value)).fetchone()
            if row is None:
                raise WebhookDeliveryNotFoundError("active delivery lease not found")
            exhausted = row["attempts"] >= row["max_attempts"]
            status = "dead_letter" if exhausted else "retry_wait"
            retry_seconds = min(3600, 5 * (2 ** min(row["attempts"] - 1, 9)))
            available = (moment + timedelta(seconds=retry_seconds)).isoformat()
            connection.execute("""
                UPDATE webhook_deliveries SET status=?, available_at=?, updated_at=?,
                    last_error_code=?, lease_id=NULL, worker_id=NULL, lease_expires_at=NULL
                WHERE id=?
            """, (status, available, value, error_code, delivery_id))
            updated = connection.execute("SELECT * FROM webhook_deliveries WHERE id=?", (delivery_id,)).fetchone()
        return self._public(updated)

    def retry(self, delivery_id: int, *, now: Any = None) -> dict:
        moment = _now(now)
        value = moment.isoformat()
        with self._connection() as connection:
            cursor = connection.execute("""
                UPDATE webhook_deliveries SET status='pending', attempts=0, available_at=?,
                    updated_at=?, last_error_code=NULL, response_status=NULL,
                    lease_id=NULL, worker_id=NULL, lease_expires_at=NULL
                WHERE id=? AND status IN ('dead_letter','cancelled')
            """, (value, value, delivery_id))
            if cursor.rowcount != 1:
                raise WebhookDeliveryNotFoundError("delivery is not available for manual retry")
            row = connection.execute("SELECT * FROM webhook_deliveries WHERE id=?", (delivery_id,)).fetchone()
        return self._public(row)

    def cancel(self, delivery_id: int, *, now: Any = None) -> dict:
        value = _now(now).isoformat()
        with self._connection() as connection:
            cursor = connection.execute("""
                UPDATE webhook_deliveries SET status='cancelled', updated_at=?
                WHERE id=? AND status IN ('pending','retry_wait')
            """, (value, delivery_id))
            if cursor.rowcount != 1:
                raise WebhookDeliveryNotFoundError("delivery is not pending or retryable")
            row = connection.execute("SELECT * FROM webhook_deliveries WHERE id=?", (delivery_id,)).fetchone()
        return self._public(row)


__all__ = [
    "WebhookDeliveryStore", "WebhookDeliveryConflictError",
    "WebhookDeliveryNotFoundError", "STATUSES",
    "DEFAULT_RETENTION_DAYS", "MIN_RETENTION_DAYS", "MAX_RETENTION_DAYS",
]
