"""Persistent, site-scoped webhook subscription metadata (never stores HMAC secrets)."""
from __future__ import annotations

import json
import os
import re
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any

if __package__:
    from .feature_plugins.feature_190_router_webhook_subscription_router import _subscription as normalize_subscription
    from .site_history import default_history_path
else:
    from feature_plugins.feature_190_router_webhook_subscription_router import _subscription as normalize_subscription
    from site_history import default_history_path

MAX_SUBSCRIPTIONS = 100
SITE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class WebhookSubscriptionConflictError(ValueError):
    """An ID is already in use by a different subscription."""


class WebhookSubscriptionNotFoundError(KeyError):
    """A subscription is absent or outside the caller's site scope."""


def _scope(value: Any) -> set[str] | None:
    if value is None:
        return None
    if not isinstance(value, list) or len(value) > 128:
        raise ValueError("site scope must be a list of at most 128 site identifiers")
    if any(not isinstance(item, str) or not SITE_ID.fullmatch(item) for item in value):
        raise ValueError("site scope contains an invalid site identifier")
    if len(value) != len(set(value)):
        raise ValueError("site scope site identifiers must be unique")
    return set(value)


class WebhookSubscriptionStore:
    """SQLite-backed subscription registry containing metadata but never signing secrets."""

    def __init__(self, path: str | os.PathLike[str] | None = None):
        configured = path or os.environ.get("WIFI_ANALYZER_WEBHOOK_SUBSCRIPTIONS_DB")
        self.path = Path(configured).expanduser() if configured else (
            default_history_path().with_name("webhook-subscriptions.sqlite3")
        )
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
                CREATE TABLE IF NOT EXISTS webhook_subscriptions (
                    subscription_id TEXT PRIMARY KEY,
                    configuration_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_webhook_subscriptions_updated "
                "ON webhook_subscriptions(updated_at, subscription_id)"
            )

    @staticmethod
    def _normalise(value: Any) -> dict:
        result = normalize_subscription(value, 0)
        # The router's own validator is authoritative for URL, allowlist,
        # event-type, severity, batch-bound and identifier rules.
        return result

    @staticmethod
    def _public(row: sqlite3.Row) -> dict:
        configuration = json.loads(row["configuration_json"])
        return {
            **configuration,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    @staticmethod
    def _require_scope(configuration: dict, scope: set[str] | None):
        if scope is None:
            return
        sites = set(configuration["site_allowlist"])
        if not sites or not sites.issubset(scope):
            raise PermissionError("subscription must explicitly target only sites assigned to your account")

    def create(self, value: Any, *, allowed_site_ids: list[str] | None = None, now: str | None = None) -> dict:
        configuration = self._normalise(value)
        scope = _scope(allowed_site_ids)
        self._require_scope(configuration, scope)
        if now is None:
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc).isoformat()
        if not isinstance(now, str) or not now:
            raise ValueError("now must be a non-empty ISO timestamp")
        encoded = json.dumps(configuration, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT subscription_id FROM webhook_subscriptions WHERE subscription_id=?",
                (configuration["subscription_id"],),
            ).fetchone()
            if existing:
                raise WebhookSubscriptionConflictError("subscription_id is already registered")
            count = connection.execute("SELECT COUNT(*) AS count FROM webhook_subscriptions").fetchone()["count"]
            if count >= MAX_SUBSCRIPTIONS:
                raise ValueError(f"the workspace supports at most {MAX_SUBSCRIPTIONS} webhook subscriptions")
            connection.execute(
                "INSERT INTO webhook_subscriptions(subscription_id, configuration_json, created_at, updated_at) "
                "VALUES (?, ?, ?, ?)",
                (configuration["subscription_id"], encoded, now, now),
            )
            row = connection.execute(
                "SELECT * FROM webhook_subscriptions WHERE subscription_id=?",
                (configuration["subscription_id"],),
            ).fetchone()
        return self._public(row)

    def get(self, subscription_id: Any, *, site_ids: list[str] | None = None) -> dict | None:
        if not isinstance(subscription_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}", subscription_id):
            return None
        scope = _scope(site_ids)
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM webhook_subscriptions WHERE subscription_id=?",
                (subscription_id,),
            ).fetchone()
        if row is None:
            return None
        result = self._public(row)
        if scope is not None and (
            not result["site_allowlist"] or not set(result["site_allowlist"]).issubset(scope)
        ):
            return None
        return result

    def list_subscriptions(self, *, site_ids: list[str] | None = None, include_disabled: bool = True) -> list[dict]:
        scope = _scope(site_ids)
        if not isinstance(include_disabled, bool):
            raise ValueError("include_disabled must be a boolean")
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM webhook_subscriptions ORDER BY subscription_id"
            ).fetchall()
        result = []
        for row in rows:
            item = self._public(row)
            if not include_disabled and not item["enabled"]:
                continue
            sites = set(item["site_allowlist"])
            if scope is not None and (not sites or not sites.issubset(scope)):
                continue
            result.append(item)
        return result

    def update(
        self,
        subscription_id: Any,
        value: Any,
        *,
        allowed_site_ids: list[str] | None = None,
        now: str | None = None,
    ) -> dict:
        if not isinstance(subscription_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}", subscription_id):
            raise ValueError("subscription_id is invalid")
        configuration = self._normalise(value)
        if configuration["subscription_id"] != subscription_id:
            raise ValueError("subscription_id cannot be changed during an update")
        scope = _scope(allowed_site_ids)
        self._require_scope(configuration, scope)
        if now is None:
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc).isoformat()
        if not isinstance(now, str) or not now:
            raise ValueError("now must be a non-empty ISO timestamp")
        encoded = json.dumps(configuration, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM webhook_subscriptions WHERE subscription_id=?",
                (subscription_id,),
            ).fetchone()
            if row is None:
                raise WebhookSubscriptionNotFoundError("subscription not found")
            current = self._public(row)
            if scope is not None and (
                not current["site_allowlist"] or not set(current["site_allowlist"]).issubset(scope)
            ):
                raise WebhookSubscriptionNotFoundError("subscription not found")
            connection.execute(
                "UPDATE webhook_subscriptions SET configuration_json=?, updated_at=? WHERE subscription_id=?",
                (encoded, now, subscription_id),
            )
            updated = connection.execute(
                "SELECT * FROM webhook_subscriptions WHERE subscription_id=?",
                (subscription_id,),
            ).fetchone()
        return self._public(updated)

    def delete(self, subscription_id: Any, *, site_ids: list[str] | None = None) -> dict:
        existing = self.get(subscription_id, site_ids=site_ids)
        if existing is None:
            raise WebhookSubscriptionNotFoundError("subscription not found")
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "DELETE FROM webhook_subscriptions WHERE subscription_id=?",
                (subscription_id,),
            )
            if cursor.rowcount != 1:
                raise WebhookSubscriptionNotFoundError("subscription not found")
        return {"subscription_id": subscription_id, "deleted": True}


__all__ = [
    "WebhookSubscriptionStore",
    "WebhookSubscriptionConflictError",
    "WebhookSubscriptionNotFoundError",
]
