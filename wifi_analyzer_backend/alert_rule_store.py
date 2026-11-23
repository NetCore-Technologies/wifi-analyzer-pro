"""Site-scoped persistent alert rules and incident lifecycle.

Rules are evaluated only from allowlisted, measured observations supplied by the
local scan and host-diagnostics paths. Missing measurements never resolve an
incident. Quiet hours suppress notification eligibility only; incident state
is still retained. This module does not send notifications.
"""
from __future__ import annotations

import json
import math
import os
import re
import sqlite3
import sys
import uuid
from contextlib import contextmanager
from datetime import datetime, time, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

SITE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
TIME_PATTERN = re.compile(r"^(?:[01]\d|2[0-3]):[0-5]\d$")
MAX_RULES_PER_SITE = 100
MAX_EVENTS_PER_SITE = 20_000
MAX_EVENT_HISTORY = 500
MAX_EVENT_AGE_DAYS = 365
MAX_EVALUATION_GAP_SECONDS = 300
MAX_HOLD_SECONDS = 3600
MIN_DEDUPE_SECONDS = 60
MAX_DEDUPE_SECONDS = 86_400
MAX_PENDING_NOTIFICATIONS = 100_000

METRICS = {
    "minimum_rssi_dbm": {"unit": "dBm", "minimum": -127.0, "maximum": 0.0, "description": "Weakest measured RSSI in the scan"},
    "network_count": {"unit": "networks", "minimum": 0.0, "maximum": 512.0, "description": "Number of access-point records in the scan"},
    "open_network_count": {"unit": "networks", "minimum": 0.0, "maximum": 512.0, "description": "Number of records explicitly reported as open"},
    "gateway_latency_ms": {"unit": "ms", "minimum": 0.0, "maximum": 600_000.0, "description": "Measured mean latency to the local default gateway"},
    "packet_loss_pct": {"unit": "%", "minimum": 0.0, "maximum": 100.0, "description": "Measured packet loss to the local default gateway"},
    "gateway_jitter_ms": {"unit": "ms", "minimum": 0.0, "maximum": 600_000.0, "description": "Measured mean absolute change between gateway ping samples"},
    "dns_resolution_ms": {"unit": "ms", "minimum": 0.0, "maximum": 600_000.0, "description": "Measured DNS resolution time when explicitly enabled"},
}
OPERATORS = {"gt", "gte", "lt", "lte"}
SEVERITIES = {"info", "warning", "critical"}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None = None) -> str:
    return (value or _utc_now()).astimezone(timezone.utc).isoformat(timespec="seconds")


def _site_id(value: object) -> str:
    if not isinstance(value, str) or not SITE_ID_PATTERN.fullmatch(value.strip()):
        raise ValueError("site_id must be a valid 1 to 128 character identifier")
    return value.strip()


def _timestamp(value: object | None) -> datetime:
    if value is None:
        return _utc_now()
    if not isinstance(value, str):
        raise ValueError("observed_at must be a timezone-aware ISO-8601 timestamp")
    try:
        result = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("observed_at must be a timezone-aware ISO-8601 timestamp") from error
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("observed_at must include a timezone offset")
    result = result.astimezone(timezone.utc)
    if result > _utc_now() + timedelta(minutes=5):
        raise ValueError("observed_at is too far in the future")
    return result


def _bounded_number(value: object, field: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be a finite number")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"{field} must be a finite number")
    if not minimum <= number <= maximum:
        raise ValueError(f"{field} must be between {minimum:g} and {maximum:g}")
    return number


def _parse_time(value: object, field: str) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str) or not TIME_PATTERN.fullmatch(value):
        raise ValueError(f"{field} must use HH:MM local time")
    return value


def _validate_rule(raw: object) -> dict:
    if not isinstance(raw, dict):
        raise ValueError("rule must be an object")
    name = raw.get("name")
    if not isinstance(name, str) or not name.strip() or len(name.strip()) > 128:
        raise ValueError("name must contain 1 to 128 characters")
    metric = raw.get("metric")
    if not isinstance(metric, str) or metric not in METRICS:
        raise ValueError(f"metric must be one of {sorted(METRICS)}")
    operator = raw.get("operator")
    if not isinstance(operator, str) or operator not in OPERATORS:
        raise ValueError(f"operator must be one of {sorted(OPERATORS)}")
    severity = raw.get("severity", "warning")
    if not isinstance(severity, str) or severity not in SEVERITIES:
        raise ValueError("severity must be info, warning or critical")
    enabled = raw.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ValueError("enabled must be a boolean")
    spec = METRICS[metric]
    threshold = _bounded_number(raw.get("threshold"), "threshold", spec["minimum"], spec["maximum"])
    recovery = raw.get("recovery_threshold")
    if recovery is not None:
        recovery = _bounded_number(recovery, "recovery_threshold", spec["minimum"], spec["maximum"])
        if operator in {"lt", "lte"} and recovery <= threshold:
            raise ValueError("recovery_threshold must be greater than threshold for less-than rules")
        if operator in {"gt", "gte"} and recovery >= threshold:
            raise ValueError("recovery_threshold must be less than threshold for greater-than rules")
    hold = raw.get("hold_for_seconds", 0)
    if isinstance(hold, bool) or not isinstance(hold, int) or not 0 <= hold <= MAX_HOLD_SECONDS:
        raise ValueError(f"hold_for_seconds must be an integer from 0 to {MAX_HOLD_SECONDS}")
    dedupe = raw.get("dedupe_window_seconds", 900)
    if isinstance(dedupe, bool) or not isinstance(dedupe, int) or not MIN_DEDUPE_SECONDS <= dedupe <= MAX_DEDUPE_SECONDS:
        raise ValueError(f"dedupe_window_seconds must be an integer from {MIN_DEDUPE_SECONDS} to {MAX_DEDUPE_SECONDS}")
    quiet_start = _parse_time(raw.get("quiet_start"), "quiet_start")
    quiet_end = _parse_time(raw.get("quiet_end"), "quiet_end")
    if (quiet_start is None) != (quiet_end is None):
        raise ValueError("quiet_start and quiet_end must both be set or both be empty")
    if quiet_start == quiet_end and quiet_start is not None:
        raise ValueError("quiet_start and quiet_end must be different")
    timezone_name = raw.get("timezone", "UTC")
    if not isinstance(timezone_name, str) or not timezone_name or len(timezone_name) > 64:
        raise ValueError("timezone must be a valid IANA time-zone name")
    try:
        ZoneInfo(timezone_name)
    except (ZoneInfoNotFoundError, ValueError) as error:
        raise ValueError("timezone must be a valid IANA time-zone name") from error
    return {
        "name": name.strip(),
        "metric": metric,
        "operator": operator,
        "threshold": threshold,
        "recovery_threshold": recovery,
        "severity": severity,
        "enabled": enabled,
        "hold_for_seconds": hold,
        "dedupe_window_seconds": dedupe,
        "quiet_start": quiet_start,
        "quiet_end": quiet_end,
        "timezone": timezone_name,
    }


def _matches(value: float, operator: str, threshold: float) -> bool:
    if operator == "gt":
        return value > threshold
    if operator == "gte":
        return value >= threshold
    if operator == "lt":
        return value < threshold
    return value <= threshold


def _is_quiet(rule: dict, instant: datetime) -> bool:
    start, end = rule.get("quiet_start"), rule.get("quiet_end")
    if not start or not end:
        return False
    local = instant.astimezone(ZoneInfo(rule["timezone"])).time().replace(tzinfo=None)
    start_time = time.fromisoformat(start)
    end_time = time.fromisoformat(end)
    if start_time < end_time:
        return start_time <= local < end_time
    return local >= start_time or local < end_time


class AlertRuleStore:
    """Persistent site alert rules, deduplicated incidents and acknowledgements."""

    def __init__(self, path: str | os.PathLike | None = None):
        override = os.getenv("WIFI_ANALYZER_ALERT_DB")
        if path is not None:
            self.path = Path(path).expanduser()
        elif override:
            self.path = Path(override).expanduser()
        elif sys.platform == "win32":
            root = Path(os.getenv("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
            self.path = root / "WiFiAnalyzerPro" / "alert-rules.sqlite3"
        elif sys.platform == "darwin":
            self.path = Path.home() / "Library" / "Application Support" / "WiFi Analyzer Pro" / "alert-rules.sqlite3"
        else:
            root = Path(os.getenv("XDG_STATE_HOME", str(Path.home() / ".local" / "state"))).expanduser()
            self.path = root / "wifi-analyzer-pro" / "alert-rules.sqlite3"

    @contextmanager
    def _db(self):
        parent_existed = self.path.parent.exists()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.path.is_symlink() or (self.path.exists() and not self.path.is_file()):
            raise ValueError("alert database path must be a regular non-symbolic-link file")
        if os.name != "nt":
            if not parent_existed:
                try:
                    os.chmod(self.path.parent, 0o700)
                except OSError:
                    pass
            try:
                fd = os.open(
                    str(self.path),
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                    0o600,
                )
            except FileExistsError:
                if self.path.is_symlink() or not self.path.is_file():
                    raise ValueError("alert database path must be a regular non-symbolic-link file")
                os.chmod(self.path, 0o600)
            else:
                os.close(fd)
        db = sqlite3.connect(str(self.path), timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout = 10000")
        db.execute("PRAGMA journal_mode = WAL")
        db.execute("""
            CREATE TABLE IF NOT EXISTS alert_rules (
                rule_id TEXT PRIMARY KEY,
                site_id TEXT NOT NULL,
                name TEXT NOT NULL,
                metric TEXT NOT NULL,
                operator TEXT NOT NULL,
                threshold REAL NOT NULL,
                recovery_threshold REAL,
                severity TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                hold_for_seconds INTEGER NOT NULL,
                dedupe_window_seconds INTEGER NOT NULL,
                quiet_start TEXT,
                quiet_end TEXT,
                timezone TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_alert_rules_site
            ON alert_rules(site_id, enabled, updated_at)
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS alert_rule_state (
                site_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                first_breach_at TEXT NOT NULL,
                last_value REAL NOT NULL,
                last_observed_at TEXT NOT NULL,
                current_event_id TEXT,
                PRIMARY KEY(site_id, rule_id)
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS alert_events (
                event_id TEXT PRIMARY KEY,
                site_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                metric TEXT NOT NULL,
                unit TEXT NOT NULL,
                severity TEXT NOT NULL,
                observed_value REAL NOT NULL,
                threshold REAL NOT NULL,
                message TEXT NOT NULL,
                status TEXT NOT NULL,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                resolved_at TEXT,
                acknowledged_at TEXT,
                acknowledged_by TEXT,
                occurrence_count INTEGER NOT NULL,
                dedupe_suppressed_count INTEGER NOT NULL,
                quiet_hours_active INTEGER NOT NULL
            )
        """)
        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_alert_events_site_status
            ON alert_events(site_id, status, last_seen_at DESC)
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS alert_notification_outbox (
                notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
                site_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                transition TEXT NOT NULL CHECK (transition IN ('opened', 'acknowledged', 'resolved')),
                event_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'queued', 'not_configured', 'suppressed')),
                attempts INTEGER NOT NULL DEFAULT 0,
                available_at TEXT NOT NULL,
                last_error_code TEXT,
                processed_at TEXT,
                UNIQUE (event_id, transition)
            )
        """)
        schema_row = db.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='alert_notification_outbox'"
        ).fetchone()
        if schema_row and "'suppressed'" not in (schema_row["sql"] or ""):
            # Upgrade pre-bridge databases without losing queued or processed transitions.
            db.execute("ALTER TABLE alert_notification_outbox RENAME TO alert_notification_outbox_legacy")
            db.execute("""
                CREATE TABLE alert_notification_outbox (
                    notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    site_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    transition TEXT NOT NULL CHECK (transition IN ('opened', 'acknowledged', 'resolved')),
                    event_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'queued', 'not_configured', 'suppressed')),
                    attempts INTEGER NOT NULL DEFAULT 0,
                    available_at TEXT NOT NULL,
                    last_error_code TEXT,
                    processed_at TEXT,
                    UNIQUE (event_id, transition)
                )
            """)
            db.execute("""
                INSERT INTO alert_notification_outbox (
                    notification_id, site_id, event_id, transition, event_json,
                    created_at, status, attempts, available_at, last_error_code, processed_at
                )
                SELECT notification_id, site_id, event_id, transition, event_json,
                    created_at, status, attempts, available_at, last_error_code, processed_at
                FROM alert_notification_outbox_legacy
            """)
            db.execute("DROP TABLE alert_notification_outbox_legacy")
        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_alert_notification_due
            ON alert_notification_outbox(status, available_at, notification_id)
        """)
        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_alert_notification_event
            ON alert_notification_outbox(event_id, notification_id DESC)
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
    def _rule_dict(row: sqlite3.Row) -> dict:
        result = dict(row)
        result["enabled"] = bool(result["enabled"])
        result["metric_description"] = METRICS[result["metric"]]["description"]
        result["unit"] = METRICS[result["metric"]]["unit"]
        return result

    @staticmethod
    def _event_dict(row: sqlite3.Row, delivery_status: str = "not_configured") -> dict:
        result = dict(row)
        result["quiet_hours_active"] = bool(result["quiet_hours_active"])
        result["delivery_status"] = delivery_status
        return result

    @staticmethod
    def _queue_notification(db: sqlite3.Connection, event_id: str, transition: str, occurred_at: str) -> None:
        if transition not in {"opened", "acknowledged", "resolved"}:
            raise ValueError("notification transition is invalid")
        row = db.execute(
            "SELECT * FROM alert_events WHERE event_id=?",
            (event_id,),
        ).fetchone()
        if row is None:
            raise RuntimeError("alert notification references a missing incident")
        event = AlertRuleStore._event_dict(row)
        event.pop("delivery_status", None)
        encoded = json.dumps(
            event, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
        )
        db.execute("""
            INSERT OR IGNORE INTO alert_notification_outbox (
                site_id, event_id, transition, event_json, created_at, available_at
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (row["site_id"], event_id, transition, encoded, occurred_at, occurred_at))
        pending = db.execute(
            "SELECT COUNT(*) FROM alert_notification_outbox WHERE status='pending'"
        ).fetchone()[0]
        if pending > MAX_PENDING_NOTIFICATIONS:
            raise RuntimeError("alert notification outbox is full; no new incident transition was discarded")

    def list_rules(self, site_id: str) -> list[dict]:
        site_id = _site_id(site_id)
        with self._db() as db:
            rows = db.execute(
                "SELECT * FROM alert_rules WHERE site_id = ? ORDER BY created_at, rule_id",
                (site_id,),
            ).fetchall()
        return [self._rule_dict(row) for row in rows]

    def list_events(self, site_id: str, *, limit: int = 100, status: str | None = None) -> list[dict]:
        site_id = _site_id(site_id)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_EVENT_HISTORY:
            raise ValueError(f"limit must be an integer from 1 to {MAX_EVENT_HISTORY}")
        if status not in {None, "active", "acknowledged", "resolved"}:
            raise ValueError("status must be active, acknowledged, resolved or omitted")
        with self._db() as db:
            if status:
                rows = db.execute(
                    "SELECT * FROM alert_events WHERE site_id = ? AND status = ? ORDER BY last_seen_at DESC LIMIT ?",
                    (site_id, status, limit),
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT * FROM alert_events WHERE site_id = ? ORDER BY last_seen_at DESC LIMIT ?",
                    (site_id, limit),
                ).fetchall()
            delivery_statuses = {}
            if rows:
                event_ids = [row["event_id"] for row in rows]
                placeholders = ",".join("?" for _ in event_ids)
                notifications = db.execute(
                    "SELECT event_id, status FROM alert_notification_outbox "
                    f"WHERE event_id IN ({placeholders}) ORDER BY notification_id",
                    event_ids,
                ).fetchall()
                delivery_statuses = {item["event_id"]: item["status"] for item in notifications}
        return [
            self._event_dict(row, delivery_statuses.get(row["event_id"], "not_configured"))
            for row in rows
        ]

    def save_rule(self, site_id: str, rule: dict, *, rule_id: str | None = None) -> dict:
        site_id = _site_id(site_id)
        clean = _validate_rule(rule)
        now = _iso()
        if rule_id is not None:
            try:
                rule_id = str(uuid.UUID(rule_id))
            except (TypeError, ValueError, AttributeError) as error:
                raise ValueError("rule_id must be a valid UUID") from error
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = None
            if rule_id:
                existing = db.execute(
                    "SELECT * FROM alert_rules WHERE site_id = ? AND rule_id = ?",
                    (site_id, rule_id),
                ).fetchone()
                if existing is None:
                    raise ValueError("alert rule was not found in this site")
            else:
                count = db.execute(
                    "SELECT COUNT(*) FROM alert_rules WHERE site_id = ?",
                    (site_id,),
                ).fetchone()[0]
                if count >= MAX_RULES_PER_SITE:
                    raise ValueError(f"a site may have no more than {MAX_RULES_PER_SITE} alert rules")
                rule_id = str(uuid.uuid4())
            created_at = existing["created_at"] if existing else now
            if existing:
                semantic_fields = (
                    "name", "metric", "operator", "threshold", "recovery_threshold", "severity",
                    "enabled", "hold_for_seconds", "dedupe_window_seconds",
                    "quiet_start", "quiet_end", "timezone",
                )
                changed = any(
                    existing[field] != (int(clean[field]) if field == "enabled" else clean[field])
                    for field in semantic_fields
                )
                if changed:
                    active_events = db.execute(
                        "SELECT event_id FROM alert_events WHERE site_id=? AND rule_id=? "
                        "AND status IN ('active','acknowledged')",
                        (site_id, rule_id),
                    ).fetchall()
                    db.execute("""
                        UPDATE alert_events SET status='resolved', resolved_at=?, last_seen_at=?
                        WHERE site_id=? AND rule_id=? AND status IN ('active','acknowledged')
                    """, (now, now, site_id, rule_id))
                    for event in active_events:
                        self._queue_notification(db, event["event_id"], "resolved", now)
                    db.execute(
                        "DELETE FROM alert_rule_state WHERE site_id=? AND rule_id=?",
                        (site_id, rule_id),
                    )
            db.execute("""
                INSERT INTO alert_rules (
                    rule_id, site_id, name, metric, operator, threshold, recovery_threshold,
                    severity, enabled, hold_for_seconds, dedupe_window_seconds,
                    quiet_start, quiet_end, timezone, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(rule_id) DO UPDATE SET
                    name=excluded.name, metric=excluded.metric, operator=excluded.operator,
                    threshold=excluded.threshold, recovery_threshold=excluded.recovery_threshold,
                    severity=excluded.severity, enabled=excluded.enabled,
                    hold_for_seconds=excluded.hold_for_seconds,
                    dedupe_window_seconds=excluded.dedupe_window_seconds,
                    quiet_start=excluded.quiet_start, quiet_end=excluded.quiet_end,
                    timezone=excluded.timezone, updated_at=excluded.updated_at
            """, (
                rule_id, site_id, clean["name"], clean["metric"], clean["operator"],
                clean["threshold"], clean["recovery_threshold"], clean["severity"],
                int(clean["enabled"]), clean["hold_for_seconds"], clean["dedupe_window_seconds"],
                clean["quiet_start"], clean["quiet_end"], clean["timezone"], created_at, now,
            ))
            if existing and not clean["enabled"]:
                # A semantic change above may already have closed these incidents.
                active_events = db.execute(
                    "SELECT event_id FROM alert_events WHERE site_id=? AND rule_id=? "
                    "AND status IN ('active','acknowledged')",
                    (site_id, rule_id),
                ).fetchall()
                db.execute("""
                    UPDATE alert_events SET status='resolved', resolved_at=?, last_seen_at=?
                    WHERE site_id=? AND rule_id=? AND status IN ('active','acknowledged')
                """, (now, now, site_id, rule_id))
                for event in active_events:
                    self._queue_notification(db, event["event_id"], "resolved", now)
                db.execute("DELETE FROM alert_rule_state WHERE site_id=? AND rule_id=?", (site_id, rule_id))
            row = db.execute("SELECT * FROM alert_rules WHERE rule_id=?", (rule_id,)).fetchone()
            return self._rule_dict(row)

    def delete_rule(self, site_id: str, rule_id: str) -> bool:
        site_id = _site_id(site_id)
        try:
            rule_id = str(uuid.UUID(rule_id))
        except (TypeError, ValueError, AttributeError) as error:
            raise ValueError("rule_id must be a valid UUID") from error
        now = _iso()
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            cursor = db.execute("DELETE FROM alert_rules WHERE site_id=? AND rule_id=?", (site_id, rule_id))
            if cursor.rowcount:
                active_events = db.execute(
                    "SELECT event_id FROM alert_events WHERE site_id=? AND rule_id=? "
                    "AND status IN ('active','acknowledged')",
                    (site_id, rule_id),
                ).fetchall()
                db.execute("""
                    UPDATE alert_events SET status='resolved', resolved_at=?, last_seen_at=?
                    WHERE site_id=? AND rule_id=? AND status IN ('active','acknowledged')
                """, (now, now, site_id, rule_id))
                for event in active_events:
                    self._queue_notification(db, event["event_id"], "resolved", now)
                db.execute("DELETE FROM alert_rule_state WHERE site_id=? AND rule_id=?", (site_id, rule_id))
            return cursor.rowcount == 1

    def acknowledge(self, site_id: str, event_id: str, actor: str) -> dict | None:
        site_id = _site_id(site_id)
        if not isinstance(actor, str) or not actor.strip() or len(actor) > 64:
            raise ValueError("actor must be a valid username")
        try:
            event_id = str(uuid.UUID(event_id))
        except (TypeError, ValueError, AttributeError) as error:
            raise ValueError("event_id must be a valid UUID") from error
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            acknowledged_at = _iso()
            cursor = db.execute("""
                UPDATE alert_events
                SET status='acknowledged', acknowledged_at=?, acknowledged_by=?
                WHERE site_id=? AND event_id=? AND status='active'
            """, (acknowledged_at, actor.strip(), site_id, event_id))
            row = db.execute(
                "SELECT * FROM alert_events WHERE site_id=? AND event_id=?",
                (site_id, event_id),
            ).fetchone()
            if row is None:
                return None
            if row["status"] == "resolved":
                raise ValueError("only active alerts can be acknowledged")
            if cursor.rowcount:
                self._queue_notification(db, event_id, "acknowledged", acknowledged_at)
            return self._event_dict(row, "pending" if cursor.rowcount else "not_configured")

    @staticmethod
    def _breached(rule: dict, value: float, *, active: bool) -> bool:
        if active and rule["recovery_threshold"] is not None:
            threshold = rule["recovery_threshold"]
            if rule["operator"] in {"lt", "lte"}:
                return value < threshold
            return value > threshold
        return _matches(value, rule["operator"], rule["threshold"])

    @staticmethod
    def _message(rule: dict, value: float) -> str:
        symbol = {"gt": ">", "gte": "≥", "lt": "<", "lte": "≤"}[rule["operator"]]
        unit = METRICS[rule["metric"]]["unit"]
        return f"{rule['name']}: measured {value:g} {unit} {symbol} threshold {rule['threshold']:g} {unit}"

    def evaluate(self, site_id: str, observations: dict, *, observed_at: object | None = None) -> dict:
        site_id = _site_id(site_id)
        if not isinstance(observations, dict):
            raise ValueError("observations must be an object")
        moment = _timestamp(observed_at)
        moment_text = _iso(moment)
        safe_values = {}
        for metric, raw_value in observations.items():
            if metric not in METRICS or raw_value is None:
                continue
            spec = METRICS[metric]
            safe_values[metric] = _bounded_number(
                raw_value, metric, spec["minimum"], spec["maximum"],
            )
        created, updated, resolved, pending, out_of_order = [], [], [], [], []
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            cutoff = _iso(moment - timedelta(days=MAX_EVENT_AGE_DAYS))
            db.execute(
                "DELETE FROM alert_events WHERE site_id=? AND status='resolved' AND last_seen_at < ?",
                (site_id, cutoff),
            )
            db.execute(
                "DELETE FROM alert_notification_outbox WHERE site_id=? "
                "AND status!='pending' AND created_at < ?",
                (site_id, cutoff),
            )
            rules = db.execute(
                "SELECT * FROM alert_rules WHERE site_id=? AND enabled=1",
                (site_id,),
            ).fetchall()
            for rule_row in rules:
                rule = self._rule_dict(rule_row)
                if rule["metric"] not in safe_values:
                    continue
                value = safe_values[rule["metric"]]
                state = db.execute(
                    "SELECT * FROM alert_rule_state WHERE site_id=? AND rule_id=?",
                    (site_id, rule["rule_id"]),
                ).fetchone()
                if state and moment < datetime.fromisoformat(state["last_observed_at"]):
                    out_of_order.append(rule["rule_id"])
                    continue
                current_event = None
                if state and state["current_event_id"]:
                    current_event = db.execute(
                        "SELECT * FROM alert_events WHERE site_id=? AND event_id=?",
                        (site_id, state["current_event_id"]),
                    ).fetchone()
                    if current_event and current_event["status"] == "resolved":
                        current_event = None
                is_breach = self._breached(rule, value, active=current_event is not None)
                if is_breach:
                    first = state["first_breach_at"] if state else moment_text
                    first_dt = datetime.fromisoformat(first)
                    if state and not current_event:
                        last_observed = datetime.fromisoformat(state["last_observed_at"])
                        if (moment - last_observed).total_seconds() > MAX_EVALUATION_GAP_SECONDS:
                            first = moment_text
                            first_dt = moment
                    if (moment - first_dt).total_seconds() < rule["hold_for_seconds"]:
                        db.execute("""
                            INSERT INTO alert_rule_state(site_id,rule_id,first_breach_at,last_value,last_observed_at,current_event_id)
                            VALUES(?,?,?,?,?,NULL)
                            ON CONFLICT(site_id,rule_id) DO UPDATE SET
                                last_value=excluded.last_value,last_observed_at=excluded.last_observed_at
                        """, (site_id, rule["rule_id"], first, value, moment_text))
                        pending.append(rule["rule_id"])
                        continue
                    quiet = _is_quiet(rule, moment)
                    if current_event:
                        last_seen = datetime.fromisoformat(current_event["last_seen_at"])
                        within_dedupe = (moment - last_seen).total_seconds() <= rule["dedupe_window_seconds"]
                        new_count = current_event["occurrence_count"] + 1
                        suppressed = current_event["dedupe_suppressed_count"] + (1 if within_dedupe else 0)
                        db.execute("""
                            UPDATE alert_events SET observed_value=?, message=?, last_seen_at=?,
                                occurrence_count=?, dedupe_suppressed_count=?,
                                quiet_hours_active=?
                            WHERE site_id=? AND event_id=?
                        """, (value, self._message(rule, value), moment_text, new_count, suppressed, int(quiet), site_id, current_event["event_id"]))
                        updated.append(current_event["event_id"])
                        event_id = current_event["event_id"]
                    else:
                        event_count = db.execute(
                            "SELECT COUNT(*) FROM alert_events WHERE site_id=?",
                            (site_id,),
                        ).fetchone()[0]
                        if event_count >= MAX_EVENTS_PER_SITE:
                            oldest_resolved = db.execute("""
                                SELECT event_id FROM alert_events
                                WHERE site_id=? AND status='resolved'
                                ORDER BY last_seen_at ASC LIMIT 1
                            """, (site_id,)).fetchone()
                            if oldest_resolved is None:
                                raise RuntimeError("site alert event limit reached; active incidents were not discarded")
                            db.execute(
                                "DELETE FROM alert_events WHERE site_id=? AND event_id=?",
                                (site_id, oldest_resolved["event_id"]),
                            )
                        event_id = str(uuid.uuid4())
                        db.execute("""
                            INSERT INTO alert_events (
                                event_id,site_id,rule_id,rule_name,metric,unit,severity,
                                observed_value,threshold,message,status,first_seen_at,last_seen_at,
                                resolved_at,acknowledged_at,acknowledged_by,occurrence_count,
                                dedupe_suppressed_count,quiet_hours_active
                            ) VALUES (?,?,?,?,?,?,?,?,?,?,'active',?,?,NULL,NULL,NULL,1,0,?)
                        """, (
                            event_id, site_id, rule["rule_id"], rule["name"], rule["metric"],
                            METRICS[rule["metric"]]["unit"], rule["severity"], value,
                            rule["threshold"], self._message(rule, value), moment_text,
                            moment_text, int(quiet),
                        ))
                        created.append(event_id)
                        self._queue_notification(db, event_id, "opened", moment_text)
                    db.execute("""
                        INSERT INTO alert_rule_state(site_id,rule_id,first_breach_at,last_value,last_observed_at,current_event_id)
                        VALUES(?,?,?,?,?,?)
                        ON CONFLICT(site_id,rule_id) DO UPDATE SET
                            last_value=excluded.last_value,last_observed_at=excluded.last_observed_at,
                            current_event_id=excluded.current_event_id
                    """, (site_id, rule["rule_id"], first, value, moment_text, event_id))
                elif current_event:
                    db.execute("""
                        UPDATE alert_events SET status='resolved',resolved_at=?,last_seen_at=?
                        WHERE site_id=? AND event_id=?
                    """, (moment_text, moment_text, site_id, current_event["event_id"]))
                    db.execute("DELETE FROM alert_rule_state WHERE site_id=? AND rule_id=?", (site_id, rule["rule_id"]))
                    self._queue_notification(db, current_event["event_id"], "resolved", moment_text)
                    resolved.append(current_event["event_id"])
                elif state:
                    db.execute("DELETE FROM alert_rule_state WHERE site_id=? AND rule_id=?", (site_id, rule["rule_id"]))
        return {
            "site_id": site_id,
            "created_event_ids": created,
            "updated_event_ids": updated,
            "resolved_event_ids": resolved,
            "pending_rule_ids": pending,
            "out_of_order_rule_ids": out_of_order,
            "evaluated_rule_count": len(rules),
            "measured_metric_count": len(safe_values),
        }

    def pending_notifications(self, *, limit: int = 100, now: object | None = None) -> list[dict]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1_000:
            raise ValueError("limit must be an integer from 1 to 1000")
        moment = _timestamp(now)
        with self._db() as db:
            rows = db.execute("""
                SELECT * FROM alert_notification_outbox
                WHERE status='pending' AND available_at <= ?
                ORDER BY notification_id LIMIT ?
            """, (_iso(moment), limit)).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["event"] = json.loads(item.pop("event_json"))
            result.append(item)
        return result

    def mark_notification_processed(self, notification_id: int, status: str) -> dict | None:
        if isinstance(notification_id, bool) or not isinstance(notification_id, int) or notification_id < 1:
            raise ValueError("notification_id must be a positive integer")
        if status not in {"queued", "not_configured", "suppressed"}:
            raise ValueError("notification status must be queued, not_configured or suppressed")
        processed_at = _iso()
        with self._db() as db:
            db.execute("""
                UPDATE alert_notification_outbox
                SET status=?, processed_at=?, last_error_code=NULL
                WHERE notification_id=? AND status='pending'
            """, (status, processed_at, notification_id))
            row = db.execute(
                "SELECT * FROM alert_notification_outbox WHERE notification_id=?",
                (notification_id,),
            ).fetchone()
        return dict(row) if row else None

    def retry_notification(
        self,
        notification_id: int,
        error_code: str,
        *,
        now: object | None = None,
    ) -> dict | None:
        if isinstance(notification_id, bool) or not isinstance(notification_id, int) or notification_id < 1:
            raise ValueError("notification_id must be a positive integer")
        if not isinstance(error_code, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", error_code):
            raise ValueError("error_code must be a lowercase operational code")
        moment = _timestamp(now)
        with self._db() as db:
            row = db.execute(
                "SELECT attempts FROM alert_notification_outbox "
                "WHERE notification_id=? AND status='pending'",
                (notification_id,),
            ).fetchone()
            if row is None:
                return None
            attempts = int(row["attempts"]) + 1
            delay = min(3_600, 5 * (2 ** min(attempts - 1, 9)))
            available_at = _iso(moment + timedelta(seconds=delay))
            db.execute("""
                UPDATE alert_notification_outbox
                SET attempts=?, available_at=?, last_error_code=?
                WHERE notification_id=? AND status='pending'
            """, (attempts, available_at, error_code, notification_id))
            updated = db.execute(
                "SELECT * FROM alert_notification_outbox WHERE notification_id=?",
                (notification_id,),
            ).fetchone()
        return dict(updated) if updated else None

    def site_ids(self, *, limit: int = 100) -> list[str]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("limit must be an integer between 1 and 100")
        with self._db() as db:
            rows = db.execute("""
                SELECT site_id FROM alert_rules
                UNION SELECT site_id FROM alert_events
                ORDER BY site_id LIMIT ?
            """, (limit,)).fetchall()
        return [row["site_id"] for row in rows]


def scan_observations(networks: list[dict]) -> dict:
    if not isinstance(networks, list) or len(networks) > 512:
        raise ValueError("networks must be a list containing no more than 512 records")
    rssi = []
    open_count = 0
    security_complete = bool(networks)
    for network in networks:
        if not isinstance(network, dict):
            security_complete = False
            continue
        value = network.get("rssi")
        if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value)) and -127 <= value <= 0:
            rssi.append(float(value))
        security = network.get("security", network.get("sec"))
        if not isinstance(security, str) or security.strip().lower() in {"", "unknown", "n/a", "not reported"}:
            security_complete = False
        elif security.strip().lower() == "open":
            open_count += 1
    # An empty result is ambiguous: current platform adapters can return [] for
    # either a valid empty scan or a command/adapter failure. Unknown security
    # metadata also cannot be counted as evidence of a secured network.
    return {
        "network_count": float(len(networks)) if networks else None,
        "open_network_count": float(open_count) if security_complete else None,
        "minimum_rssi_dbm": min(rssi) if rssi else None,
    }


def diagnostic_observations(diagnostics: dict) -> dict:
    if not isinstance(diagnostics, dict):
        return {}
    measured = diagnostics.get("gateway_probe_status") == "measured"
    dns_measured = diagnostics.get("dns_resolution_status") == "resolved"
    return {
        "gateway_latency_ms": diagnostics.get("latency_ms") if measured else None,
        "packet_loss_pct": diagnostics.get("packet_loss_pct") if measured else None,
        "gateway_jitter_ms": diagnostics.get("jitter_ms") if measured else None,
        "dns_resolution_ms": diagnostics.get("dns_resolution_ms") if dns_measured else None,
    }
