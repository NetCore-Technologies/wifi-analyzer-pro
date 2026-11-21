"""Durable, bounded and site-scoped storage for validated RF survey reports."""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import sys
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

SITE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
MAX_REPORTS_PER_SITE = 250
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_MEASUREMENTS = 20_000
MAX_ACCESS_POINTS = 256
DEFAULT_RETENTION_DAYS = 365


def _default_path() -> Path:
    override = os.getenv("WIFI_ANALYZER_RF_SURVEY_DB")
    if override:
        return Path(override).expanduser()
    if sys.platform == "win32":
        root = Path(os.getenv("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        return root / "WiFiAnalyzerPro" / "rf-survey-history.sqlite3"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "WiFi Analyzer Pro" / "rf-survey-history.sqlite3"
    root = Path(os.getenv("XDG_STATE_HOME", str(Path.home() / ".local" / "state"))).expanduser()
    return root / "wifi-analyzer-pro" / "rf-survey-history.sqlite3"


def _site_id(value: object) -> str:
    if not isinstance(value, str) or not SITE_ID_RE.fullmatch(value.strip()):
        raise ValueError("site_id must be a valid 1 to 128 character identifier")
    return value.strip()


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not ID_RE.fullmatch(value.strip()):
        raise ValueError(f"{field} must be a valid 1 to 64 character identifier")
    return value.strip()


def _label(value: object, fallback: str) -> str:
    if value is None or value == "":
        return fallback
    if not isinstance(value, str):
        raise ValueError("label must be a string")
    label = value.strip()
    if not label or len(label) > 128 or any(ord(char) < 32 or ord(char) == 127 for char in label):
        raise ValueError("label must contain 1 to 128 printable characters")
    return label


class RfSurveyHistoryStore:
    """Save immutable F203 results with bounded retention and integrity checks."""

    def __init__(
        self,
        path: str | os.PathLike | None = None,
        *,
        retention_days: int = DEFAULT_RETENTION_DAYS,
        max_reports_per_site: int = MAX_REPORTS_PER_SITE,
        max_report_bytes: int = MAX_REPORT_BYTES,
    ):
        if isinstance(retention_days, bool) or not isinstance(retention_days, int) or not 1 <= retention_days <= 3650:
            raise ValueError("retention_days must be an integer between 1 and 3650")
        if isinstance(max_reports_per_site, bool) or not isinstance(max_reports_per_site, int) or not 1 <= max_reports_per_site <= MAX_REPORTS_PER_SITE:
            raise ValueError(f"max_reports_per_site must be an integer between 1 and {MAX_REPORTS_PER_SITE}")
        if isinstance(max_report_bytes, bool) or not isinstance(max_report_bytes, int) or not 1024 <= max_report_bytes <= MAX_REPORT_BYTES:
            raise ValueError(f"max_report_bytes must be an integer between 1024 and {MAX_REPORT_BYTES}")
        self.path = Path(path).expanduser() if path else _default_path()
        self.retention_days = retention_days
        self.max_reports_per_site = max_reports_per_site
        self.max_report_bytes = max_report_bytes

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
        db.execute("PRAGMA busy_timeout = 10000")
        db.execute("PRAGMA journal_mode = WAL")
        db.execute("""
            CREATE TABLE IF NOT EXISTS rf_survey_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                survey_id TEXT NOT NULL UNIQUE,
                site_id TEXT NOT NULL,
                floorplan_id TEXT NOT NULL,
                floor_id TEXT NOT NULL,
                label TEXT NOT NULL,
                status TEXT NOT NULL,
                accepted_sample_count INTEGER NOT NULL,
                measurement_count INTEGER NOT NULL,
                access_point_count INTEGER NOT NULL,
                result_sha256 TEXT NOT NULL,
                result_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_rf_survey_site_created
            ON rf_survey_reports(site_id, created_at DESC, id DESC)
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
    def _summary(row: sqlite3.Row) -> dict:
        return {
            "survey_id": row["survey_id"],
            "site_id": row["site_id"],
            "floorplan_id": row["floorplan_id"],
            "floor_id": row["floor_id"],
            "label": row["label"],
            "status": row["status"],
            "accepted_sample_count": row["accepted_sample_count"],
            "measurement_count": row["measurement_count"],
            "access_point_count": row["access_point_count"],
            "result_sha256": row["result_sha256"],
            "created_at": row["created_at"],
        }

    def save(self, site_id: str, result: dict, *, label: str | None = None) -> dict:
        site_id = _site_id(site_id)
        if not isinstance(result, dict) or result.get("site_id") != site_id:
            raise ValueError("result site_id must match the requested site")
        floorplan_id = _identifier(result.get("floorplan_id"), "floorplan_id")
        floor_id = _identifier(result.get("floor_id"), "floor_id")
        status = result.get("status")
        if status not in {"analysed", "insufficient_fresh_survey_evidence"}:
            raise ValueError("result status is not a recognised F203 outcome")
        measurements = result.get("measurements")
        aps = result.get("access_points")
        if not isinstance(measurements, list) or len(measurements) > MAX_MEASUREMENTS:
            raise ValueError(f"measurements must contain no more than {MAX_MEASUREMENTS} records")
        if not isinstance(aps, list) or not 1 <= len(aps) <= MAX_ACCESS_POINTS:
            raise ValueError(f"access_points must contain 1 to {MAX_ACCESS_POINTS} records")
        sample_count = result.get("accepted_sample_count")
        if isinstance(sample_count, bool) or not isinstance(sample_count, int) or not 0 <= sample_count <= 8192:
            raise ValueError("accepted_sample_count is outside its supported range")
        try:
            encoded_text = json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError) as error:
            raise ValueError("result must contain only finite JSON-compatible values") from error
        encoded = encoded_text.encode("utf-8")
        if len(encoded) > self.max_report_bytes:
            raise ValueError(f"result exceeds the {self.max_report_bytes} byte report storage limit")
        created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        report_id = str(uuid.uuid4())
        digest = hashlib.sha256(encoded).hexdigest()
        report_label = _label(label, f"{floorplan_id} · {created_at.replace('T', ' ')}")
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            cutoff = (datetime.now(timezone.utc) - timedelta(days=self.retention_days)).isoformat(timespec="seconds")
            db.execute("DELETE FROM rf_survey_reports WHERE site_id = ? AND created_at < ?", (site_id, cutoff))
            count = db.execute("SELECT COUNT(*) FROM rf_survey_reports WHERE site_id = ?", (site_id,)).fetchone()[0]
            if count >= self.max_reports_per_site:
                raise ValueError(f"site already has {self.max_reports_per_site} saved RF survey reports; export or remove older reports before saving another")
            db.execute("""
                INSERT INTO rf_survey_reports (
                    survey_id, site_id, floorplan_id, floor_id, label, status,
                    accepted_sample_count, measurement_count, access_point_count,
                    result_sha256, result_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (report_id, site_id, floorplan_id, floor_id, report_label, status,
                  sample_count, len(measurements), len(aps), digest, encoded_text, created_at))
            row = db.execute("SELECT * FROM rf_survey_reports WHERE survey_id = ?", (report_id,)).fetchone()
            return self._summary(row)

    def list_for_site(self, site_id: str, *, limit: int = 50) -> list[dict]:
        site_id = _site_id(site_id)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("limit must be an integer between 1 and 100")
        cutoff = (datetime.now(timezone.utc) - timedelta(days=self.retention_days)).isoformat(timespec="seconds")
        with self._db() as db:
            rows = db.execute("""
                SELECT * FROM rf_survey_reports
                WHERE site_id = ? AND created_at >= ?
                ORDER BY created_at DESC, id DESC LIMIT ?
            """, (site_id, cutoff, limit)).fetchall()
        return [self._summary(row) for row in rows]

    def get(self, site_id: str, survey_id: str) -> dict | None:
        site_id = _site_id(site_id)
        try:
            survey_id = str(uuid.UUID(survey_id))
        except (TypeError, ValueError, AttributeError) as error:
            raise ValueError("survey_id must be a valid UUID") from error
        with self._db() as db:
            row = db.execute(
                "SELECT * FROM rf_survey_reports WHERE site_id = ? AND survey_id = ?",
                (site_id, survey_id),
            ).fetchone()
        if row is None:
            return None
        encoded = row["result_json"].encode("utf-8")
        if not hashlib.sha256(encoded).hexdigest() == row["result_sha256"]:
            raise RuntimeError("saved RF survey report integrity verification failed")
        return {"report": self._summary(row), "result": json.loads(row["result_json"])}

    def site_ids(self, *, limit: int = 100) -> list[str]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("limit must be an integer between 1 and 100")
        with self._db() as db:
            rows = db.execute(
                "SELECT DISTINCT site_id FROM rf_survey_reports ORDER BY site_id LIMIT ?",
                (limit,),
            ).fetchall()
        return [row["site_id"] for row in rows]
