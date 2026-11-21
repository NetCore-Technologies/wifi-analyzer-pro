"""Immutable site-scoped storage for reviewed F206 regulatory dataset versions."""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import sys
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .feature_plugins.feature_207_radio_capability_regulatory_planner import (
    _fingerprint_dataset,
    _validate_dataset,
)

_SITE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
MAX_VERSIONS_PER_SITE = 100
MAX_DATASET_BYTES = 900 * 1024


def _default_path() -> Path:
    override = os.getenv("WIFI_ANALYZER_REGULATORY_DATASETS_DB")
    if override:
        return Path(override).expanduser()
    if sys.platform == "win32":
        base = Path(os.getenv("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        return base / "WiFiAnalyzerPro" / "regulatory-datasets.sqlite3"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "WiFi Analyzer Pro" / "regulatory-datasets.sqlite3"
    state = Path(os.getenv("XDG_STATE_HOME", str(Path.home() / ".local" / "state"))).expanduser()
    return state / "wifi-analyzer-pro" / "regulatory-datasets.sqlite3"


def _site(value: object) -> str:
    if not isinstance(value, str) or not _SITE.fullmatch(value.strip()):
        raise ValueError("site_id must be a valid 1 to 128 character identifier")
    return value.strip()


def _id(value: object, field: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value.strip()):
        raise ValueError(f"{field} must be a valid 1 to 128 character identifier")
    return value.strip()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _reason(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("reason must be a string")
    value = value.strip()
    if not 12 <= len(value) <= 512 or any(ord(char) < 32 and char != "\t" for char in value):
        raise ValueError("reason must contain 12 to 512 printable characters")
    return value


class RegulatoryDatasetStore:
    """Persist versioned F206 evidence with immutable content and revocation metadata."""

    def __init__(
        self,
        path: str | os.PathLike | None = None,
        *,
        max_versions_per_site: int = MAX_VERSIONS_PER_SITE,
        max_dataset_bytes: int = MAX_DATASET_BYTES,
    ):
        if isinstance(max_versions_per_site, bool) or not isinstance(max_versions_per_site, int) or not 1 <= max_versions_per_site <= MAX_VERSIONS_PER_SITE:
            raise ValueError(f"max_versions_per_site must be an integer from 1 to {MAX_VERSIONS_PER_SITE}")
        if isinstance(max_dataset_bytes, bool) or not isinstance(max_dataset_bytes, int) or not 1024 <= max_dataset_bytes <= MAX_DATASET_BYTES:
            raise ValueError(f"max_dataset_bytes must be an integer from 1024 to {MAX_DATASET_BYTES}")
        self.path = Path(path).expanduser() if path else _default_path()
        self.max_versions_per_site = max_versions_per_site
        self.max_dataset_bytes = max_dataset_bytes

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
            CREATE TABLE IF NOT EXISTS regulatory_datasets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dataset_ref TEXT NOT NULL UNIQUE,
                site_id TEXT NOT NULL,
                jurisdiction TEXT NOT NULL,
                dataset_id TEXT NOT NULL,
                version TEXT NOT NULL,
                fingerprint_sha256 TEXT NOT NULL,
                document_sha256 TEXT NOT NULL,
                dataset_json TEXT NOT NULL,
                acknowledgement_json TEXT NOT NULL,
                reviewer_id TEXT NOT NULL,
                review_reference TEXT NOT NULL,
                reviewed_at TEXT NOT NULL,
                effective_from TEXT NOT NULL,
                effective_to TEXT,
                retrieved_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                revoked_at TEXT,
                revoked_by TEXT,
                revocation_reason TEXT,
                UNIQUE(site_id, jurisdiction, dataset_id, version)
            )
        """)
        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_regulatory_datasets_site_created
            ON regulatory_datasets(site_id, created_at DESC, id DESC)
        """)
        db.execute("""
            CREATE TRIGGER IF NOT EXISTS regulatory_dataset_content_immutable
            BEFORE UPDATE OF site_id, jurisdiction, dataset_id, version,
                fingerprint_sha256, document_sha256, dataset_json,
                acknowledgement_json, reviewer_id, review_reference,
                reviewed_at, effective_from, effective_to, retrieved_at, created_at
            ON regulatory_datasets
            BEGIN
                SELECT RAISE(ABORT, 'regulatory dataset content is immutable');
            END
        """)
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()
            if os.name != "nt":
                for suffix in ("", "-wal", "-shm"):
                    file_path = Path(str(self.path) + suffix)
                    if file_path.exists():
                        try:
                            os.chmod(file_path, 0o600)
                        except OSError:
                            pass

    @staticmethod
    def _summary(row: sqlite3.Row) -> dict:
        return {
            "dataset_ref": row["dataset_ref"],
            "site_id": row["site_id"],
            "jurisdiction": row["jurisdiction"],
            "dataset_id": row["dataset_id"],
            "version": row["version"],
            "fingerprint_sha256": row["fingerprint_sha256"],
            "reviewer_id": row["reviewer_id"],
            "review_reference": row["review_reference"],
            "reviewed_at": row["reviewed_at"],
            "effective_from": row["effective_from"],
            "effective_to": row["effective_to"],
            "retrieved_at": row["retrieved_at"],
            "created_at": row["created_at"],
            "revoked_at": row["revoked_at"],
            "revoked_by": row["revoked_by"],
            "revocation_reason": row["revocation_reason"],
            "revoked": row["revoked_at"] is not None,
        }

    def save(self, site_id: str, dataset: dict, acknowledgement: dict) -> dict:
        site_id = _site(site_id)
        if not isinstance(dataset, dict) or not isinstance(acknowledgement, dict):
            raise ValueError("dataset and acknowledgement must be objects")
        if acknowledgement.get("acknowledged") is not True:
            raise ValueError("explicit acknowledged=true is required to retain a regulatory dataset")
        validated, fingerprint, _source_map = _validate_dataset(
            dataset, acknowledgement, datetime.now(timezone.utc),
        )
        try:
            dataset_text = json.dumps(validated, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
            acknowledgement_text = json.dumps(acknowledgement, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError) as error:
            raise ValueError("dataset and acknowledgement must contain finite JSON-compatible values") from error
        encoded = dataset_text.encode("utf-8")
        if len(encoded) > self.max_dataset_bytes:
            raise ValueError(f"normalized dataset exceeds the {self.max_dataset_bytes} byte storage limit")
        document_sha = hashlib.sha256(encoded).hexdigest()
        dataset_id = _id(validated.get("dataset_id"), "dataset_id")
        version = _id(validated.get("version"), "version")
        reviewer = _id(acknowledgement.get("reviewer_id"), "reviewer_id")
        review_reference = _id(acknowledgement.get("review_reference"), "review_reference")
        now = _now()
        dataset_ref = str(uuid.uuid4())

        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("""
                SELECT * FROM regulatory_datasets
                WHERE site_id = ? AND jurisdiction = ? AND dataset_id = ? AND version = ?
            """, (site_id, validated["jurisdiction"], dataset_id, version)).fetchone()
            if existing is not None:
                same = (
                    existing["fingerprint_sha256"] == fingerprint
                    and existing["reviewer_id"] == reviewer
                    and existing["review_reference"] == review_reference
                )
                if same:
                    return {**self._summary(existing), "created": False}
                raise ValueError("this dataset identity and version already exists with different content or review metadata")
            count = db.execute(
                "SELECT COUNT(*) FROM regulatory_datasets WHERE site_id = ?",
                (site_id,),
            ).fetchone()[0]
            if count >= self.max_versions_per_site:
                raise ValueError(f"site already has {self.max_versions_per_site} retained regulatory dataset versions")
            db.execute("""
                INSERT INTO regulatory_datasets (
                    dataset_ref, site_id, jurisdiction, dataset_id, version,
                    fingerprint_sha256, document_sha256, dataset_json,
                    acknowledgement_json, reviewer_id, review_reference,
                    reviewed_at, effective_from, effective_to, retrieved_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                dataset_ref, site_id, validated["jurisdiction"], dataset_id, version,
                fingerprint, document_sha, dataset_text, acknowledgement_text,
                reviewer, review_reference, acknowledgement["reviewed_at"],
                validated["effective_from"], validated["effective_to"],
                validated["retrieved_at"], now,
            ))
            row = db.execute(
                "SELECT * FROM regulatory_datasets WHERE dataset_ref = ?",
                (dataset_ref,),
            ).fetchone()
            return {**self._summary(row), "created": True}

    def list_for_site(self, site_id: str, *, limit: int = 50, include_revoked: bool = True) -> list[dict]:
        site_id = _site(site_id)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("limit must be an integer from 1 to 100")
        if not isinstance(include_revoked, bool):
            raise ValueError("include_revoked must be a boolean")
        query = "SELECT * FROM regulatory_datasets WHERE site_id = ?"
        args: list[object] = [site_id]
        if not include_revoked:
            query += " AND revoked_at IS NULL"
        query += " ORDER BY created_at DESC, id DESC LIMIT ?"
        args.append(limit)
        with self._db() as db:
            rows = db.execute(query, args).fetchall()
        return [self._summary(row) for row in rows]

    def get(self, site_id: str, dataset_ref: str) -> dict | None:
        site_id = _site(site_id)
        try:
            dataset_ref = str(uuid.UUID(dataset_ref))
        except (TypeError, ValueError, AttributeError) as error:
            raise ValueError("dataset_ref must be a valid UUID") from error
        with self._db() as db:
            row = db.execute(
                "SELECT * FROM regulatory_datasets WHERE site_id = ? AND dataset_ref = ?",
                (site_id, dataset_ref),
            ).fetchone()
        if row is None:
            return None
        encoded = row["dataset_json"].encode("utf-8")
        if hashlib.sha256(encoded).hexdigest() != row["document_sha256"]:
            raise RuntimeError("retained regulatory dataset integrity verification failed")
        dataset = json.loads(row["dataset_json"])
        acknowledgement = json.loads(row["acknowledgement_json"])
        if dataset.get("dataset_fingerprint_sha256") != row["fingerprint_sha256"]:
            raise RuntimeError("retained regulatory dataset fingerprint metadata is inconsistent")
        if _fingerprint_dataset(dataset) != row["fingerprint_sha256"]:
            raise RuntimeError("retained regulatory dataset canonical fingerprint verification failed")
        return {
            "record": self._summary(row),
            "dataset": dataset,
            "acknowledgement": acknowledgement,
        }

    def revoke(self, site_id: str, dataset_ref: str, *, actor: str, reason: str) -> bool:
        site_id = _site(site_id)
        actor = _id(actor, "actor")
        reason = _reason(reason)
        try:
            dataset_ref = str(uuid.UUID(dataset_ref))
        except (TypeError, ValueError, AttributeError) as error:
            raise ValueError("dataset_ref must be a valid UUID") from error
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT revoked_at FROM regulatory_datasets WHERE site_id = ? AND dataset_ref = ?",
                (site_id, dataset_ref),
            ).fetchone()
            if row is None or row["revoked_at"] is not None:
                return False
            db.execute("""
                UPDATE regulatory_datasets
                SET revoked_at = ?, revoked_by = ?, revocation_reason = ?
                WHERE site_id = ? AND dataset_ref = ? AND revoked_at IS NULL
            """, (_now(), actor, reason, site_id, dataset_ref))
            return db.execute("SELECT changes()").fetchone()[0] == 1

    def site_ids(self, *, limit: int = 100) -> list[str]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("limit must be an integer from 1 to 100")
        with self._db() as db:
            rows = db.execute(
                "SELECT DISTINCT site_id FROM regulatory_datasets ORDER BY site_id LIMIT ?",
                (limit,),
            ).fetchall()
        return [row["site_id"] for row in rows]
