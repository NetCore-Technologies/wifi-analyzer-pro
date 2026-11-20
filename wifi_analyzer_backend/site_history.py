"""Bounded, privacy-conscious SQLite persistence for site discovery snapshots."""
from __future__ import annotations

import json
import os
import sqlite3
import sys
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path


MAX_SNAPSHOT_BYTES = 512 * 1024
MAX_SNAPSHOTS_PER_SITE = 1000
DEFAULT_RETENTION_DAYS = 90
MAX_LIST_LIMIT = 100


class DuplicateSnapshotError(ValueError):
    """Raised when the same site/timestamp snapshot is submitted twice."""


def default_history_path() -> Path:
    override = os.getenv("WIFI_ANALYZER_HISTORY_DB")
    if override:
        return Path(override).expanduser()
    if sys.platform == "win32":
        root = Path(os.getenv("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        return root / "WiFiAnalyzerPro" / "site-history.sqlite3"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "WiFi Analyzer Pro" / "site-history.sqlite3"
    state_home = os.getenv("XDG_STATE_HOME")
    root = Path(state_home).expanduser() if state_home else Path.home() / ".local" / "state"
    return root / "wifi-analyzer-pro" / "site-history.sqlite3"


class SiteHistoryStore:
    """Store immutable, timestamped topology snapshots with per-site retention."""

    def __init__(
        self,
        path: str | os.PathLike | None = None,
        *,
        retention_days: int = DEFAULT_RETENTION_DAYS,
        max_per_site: int = MAX_SNAPSHOTS_PER_SITE,
    ):
        if isinstance(retention_days, bool) or not isinstance(retention_days, int) or not 1 <= retention_days <= 3650:
            raise ValueError("retention_days must be an integer between 1 and 3650")
        if isinstance(max_per_site, bool) or not isinstance(max_per_site, int) or not 1 <= max_per_site <= MAX_SNAPSHOTS_PER_SITE:
            raise ValueError(f"max_per_site must be an integer between 1 and {MAX_SNAPSHOTS_PER_SITE}")
        self.path = Path(path).expanduser() if path is not None else default_history_path()
        if not str(self.path):
            raise ValueError("A history database path is required")
        self.retention_days = retention_days
        self.max_per_site = max_per_site

    @contextmanager
    def _connection(self):
        parent = self.path.parent
        parent_existed = parent.exists()
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt" and not parent_existed:
            try:
                os.chmod(parent, 0o700)
            except OSError:
                pass
        connection = sqlite3.connect(str(self.path), timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS site_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site_id TEXT NOT NULL,
                captured_at TEXT NOT NULL,
                received_at TEXT NOT NULL,
                access_point_count INTEGER NOT NULL,
                link_count INTEGER NOT NULL,
                payload TEXT NOT NULL,
                UNIQUE(site_id, captured_at)
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_site_snapshots_site_id_id "
            "ON site_snapshots(site_id, id DESC)"
        )
        try:
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
            if os.name != "nt" and self.path.exists():
                try:
                    os.chmod(self.path, 0o600)
                except OSError:
                    pass

    def record(self, snapshot: dict) -> dict:
        if not isinstance(snapshot, dict):
            raise ValueError("snapshot must be an object")
        site_id = snapshot.get("site_id")
        captured_at = snapshot.get("captured_at")
        access_points = snapshot.get("access_points")
        links = snapshot.get("links")
        if not isinstance(site_id, str) or not site_id.strip() or len(site_id) > 128:
            raise ValueError("snapshot.site_id must contain 1 to 128 characters")
        if not isinstance(captured_at, str) or not captured_at.strip():
            raise ValueError("snapshot.captured_at must be an ISO-8601 timestamp")
        if not isinstance(access_points, list) or not isinstance(links, list):
            raise ValueError("snapshot access_points and links must be lists")

        content = {
            "site_id": site_id,
            "captured_at": captured_at,
            "access_points": access_points,
            "links": links,
        }
        try:
            encoded = json.dumps(content, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False)
        except (TypeError, ValueError) as error:
            raise ValueError("snapshot must contain JSON-compatible finite values") from error
        if len(encoded.encode("utf-8")) > MAX_SNAPSHOT_BYTES:
            raise ValueError(f"snapshot exceeds the {MAX_SNAPSHOT_BYTES}-byte storage limit")

        now = datetime.now(timezone.utc)
        received_at = now.isoformat()
        cutoff = (now - timedelta(days=self.retention_days)).isoformat()
        if captured_at < cutoff:
            raise ValueError("captured_at is older than the configured history retention window")

        try:
            with self._connection() as connection:
                cursor = connection.execute(
                    """
                    INSERT INTO site_snapshots
                        (site_id, captured_at, received_at, access_point_count, link_count, payload)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (site_id, captured_at, received_at, len(access_points), len(links), encoded),
                )
                snapshot_id = cursor.lastrowid
                connection.execute(
                    "DELETE FROM site_snapshots WHERE site_id = ? AND captured_at < ?",
                    (site_id, cutoff),
                )
                connection.execute(
                    """
                    DELETE FROM site_snapshots
                    WHERE site_id = ? AND id NOT IN (
                        SELECT id FROM site_snapshots
                        WHERE site_id = ?
                        ORDER BY captured_at DESC, id DESC
                        LIMIT ?
                    )
                    """,
                    (site_id, site_id, self.max_per_site),
                )
        except sqlite3.IntegrityError as error:
            if "UNIQUE constraint failed" in str(error):
                raise DuplicateSnapshotError("A snapshot for this site and timestamp already exists") from error
            raise

        return {
            "id": snapshot_id,
            "site_id": site_id,
            "captured_at": captured_at,
            "received_at": received_at,
            "access_point_count": len(access_points),
            "link_count": len(links),
        }

    def list(
        self,
        *,
        site_id: str | None = None,
        limit: int = 50,
        before_id: int | None = None,
        site_ids: list[str] | None = None,
    ) -> list[dict]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LIST_LIMIT:
            raise ValueError(f"limit must be an integer between 1 and {MAX_LIST_LIMIT}")
        if site_id is not None and (not isinstance(site_id, str) or not site_id.strip() or len(site_id) > 128):
            raise ValueError("site_id must contain 1 to 128 characters")
        if before_id is not None and (isinstance(before_id, bool) or not isinstance(before_id, int) or before_id < 1):
            raise ValueError("before_id must be a positive integer")
        if site_id is not None and site_ids is not None:
            raise ValueError("site_id and site_ids cannot be supplied together")
        if site_ids is not None:
            if not isinstance(site_ids, list) or len(site_ids) > 100:
                raise ValueError("site_ids must contain no more than 100 site identifiers")
            cleaned = []
            for item in site_ids:
                if not isinstance(item, str) or not item.strip() or len(item) > 128:
                    raise ValueError("each site_id must contain 1 to 128 characters")
                cleaned.append(item.strip())
            if len(cleaned) != len(set(cleaned)):
                raise ValueError("site_ids must be unique")
            site_ids = cleaned
            if not site_ids:
                return []

        clauses = []
        values = []
        if site_id is not None:
            clauses.append("site_id = ?")
            values.append(site_id)
        elif site_ids is not None:
            placeholders = ", ".join("?" for _ in site_ids)
            clauses.append(f"site_id IN ({placeholders})")
            values.extend(site_ids)
        if before_id is not None:
            clauses.append("id < ?")
            values.append(before_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._connection() as connection:
            rows = connection.execute(
                f"""
                SELECT id, site_id, captured_at, received_at, access_point_count, link_count
                FROM site_snapshots {where}
                ORDER BY id DESC LIMIT ?
                """,
                (*values, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def site_ids(self, *, limit: int = 100) -> list[str]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("site limit must be an integer between 1 and 100")
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT DISTINCT site_id FROM site_snapshots ORDER BY site_id LIMIT ?",
                (limit,),
            ).fetchall()
        return [row["site_id"] for row in rows]

    def latest_pairs(self, site_ids: list[str]) -> list[dict]:
        if not isinstance(site_ids, list) or len(site_ids) > 20:
            raise ValueError("site_ids must be a list containing no more than 20 sites")
        cleaned = []
        seen = set()
        for site_id in site_ids:
            if not isinstance(site_id, str) or not site_id.strip() or len(site_id) > 128:
                raise ValueError("each site_id must contain 1 to 128 characters")
            site_id = site_id.strip()
            if site_id in seen:
                raise ValueError("site_ids must be unique")
            seen.add(site_id)
            cleaned.append(site_id)
        comparisons = []
        with self._connection() as connection:
            for site_id in sorted(cleaned):
                rows = connection.execute(
                    """
                    SELECT id, site_id, captured_at, received_at,
                           access_point_count, link_count, payload
                    FROM site_snapshots WHERE site_id = ?
                    ORDER BY captured_at DESC, id DESC LIMIT 2
                    """,
                    (site_id,),
                ).fetchall()
                if not rows:
                    continue
                def unpack(row):
                    return {
                        "snapshot_id": row["id"],
                        "captured_at": row["captured_at"],
                        "received_at": row["received_at"],
                        "snapshot": json.loads(row["payload"]),
                    }
                current = unpack(rows[0])
                previous = unpack(rows[1]) if len(rows) > 1 else None
                comparisons.append({
                    "site_id": site_id,
                    "previous": previous,
                    "current": current,
                })
        return comparisons
    def get(self, snapshot_id: int) -> dict | None:
        if isinstance(snapshot_id, bool) or not isinstance(snapshot_id, int) or snapshot_id < 1:
            raise ValueError("snapshot_id must be a positive integer")
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT id, site_id, captured_at, received_at, access_point_count, link_count, payload
                FROM site_snapshots WHERE id = ?
                """,
                (snapshot_id,),
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["snapshot"] = json.loads(result.pop("payload"))
        return result
