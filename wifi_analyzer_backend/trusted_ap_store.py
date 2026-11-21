"""Persistent, site-scoped trusted Wi-Fi BSSID inventory."""
from __future__ import annotations

import os
import re
import sqlite3
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

SITE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
BSSID_PATTERN = re.compile(r"^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$")
MAX_SSIDS_PER_SITE = 256
MAX_BSSIDS_PER_SSID = 64
MAX_ENTRIES_PER_SITE = 4096


def _default_path() -> Path:
    override = os.getenv("WIFI_ANALYZER_TRUSTED_AP_DB")
    if override:
        return Path(override).expanduser()
    if sys.platform == "win32":
        root = Path(os.getenv("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        return root / "WiFiAnalyzerPro" / "trusted-access-points.sqlite3"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "WiFi Analyzer Pro" / "trusted-access-points.sqlite3"
    state_home = os.getenv("XDG_STATE_HOME")
    root = Path(state_home).expanduser() if state_home else Path.home() / ".local" / "state"
    return root / "wifi-analyzer-pro" / "trusted-access-points.sqlite3"


def _normalise_site_id(value: object) -> str:
    if not isinstance(value, str) or not SITE_ID_PATTERN.fullmatch(value.strip()):
        raise ValueError("site_id must be a valid 1 to 128 character identifier")
    return value.strip()


def _normalise_ssid(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("ssid must be a non-empty string")
    if len(value) > 32 or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError("ssid must contain 1 to 32 UTF-8 bytes and no control characters")
    if len(value.encode("utf-8")) > 32:
        raise ValueError("ssid must contain 1 to 32 UTF-8 bytes and no control characters")
    return value


def _normalise_bssid(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("bssid must be a MAC address")
    normalised = value.strip().replace("-", ":").upper()
    if not BSSID_PATTERN.fullmatch(normalised):
        raise ValueError("bssid must be a valid six-octet MAC address")
    first_octet = int(normalised[:2], 16)
    if first_octet & 1 or normalised == "00:00:00:00:00:00":
        raise ValueError("bssid must be a unicast access-point MAC address")
    return normalised


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class TrustedAccessPointStore:
    """Shared trusted BSSID baselines keyed by site and exact SSID."""

    def __init__(self, path: str | os.PathLike | None = None):
        self.path = Path(path).expanduser() if path is not None else _default_path()

    @contextmanager
    def _db(self):
        existed = self.path.parent.exists()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt" and not existed:
            try:
                os.chmod(self.path.parent, 0o700)
            except OSError:
                pass
        connection = sqlite3.connect(str(self.path), timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS trusted_access_points (
                site_id TEXT NOT NULL,
                ssid TEXT NOT NULL,
                bssid TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (site_id, ssid, bssid)
            )
        """)
        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_trusted_ap_site_ssid
            ON trusted_access_points(site_id, ssid, bssid)
        """)
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

    def list_for_site(self, site_id: str) -> list[dict]:
        site_id = _normalise_site_id(site_id)
        with self._db() as db:
            rows = db.execute("""
                SELECT site_id, ssid, bssid, created_at, updated_at
                FROM trusted_access_points
                WHERE site_id = ?
                ORDER BY ssid COLLATE BINARY, bssid
                LIMIT ?
            """, (site_id, MAX_ENTRIES_PER_SITE + 1)).fetchall()
        if len(rows) > MAX_ENTRIES_PER_SITE:
            raise RuntimeError("trusted AP inventory exceeds its configured safety limit")
        return [dict(row) for row in rows]

    def site_ids(self, *, limit: int = 100) -> list[str]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("limit must be an integer between 1 and 100")
        with self._db() as db:
            rows = db.execute(
                "SELECT DISTINCT site_id FROM trusted_access_points ORDER BY site_id LIMIT ?",
                (limit,),
            ).fetchall()
        return [row["site_id"] for row in rows]

    def add(self, site_id: str, ssid: str, bssid: str) -> dict:
        site_id = _normalise_site_id(site_id)
        ssid = _normalise_ssid(ssid)
        bssid = _normalise_bssid(bssid)
        now = _utc_now()
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("""
                SELECT site_id, ssid, bssid, created_at, updated_at
                FROM trusted_access_points WHERE site_id = ? AND ssid = ? AND bssid = ?
            """, (site_id, ssid, bssid)).fetchone()
            if existing is not None:
                return {"created": False, "record": dict(existing)}
            totals = db.execute("""
                SELECT COUNT(*) AS entry_count,
                       COUNT(DISTINCT ssid) AS ssid_count,
                       SUM(CASE WHEN ssid = ? THEN 1 ELSE 0 END) AS bssid_count
                FROM trusted_access_points WHERE site_id = ?
            """, (ssid, site_id)).fetchone()
            if totals["entry_count"] >= MAX_ENTRIES_PER_SITE:
                raise ValueError(f"a site may contain no more than {MAX_ENTRIES_PER_SITE} trusted BSSIDs")
            if totals["ssid_count"] >= MAX_SSIDS_PER_SITE and totals["bssid_count"] == 0:
                raise ValueError(f"a site may contain no more than {MAX_SSIDS_PER_SITE} trusted SSIDs")
            if (totals["bssid_count"] or 0) >= MAX_BSSIDS_PER_SSID:
                raise ValueError(f"an SSID may contain no more than {MAX_BSSIDS_PER_SSID} trusted BSSIDs")
            db.execute("""
                INSERT INTO trusted_access_points(site_id, ssid, bssid, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
            """, (site_id, ssid, bssid, now, now))
            return {
                "created": True,
                "record": {
                    "site_id": site_id,
                    "ssid": ssid,
                    "bssid": bssid,
                    "created_at": now,
                    "updated_at": now,
                },
            }

    def remove(self, site_id: str, ssid: str, bssid: str) -> bool:
        site_id = _normalise_site_id(site_id)
        ssid = _normalise_ssid(ssid)
        bssid = _normalise_bssid(bssid)
        with self._db() as db:
            cursor = db.execute(
                "DELETE FROM trusted_access_points WHERE site_id = ? AND ssid = ? AND bssid = ?",
                (site_id, ssid, bssid),
            )
            return cursor.rowcount == 1
