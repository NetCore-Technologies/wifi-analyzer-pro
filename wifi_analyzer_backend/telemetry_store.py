"""Bounded, site-scoped SQLite rollups for Wi-Fi scan and diagnostic telemetry.

Only aggregate measurements are persisted: raw SSIDs, BSSIDs, client identifiers,
and request payloads are deliberately excluded. Repeated scans are combined into
one UTC-minute bucket so high-frequency polling has a bounded storage footprint.
"""
from __future__ import annotations

import math
import os
import re
import sqlite3
import sys
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

MAX_SITE_ID_LENGTH = 128
MAX_NETWORKS_PER_SCAN = 512
MAX_RETENTION_DAYS = 365
DEFAULT_RETENTION_DAYS = 90
MAX_ROLLUPS_PER_SITE = 130_000
MAX_HISTORY_LIMIT = 5_000
SITE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
BANDS = ("2.4GHz", "5GHz", "6GHz")


def default_telemetry_path() -> Path:
    override = os.getenv("WIFI_ANALYZER_TELEMETRY_DB")
    if override:
        return Path(override).expanduser()
    if sys.platform == "win32":
        root = Path(os.getenv("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        return root / "WiFiAnalyzerPro" / "telemetry-history.sqlite3"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "WiFi Analyzer Pro" / "telemetry-history.sqlite3"
    state_home = os.getenv("XDG_STATE_HOME")
    root = Path(state_home).expanduser() if state_home else Path.home() / ".local" / "state"
    return root / "wifi-analyzer-pro" / "telemetry-history.sqlite3"


def _site_id(value: object) -> str:
    if not isinstance(value, str) or not SITE_ID_PATTERN.fullmatch(value.strip()):
        raise ValueError("site_id must be a valid 1 to 128 character identifier")
    return value.strip()


def _timestamp(value: object | None) -> datetime:
    if value is None:
        result = datetime.now(timezone.utc)
    elif isinstance(value, bool):
        raise ValueError("sampled_at must be a finite Unix timestamp or timezone-aware datetime")
    elif isinstance(value, (int, float)):
        if not math.isfinite(float(value)):
            raise ValueError("sampled_at must be finite")
        try:
            result = datetime.fromtimestamp(float(value), timezone.utc)
        except (OverflowError, OSError, ValueError) as error:
            raise ValueError("sampled_at is outside the supported range") from error
    elif isinstance(value, datetime):
        result = value
    else:
        raise ValueError("sampled_at must be a finite Unix timestamp or timezone-aware datetime")
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError("sampled_at must include a timezone")
    result = result.astimezone(timezone.utc)
    now = datetime.now(timezone.utc)
    if result > now + timedelta(minutes=5):
        raise ValueError("sampled_at is too far in the future")
    if result < datetime(2000, 1, 1, tzinfo=timezone.utc):
        raise ValueError("sampled_at is outside the supported range")
    return result


def _measurement(value: object, minimum: float, maximum: float) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if not math.isfinite(number) or not minimum <= number <= maximum:
        return None
    return number


def _bucket(value: datetime) -> str:
    return value.replace(second=0, microsecond=0).isoformat(timespec="seconds")


def _merge_min(previous, current):
    if current is None:
        return previous
    return current if previous is None else min(previous, current)


def _merge_max(previous, current):
    if current is None:
        return previous
    return current if previous is None else max(previous, current)


class WiFiTelemetryStore:
    """Persist minute-level site aggregates with explicit retention bounds."""

    def __init__(
        self,
        path: str | os.PathLike | None = None,
        *,
        retention_days: int = DEFAULT_RETENTION_DAYS,
        max_rollups_per_site: int = MAX_ROLLUPS_PER_SITE,
    ):
        if isinstance(retention_days, bool) or not isinstance(retention_days, int) or not 1 <= retention_days <= MAX_RETENTION_DAYS:
            raise ValueError(f"retention_days must be an integer between 1 and {MAX_RETENTION_DAYS}")
        if isinstance(max_rollups_per_site, bool) or not isinstance(max_rollups_per_site, int) or not 1 <= max_rollups_per_site <= MAX_ROLLUPS_PER_SITE:
            raise ValueError(f"max_rollups_per_site must be an integer between 1 and {MAX_ROLLUPS_PER_SITE}")
        self.path = Path(path).expanduser() if path is not None else default_telemetry_path()
        self.retention_days = retention_days
        self.max_rollups_per_site = max_rollups_per_site

    @contextmanager
    def _connection(self):
        parent = self.path.parent
        existed = parent.exists()
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt" and not existed:
            try:
                os.chmod(parent, 0o700)
            except OSError:
                pass
        db = sqlite3.connect(str(self.path), timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout = 10000")
        db.execute("PRAGMA journal_mode = WAL")
        db.execute("""
            CREATE TABLE IF NOT EXISTS wifi_telemetry_minute (
                site_id TEXT NOT NULL,
                minute_utc TEXT NOT NULL,
                scan_count INTEGER NOT NULL DEFAULT 0,
                network_count_sum INTEGER NOT NULL DEFAULT 0,
                network_count_min INTEGER,
                network_count_max INTEGER,
                open_network_count_sum INTEGER NOT NULL DEFAULT 0,
                band_24_count_sum INTEGER NOT NULL DEFAULT 0,
                band_5_count_sum INTEGER NOT NULL DEFAULT 0,
                band_6_count_sum INTEGER NOT NULL DEFAULT 0,
                rssi_sum REAL NOT NULL DEFAULT 0,
                rssi_count INTEGER NOT NULL DEFAULT 0,
                rssi_min REAL,
                rssi_max REAL,
                diagnostics_count INTEGER NOT NULL DEFAULT 0,
                latency_sum REAL NOT NULL DEFAULT 0,
                latency_count INTEGER NOT NULL DEFAULT 0,
                latency_min REAL,
                latency_max REAL,
                jitter_sum REAL NOT NULL DEFAULT 0,
                jitter_count INTEGER NOT NULL DEFAULT 0,
                jitter_min REAL,
                jitter_max REAL,
                packet_loss_sum REAL NOT NULL DEFAULT 0,
                packet_loss_count INTEGER NOT NULL DEFAULT 0,
                packet_loss_min REAL,
                packet_loss_max REAL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (site_id, minute_utc)
            )
        """)
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_wifi_telemetry_site_minute "
            "ON wifi_telemetry_minute(site_id, minute_utc DESC)"
        )
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

    def _prune(self, db, site_id: str, now: datetime) -> None:
        cutoff = (now - timedelta(days=self.retention_days)).isoformat(timespec="seconds")
        db.execute(
            "DELETE FROM wifi_telemetry_minute WHERE site_id = ? AND minute_utc < ?",
            (site_id, cutoff),
        )
        db.execute("""
            DELETE FROM wifi_telemetry_minute
            WHERE site_id = ? AND minute_utc NOT IN (
                SELECT minute_utc FROM wifi_telemetry_minute
                WHERE site_id = ?
                ORDER BY minute_utc DESC LIMIT ?
            )
        """, (site_id, site_id, self.max_rollups_per_site))

    def record_scan(
        self,
        site_id: str,
        networks: list[dict],
        *,
        sampled_at: object | None = None,
    ) -> dict:
        site_id = _site_id(site_id)
        if not isinstance(networks, list) or len(networks) > MAX_NETWORKS_PER_SCAN:
            raise ValueError(f"networks must be a list containing no more than {MAX_NETWORKS_PER_SCAN} records")
        if any(not isinstance(network, dict) for network in networks):
            raise ValueError("each network observation must be an object")
        moment = _timestamp(sampled_at)
        if moment < datetime.now(timezone.utc) - timedelta(days=self.retention_days):
            raise ValueError("sampled_at is outside the configured telemetry retention window")
        minute = _bucket(moment)
        now_text = datetime.now(timezone.utc).isoformat(timespec="seconds")
        rssi_values = [
            value for network in networks
            if (value := _measurement(network.get("rssi"), -127, 0)) is not None
        ]
        open_count = sum(network.get("security") == "Open" for network in networks)
        band_counts = {
            band: sum(network.get("band") == band for network in networks)
            for band in BANDS
        }
        rssi_sum = sum(rssi_values)
        rssi_count = len(rssi_values)
        rssi_min = min(rssi_values) if rssi_values else None
        rssi_max = max(rssi_values) if rssi_values else None

        with self._connection() as db:
            db.execute("""
                INSERT INTO wifi_telemetry_minute (
                    site_id, minute_utc, scan_count, network_count_sum,
                    network_count_min, network_count_max, open_network_count_sum,
                    band_24_count_sum, band_5_count_sum, band_6_count_sum,
                    rssi_sum, rssi_count, rssi_min, rssi_max, updated_at
                ) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(site_id, minute_utc) DO UPDATE SET
                    scan_count = scan_count + 1,
                    network_count_sum = network_count_sum + excluded.network_count_sum,
                    network_count_min = MIN(network_count_min, excluded.network_count_min),
                    network_count_max = MAX(network_count_max, excluded.network_count_max),
                    open_network_count_sum = open_network_count_sum + excluded.open_network_count_sum,
                    band_24_count_sum = band_24_count_sum + excluded.band_24_count_sum,
                    band_5_count_sum = band_5_count_sum + excluded.band_5_count_sum,
                    band_6_count_sum = band_6_count_sum + excluded.band_6_count_sum,
                    rssi_sum = rssi_sum + excluded.rssi_sum,
                    rssi_count = rssi_count + excluded.rssi_count,
                    rssi_min = CASE WHEN excluded.rssi_min IS NULL THEN rssi_min WHEN rssi_min IS NULL THEN excluded.rssi_min ELSE MIN(rssi_min, excluded.rssi_min) END,
                    rssi_max = CASE WHEN excluded.rssi_max IS NULL THEN rssi_max WHEN rssi_max IS NULL THEN excluded.rssi_max ELSE MAX(rssi_max, excluded.rssi_max) END,
                    updated_at = excluded.updated_at
            """, (
                site_id, minute, len(networks), len(networks), len(networks),
                open_count, band_counts["2.4GHz"], band_counts["5GHz"],
                band_counts["6GHz"], rssi_sum, rssi_count, rssi_min,
                rssi_max, now_text,
            ))
            self._prune(db, site_id, moment)

        return {
            "site_id": site_id,
            "minute_utc": minute,
            "network_count": len(networks),
            "measured_rssi_count": rssi_count,
        }

    def record_diagnostics(
        self,
        site_id: str,
        diagnostics: dict,
        *,
        sampled_at: object | None = None,
    ) -> dict | None:
        site_id = _site_id(site_id)
        if not isinstance(diagnostics, dict):
            raise ValueError("diagnostics must be an object")
        moment = _timestamp(sampled_at)
        if moment < datetime.now(timezone.utc) - timedelta(days=self.retention_days):
            raise ValueError("sampled_at is outside the configured telemetry retention window")
        minute = _bucket(moment)
        metrics = {
            "latency": _measurement(diagnostics.get("latency_ms"), 0, 600000),
            "jitter": _measurement(diagnostics.get("jitter_ms"), 0, 600000),
            "packet_loss": _measurement(diagnostics.get("packet_loss_pct"), 0, 100),
        }
        if all(value is None for value in metrics.values()):
            return None
        now_text = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._connection() as db:
            db.execute("""
                INSERT INTO wifi_telemetry_minute (
                    site_id, minute_utc, diagnostics_count,
                    latency_sum, latency_count, latency_min, latency_max,
                    jitter_sum, jitter_count, jitter_min, jitter_max,
                    packet_loss_sum, packet_loss_count, packet_loss_min, packet_loss_max,
                    updated_at
                ) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(site_id, minute_utc) DO UPDATE SET
                    diagnostics_count = diagnostics_count + 1,
                    latency_sum = latency_sum + excluded.latency_sum,
                    latency_count = latency_count + excluded.latency_count,
                    latency_min = CASE WHEN excluded.latency_min IS NULL THEN latency_min WHEN latency_min IS NULL THEN excluded.latency_min ELSE MIN(latency_min, excluded.latency_min) END,
                    latency_max = CASE WHEN excluded.latency_max IS NULL THEN latency_max WHEN latency_max IS NULL THEN excluded.latency_max ELSE MAX(latency_max, excluded.latency_max) END,
                    jitter_sum = jitter_sum + excluded.jitter_sum,
                    jitter_count = jitter_count + excluded.jitter_count,
                    jitter_min = CASE WHEN excluded.jitter_min IS NULL THEN jitter_min WHEN jitter_min IS NULL THEN excluded.jitter_min ELSE MIN(jitter_min, excluded.jitter_min) END,
                    jitter_max = CASE WHEN excluded.jitter_max IS NULL THEN jitter_max WHEN jitter_max IS NULL THEN excluded.jitter_max ELSE MAX(jitter_max, excluded.jitter_max) END,
                    packet_loss_sum = packet_loss_sum + excluded.packet_loss_sum,
                    packet_loss_count = packet_loss_count + excluded.packet_loss_count,
                    packet_loss_min = CASE WHEN excluded.packet_loss_min IS NULL THEN packet_loss_min WHEN packet_loss_min IS NULL THEN excluded.packet_loss_min ELSE MIN(packet_loss_min, excluded.packet_loss_min) END,
                    packet_loss_max = CASE WHEN excluded.packet_loss_max IS NULL THEN packet_loss_max WHEN packet_loss_max IS NULL THEN excluded.packet_loss_max ELSE MAX(packet_loss_max, excluded.packet_loss_max) END,
                    updated_at = excluded.updated_at
            """, (
                site_id, minute,
                metrics["latency"] if metrics["latency"] is not None else 0,
                int(metrics["latency"] is not None), metrics["latency"], metrics["latency"],
                metrics["jitter"] if metrics["jitter"] is not None else 0,
                int(metrics["jitter"] is not None), metrics["jitter"], metrics["jitter"],
                metrics["packet_loss"] if metrics["packet_loss"] is not None else 0,
                int(metrics["packet_loss"] is not None), metrics["packet_loss"], metrics["packet_loss"],
                now_text,
            ))
            self._prune(db, site_id, moment)
        return {"site_id": site_id, "minute_utc": minute, "measured_metrics": sorted(key for key, value in metrics.items() if value is not None)}

    def site_ids(self, *, limit: int = 100) -> list[str]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("limit must be an integer between 1 and 100")
        with self._connection() as db:
            rows = db.execute(
                "SELECT DISTINCT site_id FROM wifi_telemetry_minute ORDER BY site_id LIMIT ?",
                (limit,),
            ).fetchall()
        return [row["site_id"] for row in rows]

    def history(
        self,
        *,
        site_ids: list[str] | None = None,
        days: int = 7,
        limit: int = 5_000,
    ) -> list[dict]:
        if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= self.retention_days:
            raise ValueError(f"days must be an integer between 1 and {self.retention_days}")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_HISTORY_LIMIT:
            raise ValueError(f"limit must be an integer between 1 and {MAX_HISTORY_LIMIT}")
        if site_ids is not None:
            if not isinstance(site_ids, list) or len(site_ids) > 100:
                raise ValueError("site_ids must contain no more than 100 sites")
            site_ids = [_site_id(value) for value in site_ids]
            if len(site_ids) != len(set(site_ids)):
                raise ValueError("site_ids must be unique")
            if not site_ids:
                return []
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
        clauses = ["minute_utc >= ?"]
        values: list[object] = [cutoff]
        if site_ids is not None:
            clauses.append("site_id IN (" + ", ".join("?" for _ in site_ids) + ")")
            values.extend(site_ids)
        query = """
            SELECT site_id, minute_utc, scan_count,
                network_count_sum, network_count_min, network_count_max,
                open_network_count_sum, band_24_count_sum, band_5_count_sum, band_6_count_sum,
                rssi_sum, rssi_count, rssi_min, rssi_max,
                diagnostics_count, latency_sum, latency_count, latency_min, latency_max,
                jitter_sum, jitter_count, jitter_min, jitter_max,
                packet_loss_sum, packet_loss_count, packet_loss_min, packet_loss_max,
                updated_at
            FROM wifi_telemetry_minute
            WHERE """ + " AND ".join(clauses) + """
            ORDER BY minute_utc ASC, site_id ASC
            LIMIT ?
        """
        with self._connection() as db:
            rows = db.execute(query, (*values, limit)).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            scan_count = item["scan_count"]
            rssi_count = item["rssi_count"]
            diagnostic_count = item["diagnostics_count"]
            item.update({
                "average_network_count": item["network_count_sum"] / scan_count if scan_count else None,
                "average_open_network_count": item["open_network_count_sum"] / scan_count if scan_count else None,
                "average_2_4ghz_network_count": item["band_24_count_sum"] / scan_count if scan_count else None,
                "average_5ghz_network_count": item["band_5_count_sum"] / scan_count if scan_count else None,
                "average_6ghz_network_count": item["band_6_count_sum"] / scan_count if scan_count else None,
                "average_rssi_dbm": item["rssi_sum"] / rssi_count if rssi_count else None,
                "average_latency_ms": item["latency_sum"] / item["latency_count"] if item["latency_count"] else None,
                "average_jitter_ms": item["jitter_sum"] / item["jitter_count"] if item["jitter_count"] else None,
                "average_packet_loss_pct": item["packet_loss_sum"] / item["packet_loss_count"] if item["packet_loss_count"] else None,
                "sample_count": scan_count,
                "diagnostic_sample_count": diagnostic_count,
            })
            for key in (
                "network_count_sum", "open_network_count_sum", "band_24_count_sum",
                "band_5_count_sum", "band_6_count_sum", "rssi_sum", "rssi_count",
                "latency_sum", "latency_count", "jitter_sum", "jitter_count",
                "packet_loss_sum", "packet_loss_count",
            ):
                item.pop(key, None)
            result.append(item)
        return result
