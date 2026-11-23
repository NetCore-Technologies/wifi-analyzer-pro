"""Tests for privacy-preserving bounded telemetry rollups."""
from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from wifi_analyzer_backend.telemetry_store import WiFiTelemetryStore


class WiFiTelemetryStoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "state" / "telemetry.sqlite3"
        self.now = datetime.now(timezone.utc).replace(second=10, microsecond=0)
        self.store = WiFiTelemetryStore(self.path, retention_days=7, max_rollups_per_site=10)

    def timestamp(self, seconds=0):
        return self.now + timedelta(seconds=seconds)

    def test_repeated_scans_roll_up_to_one_minute_without_retaining_identifiers(self):
        first = self.store.record_scan("office", [
            {"ssid": "Secret-SSID", "bssid": "AA:BB:CC:DD:EE:FF", "rssi": -50, "band": "5GHz", "security": "Open"},
            {"ssid": "Other", "bssid": "00:11:22:33:44:55", "rssi": -70, "band": "2.4GHz", "security": "WPA2"},
        ], sampled_at=self.timestamp())
        second = self.store.record_scan("office", [
            {"ssid": "Private-Network", "bssid": "11:22:33:44:55:66", "rssi": -60, "band": "6GHz", "security": "WPA3"},
        ], sampled_at=self.timestamp(seconds=20))

        self.assertEqual(first["minute_utc"], second["minute_utc"])
        rows = self.store.history(site_ids=["office"], days=1)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["sample_count"], 2)
        self.assertEqual(row["average_network_count"], 1.5)
        self.assertEqual(row["network_count_min"], 1)
        self.assertEqual(row["network_count_max"], 2)
        self.assertEqual(row["rssi_min"], -70)
        self.assertEqual(row["rssi_max"], -50)
        self.assertEqual(row["average_rssi_dbm"], -60)
        self.assertEqual(row["average_2_4ghz_network_count"], 0.5)
        self.assertEqual(row["average_5ghz_network_count"], 0.5)
        self.assertEqual(row["average_6ghz_network_count"], 0.5)
        self.assertNotIn("Secret-SSID", repr(row))
        self.assertNotIn("AA:BB:CC:DD:EE:FF", repr(row))

    def test_missing_diagnostic_values_are_not_recorded_as_zeroes(self):
        empty = self.store.record_diagnostics("office", {
            "latency_ms": None, "jitter_ms": None, "packet_loss_pct": None,
        }, sampled_at=self.timestamp())
        self.assertIsNone(empty)
        self.store.record_diagnostics("office", {
            "latency_ms": 12.0, "jitter_ms": None, "packet_loss_pct": 0.0,
        }, sampled_at=self.timestamp(seconds=5))
        row = self.store.history(site_ids=["office"], days=1)[0]
        self.assertEqual(row["diagnostic_sample_count"], 1)
        self.assertEqual(row["average_latency_ms"], 12.0)
        self.assertIsNone(row["average_jitter_ms"])
        self.assertEqual(row["average_packet_loss_pct"], 0.0)

    def test_diagnostic_rollup_tracks_metric_extrema_and_sample_counts(self):
        self.store.record_diagnostics("office", {
            "latency_ms": 20, "jitter_ms": 2, "packet_loss_pct": 1,
        }, sampled_at=self.timestamp())
        self.store.record_diagnostics("office", {
            "latency_ms": 8, "jitter_ms": 5, "packet_loss_pct": 0,
        }, sampled_at=self.timestamp(seconds=10))
        row = self.store.history(site_ids=["office"], days=1)[0]
        self.assertEqual(row["latency_min"], 8)
        self.assertEqual(row["latency_max"], 20)
        self.assertEqual(row["latency_max"], 20)
        self.assertEqual(row["average_latency_ms"], 14)
        self.assertEqual(row["jitter_min"], 2)
        self.assertEqual(row["jitter_max"], 5)
        self.assertEqual(row["average_packet_loss_pct"], 0.5)

    def test_scan_and_diagnostics_share_the_same_minute_bucket(self):
        self.store.record_scan("office", [{"rssi": -55, "band": "5GHz"}], sampled_at=self.timestamp())
        self.store.record_diagnostics("office", {"latency_ms": 9}, sampled_at=self.timestamp(seconds=15))
        rows = self.store.history(site_ids=["office"], days=1)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["sample_count"], 1)
        self.assertEqual(rows[0]["diagnostic_sample_count"], 1)

    def test_site_filters_are_isolated_and_empty_scope_returns_no_data(self):
        self.store.record_scan("office", [], sampled_at=self.timestamp())
        self.store.record_scan("branch", [], sampled_at=self.timestamp())
        self.assertEqual({item["site_id"] for item in self.store.history(site_ids=["office"], days=1)}, {"office"})
        self.assertEqual(self.store.history(site_ids=[], days=1), [])
        self.assertEqual(self.store.site_ids(), ["branch", "office"])

    def test_latest_returns_one_newest_minute_per_site_without_busy_site_starvation(self):
        base = self.timestamp()
        self.store.record_scan("office", [{"rssi": -80}], sampled_at=base)
        self.store.record_scan("office", [{"rssi": -60}, {"rssi": -70}], sampled_at=base + timedelta(minutes=1))
        self.store.record_scan("branch", [{"rssi": -45}], sampled_at=base + timedelta(minutes=2))
        latest = self.store.latest(days=1, limit=10)
        self.assertEqual([row["site_id"] for row in latest], ["branch", "office"])
        self.assertEqual(latest[0]["sample_count"], 1)
        self.assertEqual(latest[0]["average_rssi_dbm"], -45)
        self.assertEqual(latest[1]["sample_count"], 1)
        self.assertEqual(latest[1]["average_network_count"], 2)
        self.assertEqual(latest[1]["average_rssi_dbm"], -65)
        self.assertNotIn("network_count_sum", latest[1])

    def test_latest_site_filter_empty_scope_and_limits_are_enforced(self):
        self.store.record_scan("office", [{"rssi": -55}], sampled_at=self.timestamp())
        self.store.record_scan("branch", [{"rssi": -65}], sampled_at=self.timestamp())
        self.assertEqual(
            [row["site_id"] for row in self.store.latest(site_ids=["office"], days=1)],
            ["office"],
        )
        self.assertEqual(self.store.latest(site_ids=[], days=1), [])
        with self.assertRaisesRegex(ValueError, "unique"):
            self.store.latest(site_ids=["office", "office"])
        with self.assertRaisesRegex(ValueError, "1 and 100"):
            self.store.latest(limit=101)
        with self.assertRaisesRegex(ValueError, "between 1 and 7"):
            self.store.latest(days=8)

    def test_history_is_durable_across_store_recreation(self):
        self.store.record_scan("office", [{"rssi": -64}], sampled_at=self.timestamp())
        reopened = WiFiTelemetryStore(self.path, retention_days=7, max_rollups_per_site=10)
        self.assertEqual(len(reopened.history(site_ids=["office"], days=1)), 1)

    def test_retention_and_per_site_row_limits_are_enforced(self):
        old = datetime.now(timezone.utc) - timedelta(days=9)
        with self.assertRaisesRegex(ValueError, "retention window"):
            self.store.record_scan("office", [], sampled_at=old)
        base = datetime.now(timezone.utc).replace(second=0, microsecond=0) - timedelta(minutes=20)
        for minute in range(12):
            self.store.record_scan("office", [], sampled_at=base + timedelta(minutes=minute))
        rows = self.store.history(site_ids=["office"], days=7)
        self.assertEqual(len(rows), 10)

    def test_invalid_metrics_and_unbounded_inputs_are_rejected_or_excluded(self):
        self.store.record_scan("office", [{"rssi": -200}, {"rssi": True}, {"rssi": -60}], sampled_at=self.timestamp())
        row = self.store.history(site_ids=["office"], days=1)[0]
        self.assertEqual(row["average_rssi_dbm"], -60)
        self.assertEqual(row["rssi_min"], -60)
        self.assertEqual(row["rssi_max"], -60)
        with self.assertRaisesRegex(ValueError, "no more than 512"):
            self.store.record_scan("office", [{}] * 513, sampled_at=self.timestamp())
        with self.assertRaisesRegex(ValueError, "timezone"):
            self.store.record_scan("office", [], sampled_at=self.now.replace(tzinfo=None))
        with self.assertRaisesRegex(ValueError, "future"):
            self.store.record_scan("office", [], sampled_at=datetime.now(timezone.utc) + timedelta(hours=1))

    def test_configuration_validation_rejects_bools_and_out_of_bounds(self):
        with self.assertRaisesRegex(ValueError, "retention_days"):
            WiFiTelemetryStore(self.path, retention_days=True)
        with self.assertRaisesRegex(ValueError, "max_rollups_per_site"):
            WiFiTelemetryStore(self.path, max_rollups_per_site=True)
        with self.assertRaisesRegex(ValueError, "site_id"):
            self.store.record_scan("../outside", [], sampled_at=self.timestamp())


    def test_speedtest_rollups_preserve_only_completed_measured_results(self):
        self.store.record_speedtest("office", {
            "download": 120.5, "upload": 22.0, "ping": 14.5,
        }, sampled_at=self.timestamp())
        self.store.record_speedtest("office", {
            "download": 80.5, "upload": None, "ping": 20.5,
        }, sampled_at=self.timestamp(seconds=20))
        self.store.record_speedtest("office", {
            "download": 0, "upload": 0, "ping": 0, "error": "probe failed",
        }, sampled_at=self.timestamp(seconds=30))
        row = self.store.history(site_ids=["office"], days=1)[0]
        self.assertEqual(row["speedtest_sample_count"], 2)
        self.assertEqual(row["average_speedtest_download_mbps"], 100.5)
        self.assertEqual(row["average_speedtest_upload_mbps"], 22.0)
        self.assertEqual(row["average_speedtest_ping_ms"], 17.5)
        self.assertEqual(row["speedtest_download_min"], 80.5)
        self.assertEqual(row["speedtest_download_max"], 120.5)

    def test_speedtest_missing_or_out_of_range_results_are_not_persisted(self):
        self.assertIsNone(self.store.record_speedtest("office", {"error": "offline"}))
        self.assertIsNone(self.store.record_speedtest("office", {"download": None, "upload": -1, "ping": float("nan")}))
        self.assertEqual(self.store.history(site_ids=["office"], days=1), [])

    def test_old_telemetry_database_is_migrated_without_losing_existing_rows(self):
        import sqlite3

        legacy_path = Path(self.directory.name) / "legacy.sqlite3"
        with sqlite3.connect(legacy_path) as db:
            db.execute("""
                CREATE TABLE wifi_telemetry_minute (
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
                "INSERT INTO wifi_telemetry_minute (site_id, minute_utc, scan_count, updated_at) VALUES (?, ?, ?, ?)",
                ("office", self.timestamp().replace(second=0).isoformat(timespec="seconds"), 3, self.timestamp().isoformat()),
            )
        migrated = WiFiTelemetryStore(legacy_path, retention_days=7)
        migrated.record_speedtest("office", {"download": 25.0}, sampled_at=self.timestamp())
        rows = migrated.history(site_ids=["office"], days=1)
        self.assertEqual(rows[0]["sample_count"], 3)
        self.assertEqual(rows[0]["average_speedtest_download_mbps"], 25.0)

if __name__ == "__main__":
    unittest.main()
