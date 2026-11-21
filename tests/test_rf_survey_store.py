"""Tests for durable, bounded site-scoped F203 report history."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from wifi_analyzer_backend.rf_survey_store import RfSurveyHistoryStore


def result_for(site_id="head-office"):
    return {
        "status": "analysed",
        "site_id": site_id,
        "floorplan_id": "hq-floor-1",
        "floor_id": "level-1",
        "accepted_sample_count": 2,
        "access_points": [{"ap_id": "ap-01", "sample_count": 2}],
        "measurements": [
            {"ap_id": "ap-01", "rssi_dbm": -55, "distance_m": 2.0},
            {"ap_id": "ap-01", "rssi_dbm": -60, "distance_m": 4.0},
        ],
    }


class RfSurveyHistoryStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "state" / "rf-surveys.sqlite3"
        self.store = RfSurveyHistoryStore(self.path, max_reports_per_site=2, max_report_bytes=128 * 1024)

    def test_saved_reports_are_durable_and_isolated_by_site(self):
        saved = self.store.save("head-office", result_for(), label="North wing baseline")
        other = self.store.save("branch", result_for("branch"), label="Branch floor 1")
        reopened = RfSurveyHistoryStore(self.path, max_reports_per_site=2)
        self.assertEqual(saved["label"], "North wing baseline")
        self.assertEqual(saved["measurement_count"], 2)
        self.assertNotEqual(saved["survey_id"], other["survey_id"])
        self.assertEqual(len(reopened.list_for_site("head-office")), 1)
        self.assertEqual(reopened.get("head-office", saved["survey_id"])["result"], result_for())
        self.assertIsNone(reopened.get("branch", saved["survey_id"]))

    def test_report_list_is_newest_first_and_bounded(self):
        first = self.store.save("head-office", result_for(), label="first")
        second = self.store.save("head-office", result_for(), label="second")
        self.assertEqual([row["survey_id"] for row in self.store.list_for_site("head-office", limit=2)],
                         [second["survey_id"], first["survey_id"]])
        with self.assertRaisesRegex(ValueError, "between 1 and 100"):
            self.store.list_for_site("head-office", limit=101)

    def test_site_limit_never_overwrites_an_existing_report(self):
        first = self.store.save("head-office", result_for())
        second = self.store.save("head-office", result_for())
        with self.assertRaisesRegex(ValueError, "already has 2"):
            self.store.save("head-office", result_for())
        self.assertIsNotNone(self.store.get("head-office", first["survey_id"]))
        self.assertIsNotNone(self.store.get("head-office", second["survey_id"]))

    def test_rejects_mismatched_site_invalid_status_nonfinite_and_oversized_results(self):
        with self.assertRaisesRegex(ValueError, "must match"):
            self.store.save("branch", result_for())
        with self.assertRaisesRegex(ValueError, "status"):
            self.store.save("head-office", {**result_for(), "status": "failed"})
        bad = result_for()
        bad["measurements"][0]["rssi_dbm"] = float("nan")
        with self.assertRaisesRegex(ValueError, "finite JSON"):
            self.store.save("head-office", bad)
        limited = RfSurveyHistoryStore(self.path, max_report_bytes=1024)
        oversized = result_for()
        oversized["measurements"] = [{"ap_id": "ap-01", "detail": "x" * 2000}]
        with self.assertRaisesRegex(ValueError, "storage limit"):
            limited.save("head-office", oversized)

    def test_rejects_invalid_identifiers_and_configuration(self):
        with self.assertRaisesRegex(ValueError, "site_id"):
            self.store.list_for_site("../outside")
        with self.assertRaisesRegex(ValueError, "UUID"):
            self.store.get("head-office", "../outside")
        with self.assertRaisesRegex(ValueError, "max_reports_per_site"):
            RfSurveyHistoryStore(self.path, max_reports_per_site=True)
        with self.assertRaisesRegex(ValueError, "retention_days"):
            RfSurveyHistoryStore(self.path, retention_days=False)

    def test_delete_is_site_scoped_and_idempotent(self):
        saved = self.store.save("head-office", result_for())
        self.assertFalse(self.store.delete("branch", saved["survey_id"]))
        self.assertIsNotNone(self.store.get("head-office", saved["survey_id"]))
        self.assertTrue(self.store.delete("head-office", saved["survey_id"]))
        self.assertFalse(self.store.delete("head-office", saved["survey_id"]))
        with self.assertRaisesRegex(ValueError, "UUID"):
            self.store.delete("head-office", "../outside")

    def test_reports_include_only_sites_with_saved_data(self):
        self.store.save("head-office", result_for())
        self.store.save("branch", result_for("branch"))
        self.assertEqual(self.store.site_ids(), ["branch", "head-office"])

    def test_detects_result_tampering(self):
        saved = self.store.save("head-office", result_for())
        with self.store._db() as db:
            db.execute("UPDATE rf_survey_reports SET result_json = ? WHERE survey_id = ?",
                       ('{"status":"tampered"}', saved["survey_id"]))
        with self.assertRaisesRegex(RuntimeError, "integrity verification"):
            self.store.get("head-office", saved["survey_id"])
