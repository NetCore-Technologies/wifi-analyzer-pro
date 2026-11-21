"""F203 floor-plan aligned measured RF survey tests."""
from __future__ import annotations

import copy
import unittest
from datetime import datetime, timedelta, timezone

from wifi_analyzer_backend.feature_plugins.registry import run

_NOW = datetime.now(timezone.utc).replace(microsecond=0)
_PAYLOAD = {
    "site_id": "head-office",
    "as_of": _NOW.isoformat(),
    "max_age_days": 7,
    "floorplan": {
        "floorplan_id": "hq-level-1",
        "floor_id": "level-1",
        "width_px": 1000,
        "height_px": 800,
        "scale_references": [
            {"x1_px": 0, "y1_px": 0, "x2_px": 1000, "y2_px": 0, "distance_m": 20},
            {"x1_px": 0, "y1_px": 0, "x2_px": 0, "y2_px": 500, "distance_m": 10},
        ],
    },
    "access_points": [
        {"ap_id": "ap-01", "floor_id": "level-1", "x_px": 100, "y_px": 100},
        {"ap_id": "ap-02", "floor_id": "level-1", "x_px": 800, "y_px": 100},
    ],
    "survey_samples": [
        {
            "sample_id": "survey-001", "floor_id": "level-1", "x_px": 200, "y_px": 100,
            "observed_at": (_NOW - timedelta(hours=1)).isoformat(), "evidence_source": "survey",
            "measurements": [
                {"ap_id": "ap-01", "rssi_dbm": -45, "noise_dbm": -95},
                {"ap_id": "ap-02", "rssi_dbm": -68},
            ],
        },
        {
            "sample_id": "survey-002", "floor_id": "level-1", "x_px": 300, "y_px": 100,
            "observed_at": (_NOW - timedelta(hours=2)).isoformat(), "evidence_source": "controller",
            "measurements": [
                {"ap_id": "ap-01", "rssi_dbm": -53, "noise_dbm": -94},
                {"ap_id": "ap-02", "rssi_dbm": -64, "noise_dbm": -94},
            ],
        },
        {
            "sample_id": "survey-003", "floor_id": "level-1", "x_px": 400, "y_px": 100,
            "observed_at": (_NOW - timedelta(hours=3)).isoformat(), "evidence_source": "operator",
            "measurements": [
                {"ap_id": "ap-01", "rssi_dbm": -60},
                {"ap_id": "ap-02", "rssi_dbm": -59},
            ],
        },
    ],
}


class FloorplanRfSurveyAnalyzerTests(unittest.TestCase):
    def test_f203_aligns_measured_survey_points_and_summarises_per_ap(self):
        result = run("floorplan_rf_survey_analyzer", _PAYLOAD)["result"]
        self.assertEqual(result["status"], "analysed")
        self.assertEqual(result["floorplan_id"], "hq-level-1")
        self.assertAlmostEqual(result["scale"]["metres_per_pixel"], 0.02)
        self.assertEqual(result["accepted_sample_count"], 3)
        self.assertEqual(result["accepted_measurement_count"], 6)
        ap = {item["ap_id"]: item for item in result["access_points"]}["ap-01"]
        self.assertEqual(ap["sample_count"], 3)
        self.assertEqual(ap["minimum_rssi_dbm"], -60)
        self.assertEqual(ap["maximum_rssi_dbm"], -45)
        self.assertAlmostEqual(ap["minimum_distance_m"], 2.0)
        self.assertAlmostEqual(ap["maximum_distance_m"], 6.0)
        self.assertEqual(ap["distance_buckets"]["0-5m"]["sample_count"], 2)
        self.assertEqual(result["measurements"][0]["snr_db"], 50)
        self.assertEqual(result["measurements"][0]["survey_x_px"], 200)
        self.assertEqual(result["measurements"][0]["ap_x_px"], 100)
        self.assertNotIn("survey-001", repr(result))

    def test_f203_reports_descriptive_trend_without_claiming_propagation(self):
        result = run("floorplan_rf_survey_analyzer", _PAYLOAD)["result"]
        ap = {item["ap_id"]: item for item in result["access_points"]}["ap-01"]
        self.assertEqual(ap["rssi_distance_trend"]["status"], "descriptive_measured_trend")
        self.assertIsNotNone(ap["rssi_distance_trend"]["slope_db_per_distance_decade"])
        self.assertIn("not a calibrated propagation model", " ".join(result["limitations"]))

    def test_f203_excludes_stale_samples_but_still_validates_their_readings(self):
        payload = copy.deepcopy(_PAYLOAD)
        payload["max_age_days"] = 1
        payload["survey_samples"] = [{
            **payload["survey_samples"][0],
            "observed_at": (_NOW - timedelta(days=10)).isoformat(),
        }]
        result = run("floorplan_rf_survey_analyzer", payload)["result"]
        self.assertEqual(result["status"], "insufficient_fresh_survey_evidence")
        self.assertEqual(result["skipped_stale_sample_count"], 1)
        self.assertEqual(result["accepted_measurement_count"], 0)
        self.assertIsNone(result["access_points"][0]["average_rssi_dbm"])
        payload["survey_samples"][0]["measurements"][0]["ap_id"] = "missing"
        with self.assertRaisesRegex(ValueError, "unknown AP"):
            run("floorplan_rf_survey_analyzer", payload)

    def test_f203_rejects_inconsistent_scale_and_cross_floor_ap(self):
        payload = copy.deepcopy(_PAYLOAD)
        payload["floorplan"]["scale_references"][1]["distance_m"] = 20
        with self.assertRaisesRegex(ValueError, "disagree by more than 15 percent"):
            run("floorplan_rf_survey_analyzer", payload)
        payload = copy.deepcopy(_PAYLOAD)
        payload["access_points"][0]["floor_id"] = "level-2"
        with self.assertRaisesRegex(ValueError, "another floor"):
            run("floorplan_rf_survey_analyzer", payload)

    def test_f203_rejects_bad_times_duplicate_ids_and_measurement_ranges(self):
        cases = []
        payload = copy.deepcopy(_PAYLOAD)
        payload["survey_samples"][0]["observed_at"] = _NOW.replace(tzinfo=None).isoformat()
        cases.append((payload, "timezone offset"))
        payload = copy.deepcopy(_PAYLOAD)
        payload["survey_samples"][1]["sample_id"] = "survey-001"
        cases.append((payload, "unique"))
        payload = copy.deepcopy(_PAYLOAD)
        payload["survey_samples"][0]["measurements"][0]["rssi_dbm"] = -130
        cases.append((payload, "rssi_dbm"))
        payload = copy.deepcopy(_PAYLOAD)
        payload["survey_samples"][0]["measurements"][0]["noise_dbm"] = 1
        cases.append((payload, "noise_dbm"))
        for candidate, pattern in cases:
            with self.subTest(pattern=pattern), self.assertRaisesRegex(ValueError, pattern):
                run("floorplan_rf_survey_analyzer", candidate)

    def test_f203_rejects_unknown_aps_duplicate_readings_and_invalid_source(self):
        payload = copy.deepcopy(_PAYLOAD)
        payload["survey_samples"][0]["measurements"][0]["ap_id"] = "missing"
        with self.assertRaisesRegex(ValueError, "unknown AP"):
            run("floorplan_rf_survey_analyzer", payload)
        payload = copy.deepcopy(_PAYLOAD)
        payload["survey_samples"][0]["measurements"].append(payload["survey_samples"][0]["measurements"][0])
        with self.assertRaisesRegex(ValueError, "duplicate readings"):
            run("floorplan_rf_survey_analyzer", payload)
        payload = copy.deepcopy(_PAYLOAD)
        payload["survey_samples"][0]["evidence_source"] = []
        with self.assertRaisesRegex(ValueError, "evidence_source"):
            run("floorplan_rf_survey_analyzer", payload)
