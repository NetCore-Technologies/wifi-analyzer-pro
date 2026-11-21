"""F204 tests for coordinate-matched longitudinal RF survey comparison."""
from __future__ import annotations

import unittest

from wifi_analyzer_backend.feature_plugins.registry import run


def _result(*, site="hq", context=None, signal_offset=0.0, ap_x=100):
    return {
        "status": "analysed",
        "site_id": site,
        "floorplan_id": "hq-floor-1",
        "floor_id": "level-1",
        "floorplan": {"width_px": 1000, "height_px": 800},
        "scale": {"metres_per_pixel": 0.02},
        "measurement_context": context or {},
        "access_points": [{"ap_id": "ap-01", "x_px": ap_x, "y_px": 100}],
        "measurements": [
            {
                "ap_id": "ap-01",
                "floorplan_id": "hq-floor-1",
                "floor_id": "level-1",
                "observed_at": "2026-11-01T09:00:00Z",
                "evidence_source": "survey",
                "survey_x_px": x,
                "survey_y_px": 100,
                "rssi_dbm": rssi + signal_offset,
            }
            for x, rssi in ((200, -50), (300, -60), (400, -70), (500, -65))
        ],
    }


def _bundle(survey_id, created_at, result, label):
    return {
        "report": {
            "survey_id": survey_id,
            "site_id": result["site_id"],
            "floorplan_id": result["floorplan_id"],
            "floor_id": result["floor_id"],
            "label": label,
            "created_at": created_at,
        },
        "result": result,
    }


def _payload():
    context = {
        "device_model": "SurveyClient X",
        "radio_band": "5GHz",
        "channel": 36,
        "channel_width_mhz": 80,
        "antenna_type": "integrated",
        "antenna_orientation_deg": 90.0,
        "antenna_height_m": 1.2,
        "calibration_id": "cal-2026-11",
    }
    return {
        "site_id": "hq",
        "baseline_report": _bundle("survey-001", "2026-11-01T10:00:00Z", _result(context=context), "November baseline"),
        "current_report": _bundle("survey-002", "2026-11-21T10:00:00Z", _result(context=context, signal_offset=-6), "November current"),
    }


class RfSurveyReportComparatorTests(unittest.TestCase):
    def test_f204_compares_same_ap_and_coordinate_measurements(self):
        result = run("rf_survey_report_comparator", _payload())
        self.assertEqual(result["feature"], "F204")
        value = result["result"]
        self.assertEqual(value["status"], "compared")
        self.assertEqual(value["comparability"]["status"], "comparable")
        self.assertEqual(value["summary"]["matched_point_count"], 4)
        self.assertEqual(value["summary"]["median_delta_rssi_db"], -6)
        self.assertEqual(value["summary"]["weaker_by_threshold_count"], 4)
        self.assertEqual(value["access_points"][0]["median_delta_rssi_db"], -6)
        self.assertTrue(all(row["delta_rssi_db"] == -6 for row in value["matches"]))

    def test_f204_discloses_missing_and_mismatched_measurement_context(self):
        payload = _payload()
        payload["baseline_report"]["result"]["measurement_context"] = {}
        result = run("rf_survey_report_comparator", payload)["result"]
        self.assertEqual(result["comparability"]["status"], "limited")
        self.assertIn("radio_band", result["comparability"]["missing_context_fields"])
        payload = _payload()
        payload["current_report"]["result"]["measurement_context"]["device_model"] = "Different client"
        result = run("rf_survey_report_comparator", payload)["result"]
        self.assertIn("device_model", result["comparability"]["mismatched_context_fields"])

    def test_f204_excludes_repositioned_aps_and_returns_insufficient_overlap(self):
        payload = _payload()
        payload["current_report"]["result"]["access_points"][0]["x_px"] = 110
        result = run("rf_survey_report_comparator", payload)["result"]
        self.assertEqual(result["status"], "insufficient_overlap")
        self.assertEqual(result["comparability"]["moved_or_repositioned_ap_ids"], ["ap-01"])
        self.assertEqual(result["summary"]["matched_point_count"], 0)

    def test_f204_rejects_cross_site_floorplan_scale_and_report_order_mismatch(self):
        payload = _payload()
        payload["current_report"]["result"]["site_id"] = "branch"
        with self.assertRaisesRegex(ValueError, "another site"):
            run("rf_survey_report_comparator", payload)
        payload = _payload()
        payload["current_report"]["result"]["floorplan_id"] = "other-floor"
        with self.assertRaisesRegex(ValueError, "same floorplan_id"):
            run("rf_survey_report_comparator", payload)
        payload = _payload()
        payload["current_report"]["result"]["scale"]["metres_per_pixel"] = 0.03
        with self.assertRaisesRegex(ValueError, "distance scales"):
            run("rf_survey_report_comparator", payload)
        payload = _payload()
        payload["baseline_report"]["report"]["created_at"] = "2026-11-22T10:00:00Z"
        with self.assertRaisesRegex(ValueError, "must be older"):
            run("rf_survey_report_comparator", payload)

    def test_f204_reports_added_and_removed_access_points(self):
        payload = _payload()
        payload["baseline_report"]["result"]["access_points"].append(
            {"ap_id": "ap-removed", "x_px": 700, "y_px": 100}
        )
        payload["current_report"]["result"]["access_points"].append(
            {"ap_id": "ap-added", "x_px": 800, "y_px": 100}
        )
        result = run("rf_survey_report_comparator", payload)["result"]
        self.assertEqual(result["comparability"]["removed_ap_ids"], ["ap-removed"])
        self.assertEqual(result["comparability"]["added_ap_ids"], ["ap-added"])

    def test_f204_rejects_measurements_from_another_floor(self):
        payload = _payload()
        payload["current_report"]["result"]["measurements"][0]["floor_id"] = "level-2"
        with self.assertRaisesRegex(ValueError, "another floor"):
            run("rf_survey_report_comparator", payload)

    def test_f204_requires_exact_coordinate_matches_and_valid_measurement_provenance(self):
        payload = _payload()
        payload["current_report"]["result"]["measurements"][0]["survey_x_px"] = 200.01
        result = run("rf_survey_report_comparator", payload)["result"]
        self.assertEqual(result["summary"]["matched_point_count"], 3)

        payload = _payload()
        payload["current_report"]["result"]["measurements"][0]["evidence_source"] = "unknown"
        with self.assertRaisesRegex(ValueError, "evidence_source"):
            run("rf_survey_report_comparator", payload)

    def test_f204_rejects_same_report_and_invalid_thresholds(self):
        payload = _payload()
        payload["current_report"]["report"]["survey_id"] = "survey-001"
        with self.assertRaisesRegex(ValueError, "different surveys"):
            run("rf_survey_report_comparator", payload)
        payload = _payload()
        payload["change_threshold_db"] = 0
        with self.assertRaisesRegex(ValueError, "change_threshold_db"):
            run("rf_survey_report_comparator", payload)
        payload = _payload()
        payload["minimum_matched_points"] = True
        with self.assertRaisesRegex(ValueError, "minimum_matched_points"):
            run("rf_survey_report_comparator", payload)
