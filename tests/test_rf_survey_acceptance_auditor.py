"""F205 tests for policy-based measured RF survey acceptance."""
from __future__ import annotations

import copy
import unittest

from wifi_analyzer_backend.feature_plugins.registry import run


def _report(site="hq"):
    result = {
        "status": "analysed",
        "site_id": site,
        "floorplan_id": "hq-floor-1",
        "floor_id": "level-1",
        "floorplan": {"width_px": 1000, "height_px": 800},
        "scale": {"metres_per_pixel": 0.02},
        "access_points": [{"ap_id": "ap-01", "x_px": 100, "y_px": 100}],
        "measurements": [],
    }
    points = [
        ("aaaaaaaaaaaaaaaa", 200, 100, -50, -95),
        ("bbbbbbbbbbbbbbbb", 300, 100, -60, -100),
        ("cccccccccccccccc", 400, 100, -75, -100),
        ("dddddddddddddddd", 500, 100, -65, None),
    ]
    for fingerprint, x, y, rssi, noise in points:
        result["measurements"].append({
            "ap_id": "ap-01",
            "floorplan_id": "hq-floor-1",
            "floor_id": "level-1",
            "sample_fingerprint": fingerprint,
            "observed_at": "2026-11-21T10:00:00Z",
            "evidence_source": "survey",
            "survey_x_px": x,
            "survey_y_px": y,
            "rssi_dbm": rssi,
            "noise_dbm": noise,
            "snr_db": rssi - noise if noise is not None else None,
        })
    return {
        "report": {
            "survey_id": "survey-001",
            "site_id": site,
            "floorplan_id": "hq-floor-1",
            "floor_id": "level-1",
            "label": "HQ acceptance survey",
            "created_at": "2026-11-21T11:00:00Z",
        },
        "result": result,
    }


def _payload():
    return {
        "site_id": "hq",
        "as_of": "2026-11-21T12:00:00Z",
        "report": _report(),
        "policy": {
            "minimum_rssi_dbm": -67,
            "minimum_snr_db": 20,
            "minimum_passing_points_pct": 75,
            "minimum_sample_count": 3,
            "minimum_qualifying_aps": 1,
            "maximum_sample_age_days": 7,
        },
        "zones": [
            {"zone_id": "west-wing", "x1_px": 100, "y1_px": 50, "x2_px": 450, "y2_px": 200},
            {"zone_id": "east-wing", "x1_px": 450, "y1_px": 50, "x2_px": 700, "y2_px": 200},
        ],
    }


class RfSurveyAcceptanceAuditorTests(unittest.TestCase):
    def test_f205_scores_actual_points_against_customer_rssi_and_snr_policy(self):
        result = run("rf_survey_acceptance_auditor", _payload())["result"]
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["summary"]["sampled_point_count"], 4)
        self.assertEqual(result["summary"]["passing_point_count"], 2)
        self.assertEqual(result["summary"]["failing_point_count"], 2)
        self.assertEqual(result["summary"]["passing_points_pct"], 50.0)
        self.assertEqual(result["zones"][0]["sampled_point_count"], 3)
        self.assertEqual(result["zones"][0]["passing_point_count"], 2)
        self.assertEqual(result["zones"][1]["sampled_point_count"], 1)
        self.assertEqual(result["zones"][1]["status"], "insufficient_evidence")

    def test_f205_returns_insufficient_evidence_instead_of_extrapolating(self):
        payload = _payload()
        payload["policy"]["minimum_sample_count"] = 5
        result = run("rf_survey_acceptance_auditor", payload)["result"]
        self.assertEqual(result["status"], "insufficient_evidence")
        self.assertEqual(result["summary"]["minimum_sample_count_met"], False)
        self.assertEqual(result["summary"]["sampled_point_count"], 4)

    def test_f205_excludes_stale_points_but_validates_their_measurements(self):
        payload = _payload()
        payload["report"]["result"]["measurements"][0]["observed_at"] = "2026-11-01T10:00:00Z"
        result = run("rf_survey_acceptance_auditor", payload)["result"]
        self.assertEqual(result["summary"]["stale_measurement_count_excluded"], 1)
        self.assertEqual(result["summary"]["sampled_point_count"], 3)
        payload["report"]["result"]["measurements"][0]["rssi_dbm"] = -130
        with self.assertRaisesRegex(ValueError, "rssi_dbm"):
            run("rf_survey_acceptance_auditor", payload)

    def test_f205_requires_noise_when_snr_policy_is_enabled(self):
        payload = _payload()
        result = run("rf_survey_acceptance_auditor", payload)["result"]
        last = next(point for point in result["points"] if point["x_px"] == 500)
        self.assertEqual(last["status"], "fail")

    def test_f205_reports_zone_overlaps_without_counting_unmeasured_areas(self):
        payload = _payload()
        payload["zones"] = [
            {"zone_id": "all", "x1_px": 100, "y1_px": 50, "x2_px": 800, "y2_px": 300},
            {"zone_id": "overlap", "x1_px": 250, "y1_px": 50, "x2_px": 600, "y2_px": 200},
        ]
        result = run("rf_survey_acceptance_auditor", payload)["result"]
        self.assertEqual(result["zones"][0]["sampled_point_count"], 4)
        self.assertEqual(result["zones"][1]["sampled_point_count"], 3)
        self.assertEqual(result["summary"]["sampled_point_count"], 4)

    def test_f205_rejects_cross_site_floor_and_report_metadata_mismatch(self):
        payload = _payload()
        payload["report"]["result"]["site_id"] = "branch"
        with self.assertRaisesRegex(ValueError, "another site"):
            run("rf_survey_acceptance_auditor", payload)
        payload = _payload()
        payload["report"]["result"]["status"] = []
        with self.assertRaisesRegex(ValueError, "unsupported F203 status"):
            run("rf_survey_acceptance_auditor", payload)
        payload = _payload()
        payload["report"]["result"]["floor_id"] = "level-2"
        with self.assertRaisesRegex(ValueError, "metadata does not match"):
            run("rf_survey_acceptance_auditor", payload)
        payload = _payload()
        payload["report"]["result"]["measurements"][0]["floor_id"] = "level-2"
        with self.assertRaisesRegex(ValueError, "another floor"):
            run("rf_survey_acceptance_auditor", payload)

    def test_f205_rejects_unknown_ap_ids_and_non_string_evidence_sources(self):
        payload = _payload()
        payload["report"]["result"]["measurements"][0]["ap_id"] = "missing-ap"
        with self.assertRaisesRegex(ValueError, "unknown AP"):
            run("rf_survey_acceptance_auditor", payload)
        payload = _payload()
        payload["report"]["result"]["measurements"][0]["evidence_source"] = []
        with self.assertRaisesRegex(ValueError, "evidence_source"):
            run("rf_survey_acceptance_auditor", payload)

    def test_f205_rejects_bad_policy_zones_duplicate_and_future_measurements(self):
        cases = [
            ({"minimum_rssi_dbm": True}, "minimum_rssi_dbm"),
            ({"minimum_passing_points_pct": 101}, "minimum_passing_points_pct"),
            ({"minimum_sample_count": True}, "minimum_sample_count"),
            ({"minimum_qualifying_aps": 0}, "minimum_qualifying_aps"),
            ({"maximum_sample_age_days": 31}, "maximum_sample_age_days"),
        ]
        for policy_change, message in cases:
            payload = _payload()
            payload["policy"].update(policy_change)
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                run("rf_survey_acceptance_auditor", payload)
        payload = _payload()
        payload["zones"].append(payload["zones"][0])
        with self.assertRaisesRegex(ValueError, "unique"):
            run("rf_survey_acceptance_auditor", payload)
        payload = _payload()
        payload["report"]["result"]["measurements"][0]["observed_at"] = "2026-11-21T13:00:00Z"
        with self.assertRaisesRegex(ValueError, "too far in the future"):
            run("rf_survey_acceptance_auditor", payload)
        payload = _payload()
        payload["report"]["result"]["measurements"].append(payload["report"]["result"]["measurements"][0])
        with self.assertRaisesRegex(ValueError, "duplicate AP readings"):
            run("rf_survey_acceptance_auditor", payload)
