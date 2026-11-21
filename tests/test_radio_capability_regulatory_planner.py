"""Tests for F207 controller-capability and reviewed-rule eligibility."""
from __future__ import annotations

import copy
import unittest
from datetime import datetime, timedelta, timezone

from wifi_analyzer_backend.feature_plugins.registry import run
from wifi_analyzer_backend.feature_plugins.feature_206_radio_regulatory_evidence_validator import run as validate_regulatory_dataset

_NOW = datetime.now(timezone.utc).replace(microsecond=0)
_RAW_DATASET = {
    "jurisdiction": "AU",
    "dataset_id": "acma-lipd-rllan",
    "version": "ACMA-LIPD-2026-10",
    "regulator": "Australian Communications and Media Authority",
    "retrieved_at": _NOW.isoformat(),
    "effective_from": "2025-10-01",
    "effective_to": None,
    "as_of": _NOW.date().isoformat(),
    "sources": [{
        "source_id": "acma-lipd",
        "source_type": "licence_condition",
        "title": "Radiocommunications (Low Interference Potential Devices) Class Licence",
        "authority": "ACMA",
        "document_reference": "LIPD Class Licence",
        "revision": "2025-10 consolidated",
        "source_url": "https://www.acma.gov.au/licences/low-interference-potential-devices-class-licence",
        "published_at": "2025-10-01",
        "effective_from": "2025-10-01",
        "effective_to": None,
        "retrieved_at": _NOW.isoformat(),
        "content_sha256": "a" * 64,
        "clause_references": ["Schedule 1, item 51"],
    }],
    "rules": [{
        "rule_id": "au-6ghz-lpi-example",
        "band": "6GHz",
        "lower_frequency_mhz": 5925,
        "upper_frequency_mhz": 6585,
        "maximum_eirp_dbm": 24,
        "maximum_eirp_density_dbm_per_mhz": 11,
        "channel_widths_mhz": [20, 40, 80, 160],
        "channel_numbers": [1, 5, 9, 13],
        "device_classes": ["LPI"],
        "indoor_only": True,
        "outdoor_allowed": False,
        "dfs_required": False,
        "afc_required": False,
        "source_references": [{"source_id": "acma-lipd", "clause": "Schedule 1, item 51"}],
    }],
}
_DATASET = validate_regulatory_dataset(_RAW_DATASET)["result"]


def make_payload():
    return {
        "site_id": "head-office",
        "as_of": _NOW.isoformat(),
        "regulatory_dataset": copy.deepcopy(_DATASET),
        "dataset_acknowledgement": {
            "dataset_fingerprint_sha256": _DATASET["dataset_fingerprint_sha256"],
            "reviewer_id": "netops.reviewer",
            "reviewed_at": _NOW.isoformat(),
            "review_reference": "CHG-2026-1101",
        },
        "radios": [{
            "radio_id": "ap-01-radio-6g",
            "ap_id": "ap-01",
            "site_id": "head-office",
            "jurisdiction": "AU",
            "installation_reference": "hq-building-a",
            "band": "6GHz",
            "capability_source": "controller",
            "capabilities_observed_at": _NOW.isoformat(),
            "supported_channels": [1, 5, 9, 13],
            "supported_channel_widths_mhz": [20, 40, 80, 160],
            "device_class": "LPI",
            "environment": "indoor",
            "dfs_supported": False,
            "afc_supported": False,
            "maximum_eirp_dbm": 20,
            "maximum_eirp_density_dbm_per_mhz": 10,
            "current_channel": 5,
            "current_channel_width_mhz": 80,
            "current_eirp_dbm": 18,
        }],
    }


class RadioCapabilityRegulatoryPlannerTests(unittest.TestCase):
    def test_f207_verifies_dataset_fingerprint_and_explicit_review_acknowledgement(self):
        payload = make_payload()
        result = run("radio_capability_regulatory_channel_planner", payload)["result"]
        self.assertEqual(result["status"], "eligible")
        self.assertEqual(result["dataset"]["fingerprint_sha256"], _DATASET["dataset_fingerprint_sha256"])
        self.assertFalse(result["change_application"]["applied"])

        changed = make_payload()
        changed["regulatory_dataset"]["rules"][0]["maximum_eirp_dbm"] = 60
        with self.assertRaisesRegex(ValueError, "fingerprint does not match"):
            run("radio_capability_regulatory_channel_planner", changed)

        changed = make_payload()
        changed["dataset_acknowledgement"]["dataset_fingerprint_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "exact regulatory dataset fingerprint"):
            run("radio_capability_regulatory_channel_planner", changed)

    def test_f207_preserves_an_eligible_configuration_and_never_increases_power(self):
        result = run("radio_capability_regulatory_channel_planner", make_payload())["result"]
        recommendation = result["radios"][0]["recommended_configuration"]
        self.assertEqual(recommendation["channel"], 5)
        self.assertEqual(recommendation["channel_width_mhz"], 80)
        self.assertEqual(recommendation["proposed_eirp_dbm"], 18)
        self.assertFalse(recommendation["change_required"])
        candidate = next(
            item for item in result["radios"][0]["eligible_candidates"]
            if item["channel"] == 5 and item["channel_width_mhz"] == 80
        )
        self.assertTrue(candidate["six_ghz_psc"])
        self.assertLessEqual(candidate["proposed_eirp_dbm"], candidate["eirp_ceiling_dbm"])

    def test_f207_applies_rule_and_radio_eirp_density_ceilings(self):
        payload = make_payload()
        payload["radios"][0]["current_eirp_dbm"] = 28
        payload["radios"][0]["maximum_eirp_dbm"] = 30
        payload["radios"][0]["maximum_eirp_density_dbm_per_mhz"] = 5
        result = run("radio_capability_regulatory_channel_planner", payload)["result"]
        candidate = next(
            item for item in result["radios"][0]["eligible_candidates"]
            if item["channel"] == 5 and item["channel_width_mhz"] == 80
        )
        self.assertLessEqual(candidate["eirp_ceiling_dbm"], 24)
        self.assertLessEqual(candidate["proposed_eirp_dbm"], candidate["eirp_ceiling_dbm"])
        self.assertTrue(candidate["matches_current_channel_and_width"])

    def test_f207_requires_dfs_capability_and_fresh_channel_state(self):
        raw = copy.deepcopy(_RAW_DATASET)
        raw["rules"][0].update({
            "band": "5GHz",
            "lower_frequency_mhz": 5150,
            "upper_frequency_mhz": 5850,
            "channel_widths_mhz": [20],
            "channel_numbers": [36, 40],
            "dfs_required": True,
        })
        dataset = validate_regulatory_dataset(raw)["result"]
        payload = make_payload()
        payload["regulatory_dataset"] = dataset
        payload["dataset_acknowledgement"]["dataset_fingerprint_sha256"] = dataset["dataset_fingerprint_sha256"]
        radio = payload["radios"][0]
        radio.update({
            "band": "5GHz",
            "supported_channels": [36, 40],
            "supported_channel_widths_mhz": [20],
            "current_channel": 36,
            "current_channel_width_mhz": 20,
            "dfs_supported": False,
        })
        result = run("radio_capability_regulatory_channel_planner", payload)["result"]
        self.assertEqual(result["radios"][0]["eligible_candidate_count"], 0)
        self.assertGreater(result["radios"][0]["rejected_reason_counts"]["radio_does_not_support_dfs"], 0)

        radio["dfs_supported"] = True
        radio["dfs_channel_states"] = [{
            "channel": 36, "status": "non_occupancy_period", "observed_at": _NOW.isoformat(),
        }, {
            "channel": 40, "status": "cac_required", "observed_at": _NOW.isoformat(),
        }]
        result = run("radio_capability_regulatory_channel_planner", payload)["result"]
        self.assertEqual(result["radios"][0]["eligible_candidate_count"], 1)
        recommendation = result["radios"][0]["recommended_configuration"]
        self.assertEqual(recommendation["channel"], 40)
        candidate = result["radios"][0]["eligible_candidates"][0]
        self.assertTrue(candidate["requires_dfs_cac_before_activation"])

        radio["dfs_channel_states"][1]["observed_at"] = (_NOW - timedelta(days=20)).isoformat()
        result = run("radio_capability_regulatory_channel_planner", payload)["result"]
        self.assertEqual(result["radios"][0]["eligible_candidate_count"], 0)
        self.assertIn("fresh_dfs_channel_state_required", result["radios"][0]["rejected_reason_counts"])

    def test_f207_requires_afc_support_active_location_scoped_grant_and_channel(self):
        raw = copy.deepcopy(_RAW_DATASET)
        raw["rules"][0]["device_classes"] = ["SP"]
        raw["rules"][0]["afc_required"] = True
        dataset = validate_regulatory_dataset(raw)["result"]
        payload = make_payload()
        payload["regulatory_dataset"] = dataset
        payload["dataset_acknowledgement"]["dataset_fingerprint_sha256"] = dataset["dataset_fingerprint_sha256"]
        radio = payload["radios"][0]
        radio["device_class"] = "SP"
        radio["afc_supported"] = True
        result = run("radio_capability_regulatory_channel_planner", payload)["result"]
        self.assertEqual(result["radios"][0]["eligible_candidate_count"], 0)
        self.assertIn("active_afc_grant_required", result["radios"][0]["rejected_reason_counts"])

        radio["afc_grant"] = {
            "grant_id": "afc-grant-01",
            "status": "active",
            "expires_at": (_NOW + timedelta(days=1)).isoformat(),
            "channel_numbers": [5],
            "maximum_eirp_dbm": 15,
            "installation_reference": "hq-building-a",
            "jurisdiction": "AU",
        }
        result = run("radio_capability_regulatory_channel_planner", payload)["result"]
        self.assertGreater(result["radios"][0]["eligible_candidate_count"], 0)
        self.assertLessEqual(result["radios"][0]["recommended_configuration"]["proposed_eirp_dbm"], 15)

        radio["afc_grant"]["installation_reference"] = "different-building"
        with self.assertRaisesRegex(ValueError, "not scoped to this installation"):
            run("radio_capability_regulatory_channel_planner", payload)

    def test_f207_marks_stale_controller_capabilities_for_review(self):
        payload = make_payload()
        payload["radios"][0]["capabilities_observed_at"] = (_NOW - timedelta(days=20)).isoformat()
        result = run("radio_capability_regulatory_channel_planner", payload)["result"]
        self.assertEqual(result["status"], "no_eligible_radios")
        self.assertEqual(result["radios"][0]["status"], "review_required")
        self.assertEqual(result["stale_capability_radio_count"], 1)

    def test_f207_rejects_site_jurisdiction_capability_source_and_bad_channels(self):
        cases = []
        payload = make_payload()
        payload["radios"][0]["site_id"] = "branch"
        cases.append((payload, "must match the requested site"))
        payload = make_payload()
        payload["radios"][0]["jurisdiction"] = "US"
        cases.append((payload, "must match the reviewed regulatory dataset"))
        payload = make_payload()
        payload["radios"][0]["capability_source"] = "operator"
        cases.append((payload, "controller or agent"))
        payload = make_payload()
        payload["radios"][0]["supported_channels"] = [234]
        cases.append((payload, "outside the supported 6GHz"))
        payload = make_payload()
        payload["radios"][0]["supported_channel_widths_mhz"] = [25]
        cases.append((payload, "not a supported channel width"))
        for candidate, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                run("radio_capability_regulatory_channel_planner", candidate)

    def test_f207_rejects_expired_dataset_stale_review_and_unsupported_rule_ambiguity(self):
        payload = make_payload()
        payload["regulatory_dataset"]["status"] = "expired"
        with self.assertRaisesRegex(ValueError, "status validated"):
            run("radio_capability_regulatory_channel_planner", payload)

        payload = make_payload()
        payload["dataset_acknowledgement"]["reviewed_at"] = (_NOW - timedelta(days=120)).isoformat()
        with self.assertRaisesRegex(ValueError, "older than 90 days"):
            run("radio_capability_regulatory_channel_planner", payload)

        payload = make_payload()
        ambiguous_rule = copy.deepcopy(payload["regulatory_dataset"]["rules"][0])
        ambiguous_rule["rule_id"] = "second-matching-rule"
        payload["regulatory_dataset"]["rules"].append(ambiguous_rule)
        canonical = {
            "authority_allowlist_version": payload["regulatory_dataset"]["authority_allowlist_version"],
            "jurisdiction": payload["regulatory_dataset"]["jurisdiction"],
            "dataset_id": payload["regulatory_dataset"]["dataset_id"],
            "version": payload["regulatory_dataset"]["version"],
            "regulator": payload["regulatory_dataset"]["regulator"],
            "retrieved_at": payload["regulatory_dataset"]["retrieved_at"],
            "effective_from": payload["regulatory_dataset"]["effective_from"],
            "effective_to": payload["regulatory_dataset"]["effective_to"],
            "sources": payload["regulatory_dataset"]["sources"],
            "rules": sorted(payload["regulatory_dataset"]["rules"], key=lambda item: item["rule_id"]),
        }
        import hashlib
        import json
        payload["regulatory_dataset"]["dataset_fingerprint_sha256"] = hashlib.sha256(
            json.dumps(canonical, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
        ).hexdigest()
        payload["dataset_acknowledgement"]["dataset_fingerprint_sha256"] = payload["regulatory_dataset"]["dataset_fingerprint_sha256"]
        result = run("radio_capability_regulatory_channel_planner", payload)["result"]
        self.assertEqual(result["radios"][0]["eligible_candidate_count"], 0)
        self.assertGreater(result["radios"][0]["overlapping_rule_ambiguity_count"], 0)


if __name__ == "__main__":
    unittest.main()
