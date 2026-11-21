"""F206 tests for jurisdiction-aware regulatory source provenance."""
from __future__ import annotations

import copy
import unittest
from datetime import datetime, timedelta, timezone

from wifi_analyzer_backend.feature_plugins.registry import run

_NOW = datetime.now(timezone.utc).replace(microsecond=0)
_DATASET = {
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


class RadioRegulatoryEvidenceValidatorTests(unittest.TestCase):
    def test_f206_validates_source_linked_regulatory_dataset_and_fingerprint(self):
        result = run("radio_regulatory_evidence_validator", _DATASET)["result"]
        self.assertEqual(result["status"], "validated")
        self.assertEqual(result["jurisdiction"], "AU")
        self.assertEqual(result["provenance_status"], "allowlisted_domains")
        self.assertEqual(result["allowlisted_source_domain_count"], 1)
        self.assertEqual(result["rule_count"], 1)
        self.assertEqual(result["authority_allowlist_version"], "2026.11.21")
        self.assertEqual(result["retrieved_at"], _NOW.isoformat(timespec="seconds"))
        self.assertEqual(result["effective_from"], "2025-10-01")
        self.assertIsNone(result["effective_to"])
        self.assertEqual(result["rules"][0]["maximum_eirp_dbm"], 24)
        self.assertEqual(result["sources"][0]["content_digest_status"], "provided_not_independently_verified")
        self.assertEqual(len(result["dataset_fingerprint_sha256"]), 64)
        self.assertIn("not independently authenticated", " ".join(result["limitations"]))

    def test_f206_marks_unknown_domains_and_jurisdictions_for_review(self):
        payload = copy.deepcopy(_DATASET)
        payload["sources"][0]["source_url"] = "https://wireless.example.net/regulation.pdf"
        result = run("radio_regulatory_evidence_validator", payload)["result"]
        self.assertEqual(result["status"], "review_required")
        self.assertEqual(result["provenance_status"], "review_required")
        self.assertEqual(result["unverified_source_domains"], ["wireless.example.net"])

        payload = copy.deepcopy(_DATASET)
        payload["jurisdiction"] = "ZZ"
        result = run("radio_regulatory_evidence_validator", payload)["result"]
        self.assertEqual(result["status"], "review_required")

    def test_f206_reports_not_yet_effective_and_expired_datasets(self):
        payload = copy.deepcopy(_DATASET)
        payload["as_of"] = "2025-01-01"
        result = run("radio_regulatory_evidence_validator", payload)["result"]
        self.assertEqual(result["status"], "not_yet_effective")
        payload = copy.deepcopy(_DATASET)
        payload["effective_to"] = "2026-01-01"
        payload["sources"][0]["effective_to"] = "2026-01-01"
        payload["as_of"] = "2026-11-21"
        result = run("radio_regulatory_evidence_validator", payload)["result"]
        self.assertEqual(result["status"], "expired")

    def test_f206_rejects_untrusted_url_forms_and_missing_provenance(self):
        bad_urls = [
            "http://www.acma.gov.au/document.pdf",
            "https://user:pass@www.acma.gov.au/document.pdf",
            "https://127.0.0.1/document.pdf",
            "https://localhost/document.pdf",
            "https://www.acma.gov.au:8443/document.pdf",
            "https://bad_host.acma.gov.au/document.pdf",
        ]
        for url in bad_urls:
            payload = copy.deepcopy(_DATASET)
            payload["sources"][0]["source_url"] = url
            with self.subTest(url=url), self.assertRaises(ValueError):
                run("radio_regulatory_evidence_validator", payload)
        payload = copy.deepcopy(_DATASET)
        # Consolidated instruments can be published after an earlier effective date.
        payload["sources"][0]["published_at"] = "2026-01-01"
        payload["sources"][0]["effective_from"] = "2025-10-01"
        self.assertEqual(run("radio_regulatory_evidence_validator", payload)["result"]["status"], "validated")

        payload = copy.deepcopy(_DATASET)
        payload["retrieved_at"] = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        with self.assertRaisesRegex(ValueError, "too far in the future"):
            run("radio_regulatory_evidence_validator", payload)
        payload = copy.deepcopy(_DATASET)
        payload["sources"][0]["content_sha256"] = "not-a-digest"
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            run("radio_regulatory_evidence_validator", payload)
        payload = copy.deepcopy(_DATASET)
        payload["rules"][0]["source_references"][0]["clause"] = "non-existent clause"
        with self.assertRaisesRegex(ValueError, "not listed"):
            run("radio_regulatory_evidence_validator", payload)

    def test_f206_rejects_invalid_rules_and_duplicate_ids(self):
        cases = [
            ({"maximum_eirp_dbm": True}, "maximum_eirp_dbm"),
            ({"lower_frequency_mhz": 7000, "upper_frequency_mhz": 6000}, "lower_frequency_mhz"),
            ({"channel_widths_mhz": [25]}, "channel_widths_mhz"),
            ({"channel_numbers": [0]}, "channel_numbers"),
            ({"device_classes": ["UNKNOWN"]}, "device_classes"),
            ({"indoor_only": True, "outdoor_allowed": True}, "indoor_only"),
            ({"dfs_required": "yes"}, "restriction flags"),
        ]
        for change, message in cases:
            payload = copy.deepcopy(_DATASET)
            payload["rules"][0].update(change)
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                run("radio_regulatory_evidence_validator", payload)
        payload = copy.deepcopy(_DATASET)
        payload["rules"].append(payload["rules"][0])
        with self.assertRaisesRegex(ValueError, "rule_id values must be unique"):
            run("radio_regulatory_evidence_validator", payload)

    def test_f206_rejects_duplicate_and_unknown_source_references(self):
        payload = copy.deepcopy(_DATASET)
        payload["sources"].append(payload["sources"][0])
        with self.assertRaisesRegex(ValueError, "source_id values must be unique"):
            run("radio_regulatory_evidence_validator", payload)
        payload = copy.deepcopy(_DATASET)
        payload["rules"][0]["source_references"][0]["source_id"] = "missing"
        with self.assertRaisesRegex(ValueError, "unknown source_id"):
            run("radio_regulatory_evidence_validator", payload)
