"""Tests for immutable, site-scoped regulatory dataset version storage."""
from __future__ import annotations

import copy
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from wifi_analyzer_backend.feature_plugins.feature_206_radio_regulatory_evidence_validator import run as validate_f206
from wifi_analyzer_backend.regulatory_dataset_store import RegulatoryDatasetStore

_NOW = datetime.now(timezone.utc).replace(microsecond=0)
_SOURCE = {
    "source_id": "acma-source",
    "source_type": "licence_condition",
    "title": "ACMA test source",
    "authority": "ACMA",
    "document_reference": "TEST-LIPD",
    "revision": "test-1",
    "source_url": "https://www.acma.gov.au/licences/test",
    "published_at": "2025-10-01",
    "effective_from": "2025-10-01",
    "effective_to": None,
    "retrieved_at": _NOW.isoformat(),
    "content_sha256": "a" * 64,
    "clause_references": ["Schedule 1, item 1"],
}
_RULE = {
    "rule_id": "au-test-6ghz-lpi",
    "band": "6GHz",
    "lower_frequency_mhz": 5925,
    "upper_frequency_mhz": 6425,
    "maximum_eirp_dbm": 24,
    "maximum_eirp_density_dbm_per_mhz": 11,
    "channel_widths_mhz": [20, 40, 80],
    "channel_numbers": [5, 21, 37],
    "device_classes": ["LPI"],
    "indoor_only": True,
    "outdoor_allowed": False,
    "dfs_required": False,
    "afc_required": False,
    "source_references": [{"source_id": "acma-source", "clause": "Schedule 1, item 1"}],
}


def validated_dataset(version="v1", *, effective_to=None, regulator="Australian Communications and Media Authority"):
    payload = {
        "jurisdiction": "AU",
        "dataset_id": "au-acma-test",
        "version": version,
        "regulator": regulator,
        "retrieved_at": _NOW.isoformat(),
        "effective_from": "2025-10-01",
        "effective_to": effective_to,
        "as_of": _NOW.date().isoformat(),
        "sources": [{**_SOURCE, "effective_to": effective_to}],
        "rules": [copy.deepcopy(_RULE)],
    }
    result = validate_f206(payload)
    acknowledgement = {
        "dataset_fingerprint_sha256": result["dataset_fingerprint_sha256"],
        "reviewer_id": "netops.reviewer",
        "reviewed_at": _NOW.isoformat(),
        "acknowledged": True,
        "review_reference": "CHG-REG-001",
    }
    return result, acknowledgement


class RegulatoryDatasetStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "private-state" / "regulatory-datasets.sqlite3"
        self.store = RegulatoryDatasetStore(self.path, max_versions_per_site=2, max_dataset_bytes=128 * 1024)

    def test_saves_immutable_reviewed_version_and_reopens_with_integrity(self):
        dataset, acknowledgement = validated_dataset()
        saved = self.store.save("head-office", dataset, acknowledgement)
        self.assertTrue(saved["created"])
        self.assertEqual(saved["fingerprint_sha256"], dataset["dataset_fingerprint_sha256"])
        reopened = RegulatoryDatasetStore(self.path, max_versions_per_site=2)
        loaded = reopened.get("head-office", saved["dataset_ref"])
        self.assertEqual(loaded["dataset"], dataset)
        self.assertEqual(loaded["acknowledgement"], acknowledgement)
        self.assertIsNone(reopened.get("branch", saved["dataset_ref"]))

    def test_duplicate_same_version_is_idempotent_and_different_content_is_rejected(self):
        dataset, acknowledgement = validated_dataset()
        first = self.store.save("head-office", dataset, acknowledgement)
        retry_acknowledgement = {
            **acknowledgement,
            "reviewed_at": (_NOW + timedelta(minutes=1)).isoformat(),
        }
        second = self.store.save("head-office", dataset, retry_acknowledgement)
        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        modified, modified_ack = validated_dataset("v1", regulator="Changed regulator label")
        with self.assertRaisesRegex(ValueError, "different content or review metadata"):
            self.store.save("head-office", modified, modified_ack)

    def test_new_versions_are_retained_without_overwriting_the_previous_version(self):
        old_dataset, old_ack = validated_dataset("v1")
        new_dataset, new_ack = validated_dataset("v2")
        old = self.store.save("head-office", old_dataset, old_ack)
        new = self.store.save("head-office", new_dataset, new_ack)
        rows = self.store.list_for_site("head-office", limit=2)
        self.assertEqual({item["dataset_ref"] for item in rows}, {old["dataset_ref"], new["dataset_ref"]})
        self.assertEqual(self.store.get("head-office", old["dataset_ref"])["dataset"]["version"], "v1")
        self.assertEqual(self.store.get("head-office", new["dataset_ref"])["dataset"]["version"], "v2")

    def test_rejects_unreviewed_mutated_or_expired_datasets(self):
        dataset, acknowledgement = validated_dataset()
        unacknowledged = dict(acknowledgement, acknowledged=False)
        with self.assertRaisesRegex(ValueError, "acknowledged=true"):
            self.store.save("head-office", dataset, unacknowledged)
        bad_ack = dict(acknowledgement, dataset_fingerprint_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "exact regulatory dataset fingerprint"):
            self.store.save("head-office", dataset, bad_ack)
        modified = copy.deepcopy(dataset)
        modified["rules"][0]["maximum_eirp_dbm"] = 60
        with self.assertRaisesRegex(ValueError, "fingerprint does not match"):
            self.store.save("head-office", modified, acknowledgement)
        expired, expired_ack = validated_dataset("expired-v1", effective_to="2020-01-01")
        with self.assertRaisesRegex(ValueError, "status validated"):
            self.store.save("head-office", expired, expired_ack)

    def test_per_site_limit_does_not_overwrite_existing_versions(self):
        one, ack_one = validated_dataset("v1")
        two, ack_two = validated_dataset("v2")
        three, ack_three = validated_dataset("v3")
        self.store.save("head-office", one, ack_one)
        self.store.save("head-office", two, ack_two)
        with self.assertRaisesRegex(ValueError, "already has 2"):
            self.store.save("head-office", three, ack_three)
        self.assertEqual(len(self.store.list_for_site("head-office")), 2)

    def test_revocation_is_site_scoped_idempotent_and_keeps_the_original_content(self):
        dataset, acknowledgement = validated_dataset()
        saved = self.store.save("head-office", dataset, acknowledgement)
        self.assertFalse(self.store.revoke(
            "branch", saved["dataset_ref"], actor="netops.admin",
            reason="Wrong site dataset was imported",
        ))
        self.assertTrue(self.store.revoke(
            "head-office", saved["dataset_ref"], actor="netops.admin",
            reason="Superseded by corrected regulator revision",
        ))
        self.assertFalse(self.store.revoke(
            "head-office", saved["dataset_ref"], actor="netops.admin",
            reason="Repeat revocation is a no-op",
        ))
        loaded = self.store.get("head-office", saved["dataset_ref"])
        self.assertTrue(loaded["record"]["revoked"])
        self.assertEqual(loaded["dataset"], dataset)
        self.assertEqual(self.store.list_for_site("head-office", include_revoked=False), [])
        self.assertEqual(self.store.list_for_site("head-office")[0]["revocation_reason"],
                         "Superseded by corrected regulator revision")

    def test_rejects_invalid_site_ids_actor_reason_and_limits(self):
        dataset, acknowledgement = validated_dataset()
        with self.assertRaisesRegex(ValueError, "site_id"):
            self.store.list_for_site("../outside")
        saved = self.store.save("head-office", dataset, acknowledgement)
        with self.assertRaisesRegex(ValueError, "actor"):
            self.store.revoke("head-office", saved["dataset_ref"], actor="../bad", reason="This is a valid reason")
        with self.assertRaisesRegex(ValueError, "reason must contain"):
            self.store.revoke("head-office", saved["dataset_ref"], actor="netops.admin", reason="bad")
        with self.assertRaisesRegex(ValueError, "max_versions_per_site"):
            RegulatoryDatasetStore(self.path, max_versions_per_site=True)

    def test_reports_only_sites_with_retained_versions_and_detects_document_tampering(self):
        dataset, acknowledgement = validated_dataset()
        saved = self.store.save("head-office", dataset, acknowledgement)
        self.assertEqual(self.store.site_ids(), ["head-office"])
        with self.store._db() as db:
            db.execute("DROP TRIGGER regulatory_dataset_content_immutable")
            db.execute(
                "UPDATE regulatory_datasets SET dataset_json = ? WHERE dataset_ref = ?",
                ('{"status":"tampered"}', saved["dataset_ref"]),
            )
        with self.assertRaisesRegex(RuntimeError, "integrity verification"):
            self.store.get("head-office", saved["dataset_ref"])


if __name__ == "__main__":
    unittest.main()
