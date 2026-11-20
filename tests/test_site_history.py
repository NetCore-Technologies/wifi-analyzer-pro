"""Tests for durable, bounded site discovery history storage."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from wifi_analyzer_backend.site_history import DuplicateSnapshotError, SiteHistoryStore


def snapshot(site_id: str, captured_at: str) -> dict:
    return {
        "site_id": site_id,
        "captured_at": captured_at,
        "access_points": [{"ap_id": f"{site_id}-ap"}],
        "links": [],
    }


class SiteHistoryStoreTests(unittest.TestCase):
    def test_snapshots_survive_store_recreation_and_can_be_read_back(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state" / "history.sqlite3"
            first = SiteHistoryStore(path)
            saved = first.record(snapshot("home", "2026-11-20T10:00:00+00:00"))
            reopened = SiteHistoryStore(path)
            detail = reopened.get(saved["id"])
            self.assertEqual(detail["snapshot"]["site_id"], "home")
            self.assertEqual(detail["access_point_count"], 1)
            self.assertEqual(reopened.list(site_id="home")[0]["id"], saved["id"])

    def test_per_site_retention_keeps_only_the_newest_snapshots(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SiteHistoryStore(Path(directory) / "history.sqlite3", max_per_site=2)
            saved = [
                store.record(snapshot("home", f"2026-11-20T10:0{minute}:00+00:00"))
                for minute in range(3)
            ]
            remaining = store.list(site_id="home", limit=10)
            self.assertEqual([item["id"] for item in remaining], [saved[2]["id"], saved[1]["id"]])
            self.assertIsNone(store.get(saved[0]["id"]))

    def test_duplicate_site_timestamp_is_rejected_and_pagination_is_stable(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SiteHistoryStore(Path(directory) / "history.sqlite3", max_per_site=10)
            first = store.record(snapshot("home", "2026-11-20T10:00:00+00:00"))
            store.record(snapshot("branch", "2026-11-20T10:00:00+00:00"))
            with self.assertRaises(DuplicateSnapshotError):
                store.record(snapshot("home", "2026-11-20T10:00:00+00:00"))
            second = store.record(snapshot("home", "2026-11-20T10:01:00+00:00"))
            page = store.list(site_id="home", limit=1)
            self.assertEqual(page[0]["id"], second["id"])
            self.assertEqual(store.list(site_id="home", before_id=second["id"], limit=1)[0]["id"], first["id"])

    def test_storage_rejects_oversized_and_expired_snapshots(self):
        with tempfile.TemporaryDirectory() as directory:
            store = SiteHistoryStore(Path(directory) / "history.sqlite3", retention_days=1)
            with self.assertRaisesRegex(ValueError, "retention window"):
                store.record(snapshot("home", "2020-01-01T00:00:00+00:00"))
            huge = snapshot("home", "2026-11-20T10:00:00+00:00")
            huge["access_points"] = [{"ap_id": "a", "label": "x" * 600000}]
            with self.assertRaisesRegex(ValueError, "storage limit"):
                store.record(huge)


if __name__ == "__main__":
    unittest.main()
