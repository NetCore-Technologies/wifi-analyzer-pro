"""Tests for the persistent site-scoped trusted AP inventory."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from wifi_analyzer_backend.trusted_ap_store import TrustedAccessPointStore


class TrustedAccessPointStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "state" / "trusted.sqlite3"
        self.store = TrustedAccessPointStore(self.path)

    def test_site_isolation_deduplication_and_durability(self):
        first = self.store.add("head-office", "CorpWiFi", "aa:bb:cc:dd:ee:ff")
        duplicate = self.store.add("head-office", "CorpWiFi", "AA-BB-CC-DD-EE-FF")
        other_site = self.store.add("branch", "CorpWiFi", "00:11:22:33:44:55")
        self.assertTrue(first["created"])
        self.assertFalse(duplicate["created"])
        self.assertTrue(other_site["created"])
        self.assertEqual(len(self.store.list_for_site("head-office")), 1)
        self.assertEqual(self.store.list_for_site("head-office")[0]["bssid"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(self.store.site_ids(), ["branch", "head-office"])
        reopened = TrustedAccessPointStore(self.path)
        self.assertEqual(len(reopened.list_for_site("head-office")), 1)
        self.assertEqual(len(reopened.list_for_site("branch")), 1)

    def test_remove_is_scoped_and_idempotent(self):
        self.store.add("head-office", "CorpWiFi", "AA:BB:CC:DD:EE:FF")
        self.assertFalse(self.store.remove("branch", "CorpWiFi", "AA:BB:CC:DD:EE:FF"))
        self.assertTrue(self.store.remove("head-office", "CorpWiFi", "AA:BB:CC:DD:EE:FF"))
        self.assertFalse(self.store.remove("head-office", "CorpWiFi", "AA:BB:CC:DD:EE:FF"))
        self.assertEqual(self.store.list_for_site("head-office"), [])

    def test_validates_site_ssid_and_bssid(self):
        for site_id in ("", "../etc", "has spaces", "x" * 129):
            with self.subTest(site_id=site_id), self.assertRaises(ValueError):
                self.store.add(site_id, "Corp", "AA:BB:CC:DD:EE:FF")
        for ssid in ("", "bad\nssid", "é" * 17):
            with self.subTest(ssid=ssid), self.assertRaises(ValueError):
                self.store.add("hq", ssid, "AA:BB:CC:DD:EE:FF")
        for bssid in ("bad", "AA:BB:CC:DD:EE", "00:11:22:33:44:GG", "FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
            with self.subTest(bssid=bssid), self.assertRaises(ValueError):
                self.store.add("hq", "Corp", bssid)

    def test_enforces_per_site_and_per_ssid_inventory_limits(self):
        for index in range(64):
            octets = [index >> 24 & 255, index >> 16 & 255, index >> 8 & 255, index & 255]
            bssid = "02:00:%02X:%02X:%02X:%02X" % tuple(octets)
            self.store.add("hq", "Corp", bssid)
        with self.assertRaisesRegex(ValueError, "64 trusted BSSIDs"):
            self.store.add("hq", "Corp", "02:00:00:00:00:FF")
