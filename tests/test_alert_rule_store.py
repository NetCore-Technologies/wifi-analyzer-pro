"""Tests for site-scoped alert policies and persistent incident lifecycle."""
from __future__ import annotations

import os
import stat
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from wifi_analyzer_backend.alert_rule_store import (
    AlertRuleStore, diagnostic_observations, scan_observations,
)


class AlertRuleStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = AlertRuleStore(Path(self.temp.name) / "state" / "alerts.sqlite3")
        self.now = datetime.now(timezone.utc).replace(microsecond=0)

    def rule(self, **overrides):
        value = {
            "name": "Weak Wi-Fi signal",
            "metric": "minimum_rssi_dbm",
            "operator": "lt",
            "threshold": -75,
            "recovery_threshold": -70,
            "severity": "warning",
            "enabled": True,
            "hold_for_seconds": 0,
            "dedupe_window_seconds": 900,
            "quiet_start": None,
            "quiet_end": None,
            "timezone": "UTC",
        }
        value.update(overrides)
        return value

    def test_rejects_database_directory_as_a_file_path(self):
        directory = Path(self.temp.name) / "not-a-database.sqlite3"
        directory.mkdir()
        with self.assertRaisesRegex(ValueError, "regular non-symbolic-link"):
            AlertRuleStore(directory).list_rules("head-office")

    @unittest.skipIf(os.name == "nt", "POSIX file mode assertions")
    def test_database_and_new_state_directory_are_owner_only(self):
        self.store.list_rules("head-office")
        self.assertEqual(stat.S_IMODE(self.path.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_rule_lifecycle_is_durable_and_site_scoped(self):
        saved = self.store.save_rule("head-office", self.rule())
        other = self.store.save_rule("branch", self.rule(name="Branch signal"))
        reopened = AlertRuleStore(self.store.path)
        self.assertEqual(len(reopened.list_rules("head-office")), 1)
        self.assertEqual(reopened.list_rules("head-office")[0]["rule_id"], saved["rule_id"])
        self.assertNotEqual(saved["rule_id"], other["rule_id"])
        self.assertTrue(reopened.delete_rule("head-office", saved["rule_id"]))
        self.assertFalse(reopened.delete_rule("head-office", saved["rule_id"]))
        self.assertEqual(reopened.list_rules("head-office"), [])

    def test_threshold_creates_one_incident_and_deduplicates_repeated_breaches(self):
        rule = self.store.save_rule("head-office", self.rule())
        first = self.store.evaluate("head-office", {"minimum_rssi_dbm": -82}, observed_at=self.now.isoformat())
        second = self.store.evaluate("head-office", {"minimum_rssi_dbm": -85}, observed_at=(self.now + timedelta(minutes=1)).isoformat())
        self.assertEqual(len(first["created_event_ids"]), 1)
        self.assertEqual(second["created_event_ids"], [])
        self.assertEqual(len(second["updated_event_ids"]), 1)
        event = self.store.list_events("head-office")[0]
        self.assertEqual(event["status"], "active")
        self.assertEqual(event["occurrence_count"], 2)
        self.assertEqual(event["dedupe_suppressed_count"], 1)
        self.assertEqual(event["rule_id"], rule["rule_id"])

    def test_recovery_threshold_resolves_without_treating_missing_data_as_healthy(self):
        self.store.save_rule("head-office", self.rule())
        self.store.evaluate("head-office", {"minimum_rssi_dbm": -82}, observed_at=self.now.isoformat())
        missing = self.store.evaluate("head-office", {"network_count": 10}, observed_at=(self.now + timedelta(minutes=1)).isoformat())
        self.assertEqual(missing["resolved_event_ids"], [])
        resolved = self.store.evaluate("head-office", {"minimum_rssi_dbm": -68}, observed_at=(self.now + timedelta(minutes=2)).isoformat())
        self.assertEqual(len(resolved["resolved_event_ids"]), 1)
        self.assertEqual(self.store.list_events("head-office")[0]["status"], "resolved")

    def test_out_of_order_observations_do_not_rewind_incident_state(self):
        self.store.save_rule("head-office", self.rule())
        later = self.now + timedelta(minutes=2)
        first = self.store.evaluate(
            "head-office", {"minimum_rssi_dbm": -82}, observed_at=later.isoformat(),
        )
        event_id = first["created_event_ids"][0]
        older = self.store.evaluate(
            "head-office",
            {"minimum_rssi_dbm": -65},
            observed_at=(self.now + timedelta(minutes=1)).isoformat(),
        )
        self.assertEqual(older["out_of_order_rule_ids"], [self.store.list_rules("head-office")[0]["rule_id"]])
        self.assertEqual(older["resolved_event_ids"], [])
        event = self.store.list_events("head-office")[0]
        self.assertEqual(event["event_id"], event_id)
        self.assertEqual(event["status"], "active")
        self.assertEqual(event["observed_value"], -82)

    def test_hold_time_requires_sustained_breach(self):
        self.store.save_rule("head-office", self.rule(hold_for_seconds=120))
        first = self.store.evaluate("head-office", {"minimum_rssi_dbm": -82}, observed_at=self.now.isoformat())
        second = self.store.evaluate("head-office", {"minimum_rssi_dbm": -83}, observed_at=(self.now + timedelta(seconds=60)).isoformat())
        third = self.store.evaluate("head-office", {"minimum_rssi_dbm": -84}, observed_at=(self.now + timedelta(seconds=121)).isoformat())
        self.assertEqual(len(first["pending_rule_ids"]), 1)
        self.assertEqual(len(second["pending_rule_ids"]), 1)
        self.assertEqual(len(third["created_event_ids"]), 1)

    def test_acknowledgement_persists_until_the_incident_recovers(self):
        self.store.save_rule("head-office", self.rule())
        created = self.store.evaluate("head-office", {"minimum_rssi_dbm": -82})
        event_id = created["created_event_ids"][0]
        acknowledged = self.store.acknowledge("head-office", event_id, "netadmin")
        self.assertEqual(acknowledged["status"], "acknowledged")
        self.assertEqual(acknowledged["acknowledged_by"], "netadmin")
        still_breached = self.store.evaluate("head-office", {"minimum_rssi_dbm": -84})
        self.assertEqual(still_breached["updated_event_ids"], [event_id])
        self.assertEqual(self.store.list_events("head-office")[0]["status"], "acknowledged")

    def test_quiet_hours_are_timezone_aware_and_overnight(self):
        rule = self.store.save_rule("head-office", self.rule(
            quiet_start="22:00", quiet_end="07:00", timezone="Australia/Sydney",
        ))
        summer_quiet = datetime(2026, 1, 1, 13, 0, tzinfo=timezone.utc)  # midnight Sydney daylight time
        result = self.store.evaluate("head-office", {"minimum_rssi_dbm": -82}, observed_at=summer_quiet.isoformat())
        event = self.store.list_events("head-office")[0]
        self.assertTrue(event["quiet_hours_active"])
        self.assertEqual(event["delivery_status"], "not_configured")
        self.assertEqual(rule["timezone"], "Australia/Sydney")

    def test_disabled_rule_resolves_an_active_incident(self):
        rule = self.store.save_rule("head-office", self.rule())
        self.store.evaluate("head-office", {"minimum_rssi_dbm": -82})
        self.store.save_rule("head-office", self.rule(enabled=False), rule_id=rule["rule_id"])
        self.assertEqual(self.store.list_events("head-office")[0]["status"], "resolved")

    def test_editing_rule_resolves_old_incident_and_restarts_hold_state(self):
        rule = self.store.save_rule("head-office", self.rule())
        self.store.evaluate("head-office", {"minimum_rssi_dbm": -82}, observed_at=self.now.isoformat())
        updated = self.store.save_rule(
            "head-office",
            self.rule(threshold=-85, hold_for_seconds=60),
            rule_id=rule["rule_id"],
        )
        self.assertEqual(updated["threshold"], -85)
        self.assertEqual(self.store.list_events("head-office")[0]["status"], "resolved")
        next_observation = self.store.evaluate(
            "head-office",
            {"minimum_rssi_dbm": -90},
            observed_at=(self.now + timedelta(seconds=30)).isoformat(),
        )
        self.assertEqual(len(next_observation["pending_rule_ids"]), 1)
        self.assertEqual(next_observation["created_event_ids"], [])

    def test_acknowledging_a_resolved_incident_is_rejected(self):
        self.store.save_rule("head-office", self.rule())
        created = self.store.evaluate("head-office", {"minimum_rssi_dbm": -82})
        event_id = created["created_event_ids"][0]
        self.store.evaluate("head-office", {"minimum_rssi_dbm": -60})
        with self.assertRaisesRegex(ValueError, "only active alerts"):
            self.store.acknowledge("head-office", event_id, "netadmin")

    def test_validation_rejects_bad_rule_values_and_observations(self):
        invalid = [
            self.rule(metric=["minimum_rssi_dbm"]),
            self.rule(operator=["lt"]),
            self.rule(severity=["critical"]),
            self.rule(metric="made_up"),
            self.rule(operator="approx"),
            self.rule(threshold=float("nan")),
            self.rule(quiet_start="25:00", quiet_end="07:00"),
            self.rule(quiet_start="22:00", quiet_end=None),
            self.rule(recovery_threshold=-90),
            self.rule(hold_for_seconds=True),
            self.rule(timezone="Mars/Olympus"),
        ]
        for rule in invalid:
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                self.store.save_rule("head-office", rule)
        with self.assertRaisesRegex(ValueError, "finite number"):
            self.store.evaluate("head-office", {"minimum_rssi_dbm": float("inf")})

    def test_empty_scan_does_not_create_zero_network_measurements(self):
        values = scan_observations([])
        self.assertIsNone(values["network_count"])
        self.assertIsNone(values["open_network_count"])
        self.assertIsNone(values["minimum_rssi_dbm"])

    def test_open_network_and_measured_diagnostic_extraction(self):
        values = scan_observations([
            {"ssid": "open", "security": "Open", "rssi": -40},
            {"ssid": "secured", "security": "WPA2", "rssi": -61},
            {"ssid": "unknown", "rssi": None},
        ])
        self.assertEqual(values["network_count"], 3)
        self.assertEqual(values["open_network_count"], 1)
        self.assertEqual(values["minimum_rssi_dbm"], -61)
        self.assertEqual(diagnostic_observations({
            "gateway_probe_status": "measured",
            "latency_ms": 22,
            "packet_loss_pct": 0,
            "jitter_ms": 3,
            "dns_resolution_status": "not_configured",
        })["dns_resolution_ms"], None)
