"""Tests for durable, append-only two-person RF change approvals."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from wifi_analyzer_backend.rf_change_approval_store import RfChangeApprovalStore


def packet_for(site_id="head-office", requester="request.user"):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    packet = {
        "schema_version": 1,
        "workflow": "two_person_rf_change_approval",
        "site_id": site_id,
        "adapter_id": "openwrt",
        "requested_by": requester,
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=2)).isoformat(),
        "required_approvals": 2,
        "dataset": {"fingerprint_sha256": "a" * 64},
        "changes": [{"radio_id": "radio-1", "before": {"channel": 36}, "after": {"channel": 40}}],
        "change_count": 1,
        "execution": {"status": "blocked_no_write_capable_adapter", "applied": False},
    }
    encoded = json.dumps(packet, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
    return {"status": "approval_packet_created", "packet": packet, "packet_sha256": hashlib.sha256(encoded).hexdigest()}


class RfChangeApprovalStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "rf-change-approvals.sqlite3"
        self.store = RfChangeApprovalStore(self.path, max_per_site=3)
        self.created = self.store.create("head-office", packet_for())

    def test_request_is_durable_and_packet_integrity_is_verified(self):
        reopened = RfChangeApprovalStore(self.path)
        loaded = reopened.get("head-office", self.created["request_id"])
        self.assertEqual(loaded["status"], "pending_approval")
        self.assertEqual(loaded["packet"]["changes"], packet_for()["packet"]["changes"])
        self.assertFalse(loaded["execution_allowed"])

    def test_requester_cannot_approve_and_two_distinct_approvers_are_required(self):
        request_id = self.created["request_id"]
        with self.assertRaisesRegex(ValueError, "requester cannot"):
            self.store.decide("head-office", request_id, actor="request.user", decision="approve")
        one = self.store.decide("head-office", request_id, actor="approver.one", decision="approve")
        self.assertEqual(one["status"], "pending_approval")
        self.assertEqual(one["approval_count"], 1)
        two = self.store.decide("head-office", request_id, actor="approver.two", decision="approve")
        self.assertEqual(two["status"], "approved_not_applied")
        self.assertEqual(two["approval_count"], 2)
        self.assertFalse(two["execution_allowed"])

    def test_unique_approvers_rejection_terminal_and_concurrent_transition_guard(self):
        request_id = self.created["request_id"]
        self.store.decide("head-office", request_id, actor="approver.one", decision="approve")
        with self.assertRaisesRegex(ValueError, "already recorded"):
            self.store.decide("head-office", request_id, actor="approver.one", decision="approve")
        rejected = self.store.decide("head-office", request_id, actor="approver.two", decision="reject", comment="Change window denied")
        self.assertEqual(rejected["status"], "rejected")
        with self.assertRaisesRegex(ValueError, "already rejected"):
            self.store.decide("head-office", request_id, actor="approver.three", decision="approve")

    def test_cancel_is_requester_only_and_terminal(self):
        request_id = self.created["request_id"]
        with self.assertRaisesRegex(ValueError, "original requester"):
            self.store.cancel("head-office", request_id, actor="other.user")
        cancelled = self.store.cancel("head-office", request_id, actor="request.user")
        self.assertEqual(cancelled["status"], "cancelled")

    def test_expired_requests_cannot_be_created_or_approved(self):
        packet = packet_for()
        packet["packet"]["expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        encoded = json.dumps(packet["packet"], sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
        packet["packet_sha256"] = hashlib.sha256(encoded).hexdigest()
        with self.assertRaisesRegex(ValueError, "expires_at"):
            self.store.create("head-office", packet)

    def test_revoked_evidence_invalidates_pending_and_approved_requests(self):
        request_id = self.created["request_id"]
        invalidated = self.store.invalidate(
            "head-office", request_id, actor="system", reason="retained F206 dataset was revoked",
        )
        self.assertEqual(invalidated["status"], "invalidated")
        self.assertEqual(invalidated["events"][-1]["action"], "invalidated")
        with self.assertRaisesRegex(ValueError, "already invalidated"):
            self.store.decide("head-office", request_id, actor="approver.one", decision="approve")

    def test_execution_is_auditable_but_remains_blocked(self):
        request_id = self.created["request_id"]
        self.store.decide("head-office", request_id, actor="approver.one", decision="approve")
        approved = self.store.decide("head-office", request_id, actor="approver.two", decision="approve")
        blocked = self.store.record_execution_blocked(
            "head-office", request_id, actor="approver.two", reason="no write-capable adapter is registered",
        )
        self.assertEqual(approved["status"], "approved_not_applied")
        self.assertEqual(blocked["status"], "approved_not_applied")
        self.assertEqual(blocked["events"][-1]["action"], "execution_blocked")
        self.assertFalse(blocked["execution_allowed"])

    def test_site_isolation_caps_and_tamper_detection(self):
        self.assertIsNone(self.store.get("branch", self.created["request_id"]))
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.store.create("branch", packet_for("head-office"))
        self.store.create("head-office", packet_for())
        self.store.create("head-office", packet_for())
        with self.assertRaisesRegex(ValueError, "already has 3"):
            self.store.create("head-office", packet_for())
        with self.store._db() as db:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                db.execute("UPDATE rf_change_requests SET packet_json = '{}' WHERE request_id = ?",
                           (self.created["request_id"],))
        self.assertEqual(self.store.get("head-office", self.created["request_id"])["status"], "pending_approval")

    def test_invalid_decisions_and_expiry_limits_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "decision"):
            self.store.decide("head-office", self.created["request_id"], actor="approver.one", decision="maybe")
        packet = packet_for()
        packet["packet"]["expires_at"] = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
        encoded = json.dumps(packet["packet"], sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
        packet["packet_sha256"] = hashlib.sha256(encoded).hexdigest()
        with self.assertRaisesRegex(ValueError, "between 1 minute"):
            self.store.create("head-office", packet)


if __name__ == "__main__":
    unittest.main()
