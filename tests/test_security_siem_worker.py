"""Tests for pinned-TLS, signed security audit export."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from wifi_analyzer_backend.audit_store import SecurityAuditStore
from wifi_analyzer_backend.security_siem_store import SecuritySiemStore
from wifi_analyzer_backend.security_siem_worker import (
    SecuritySiemWorker,
    _read_secret_file,
    _sign_event,
)


class FakeConnection:
    def __init__(self, host, peer_ip, timeout, *, response=None):
        self.host = host
        self.peer_ip = peer_ip
        self.timeout = timeout
        self.connected_port = 443
        self.tls_version = "TLSv1.3"
        self.tls_verified = True
        self.hostname_verified = True
        self.response = response or {
            "status": 202,
            "redirected": False,
            "response_bytes": 0,
        }
        self.requests = []
        self.closed = False

    def post(self, endpoint, headers, body, *, max_response_bytes):
        self.requests.append({
            "endpoint": endpoint,
            "headers": dict(headers),
            "body": body,
            "max_response_bytes": max_response_bytes,
        })
        return self.response

    def close(self):
        self.closed = True


class SecuritySiemWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.audit = SecurityAuditStore(root / "audit.sqlite3")
        self.store = SecuritySiemStore(root / "siem.sqlite3", retention_days=7)
        self.connections = []
        self.response = {
            "status": 202,
            "redirected": False,
            "response_bytes": 0,
        }

        def connection_factory(host, peer_ip, timeout):
            connection = FakeConnection(host, peer_ip, timeout, response=self.response)
            self.connections.append(connection)
            return connection

        self.worker = SecuritySiemWorker(
            audit_store=self.audit,
            store=self.store,
            worker_id="unit-test-siem-worker",
            resolver=lambda _host: ["8.8.8.8"],
            connection_factory=connection_factory,
            clock=lambda: self.now,
        )
        self.webhook = {
            "endpoint": "https://siem.example.com/ingest",
            "allowed_hosts": ["siem.example.com"],
            "key_id": "siem-prod-2026",
            "signing_secret": "S" * 48,
        }

    def record(self, count=1):
        events = []
        for index in range(count):
            events.append(self.audit.record(
                "auth.login.succeeded" if index % 2 == 0 else "auth.login.failed",
                actor={"id": "a" * 32, "username": "admin", "role": "owner"},
                outcome="success" if index % 2 == 0 else "failure",
                metadata={"username": "admin", "secret": "must-not-export"},
                occurred_at=self.now + timedelta(seconds=index),
            ))
        return events

    def test_successfully_exports_hash_chained_event_with_hmac_and_idempotency(self):
        event = self.record()[0]
        result = self.worker.run_once(self.webhook, max_events=20, max_jobs=2, now=self.now)

        self.assertEqual(result["source_event_count"], 1)
        self.assertEqual(result["ingested_count"], 1)
        self.assertEqual(result["claimed_count"], 1)
        self.assertEqual(result["delivered_count"], 1)
        self.assertEqual(result["failed_count"], 0)
        self.assertEqual(result["queue"]["pending_count"], 0)
        self.assertEqual(self.store.cursor_id(), event["id"])
        connection = self.connections[0]
        self.assertTrue(connection.closed)
        request = connection.requests[0]
        self.assertEqual(request["endpoint"], self.webhook["endpoint"])
        self.assertEqual(request["headers"]["X-WiFiAnalyzer-Key-Id"], self.webhook["key_id"])
        self.assertEqual(request["headers"]["Idempotency-Key"], event["event_id"])
        self.assertTrue(request["headers"]["X-WiFiAnalyzer-Signature"].startswith("sha256="))
        expected = _sign_event(
            self.webhook["signing_secret"],
            self.webhook["key_id"],
            request["headers"]["X-WiFiAnalyzer-Timestamp"],
            event["event_id"],
            request["body"],
        )
        self.assertEqual(request["headers"], expected)
        envelope = json.loads(request["body"])
        self.assertEqual(envelope["schema_version"], "1.0")
        self.assertEqual(envelope["audit_event"]["event_hash"], event["event_hash"])
        self.assertNotIn("must-not-export", request["body"])

    def test_queue_full_does_not_advance_cursor_but_existing_jobs_can_drain(self):
        one = self.record()[0]
        self.store = SecuritySiemStore(
            Path(self.temp.name) / "small-siem.sqlite3",
            retention_days=7,
            max_pending_events=1,
        )
        self.worker.store = self.store
        self.store.ingest([one], now=self.now)
        self.record()
        result = self.worker.run_once(self.webhook, max_events=20, now=self.now)
        self.assertTrue(result["queue_full"])
        self.assertEqual(self.store.cursor_id(), one["id"])
        self.assertEqual(result["delivered_count"], 1)
        self.assertEqual(self.store.summary()["pending_count"], 0)

    def test_non_public_dns_evidence_is_blocked_without_connecting(self):
        self.record()
        self.worker.resolver = lambda _host: ["10.10.10.20"]
        result = self.worker.run_once(self.webhook, now=self.now)
        self.assertEqual(result["delivered_count"], 0)
        self.assertEqual(result["failed_count"], 1)
        self.assertEqual(self.connections, [])
        self.assertEqual(self.store.list_events(status="retry_wait")[0]["last_error_code"], "egress_policy_blocked")

    def test_redirect_response_is_refused_and_retried(self):
        self.record()
        self.response = {
            "status": 302,
            "redirected": True,
            "response_bytes": 0,
        }
        result = self.worker.run_once(self.webhook, now=self.now)
        self.assertEqual(result["failed_count"], 1)
        self.assertEqual(self.store.list_events(status="retry_wait")[0]["last_error_code"], "redirect_refused")
        self.assertTrue(self.connections[0].closed)

    def test_http_failure_is_retryable_without_exposing_response_body(self):
        self.record()
        self.response = {
            "status": 503,
            "redirected": False,
            "response_bytes": 128,
        }
        result = self.worker.run_once(self.webhook, now=self.now)
        self.assertEqual(result["failed_count"], 1)
        listed = self.store.list_events(status="retry_wait")
        self.assertEqual(listed[0]["last_error_code"], "delivery_http_error")
        self.assertNotIn("response_body", listed[0])

    def test_signing_is_bound_to_key_timestamp_event_and_exact_body(self):
        secret = "K" * 48
        timestamp = self.now.isoformat()
        event_id = "b" * 32
        body = '{"type":"audit"}'
        headers = _sign_event(secret, "key-1", timestamp, event_id, body)
        message = "\n".join(("key-1", timestamp, event_id, body)).encode("utf-8")
        expected = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
        self.assertEqual(headers["X-WiFiAnalyzer-Signature"], "sha256=" + expected)
        self.assertNotEqual(
            headers["X-WiFiAnalyzer-Signature"],
            _sign_event(secret, "key-1", timestamp, event_id, body + " ")["X-WiFiAnalyzer-Signature"],
        )

    @unittest.skipIf(os.name == "nt", "POSIX secret-file permissions")
    def test_secret_file_rejects_group_access_and_symbolic_links(self):
        with tempfile.TemporaryDirectory() as directory:
            secret = Path(directory) / "siem-secret"
            secret.write_text("S" * 48 + "\n", encoding="utf-8")
            os.chmod(secret, stat.S_IRUSR | stat.S_IWUSR)
            self.assertEqual(_read_secret_file(str(secret)), "S" * 48)
            os.chmod(secret, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
            with self.assertRaisesRegex(ValueError, "group or other"):
                _read_secret_file(str(secret))
            os.chmod(secret, stat.S_IRUSR | stat.S_IWUSR)
            link = Path(directory) / "secret-link"
            link.symlink_to(secret)
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                _read_secret_file(str(link))

    def test_webhook_configuration_rejects_non_https_and_untrusted_hosts(self):
        bad = dict(self.webhook, endpoint="http://siem.example.com/ingest")
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            self.worker.run_once(bad, now=self.now)
        bad = dict(self.webhook, endpoint="https://attacker.example/ingest")
        with self.assertRaisesRegex(ValueError, "allowlist"):
            self.worker.run_once(bad, now=self.now)


if __name__ == "__main__":
    unittest.main()
