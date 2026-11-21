"""Integration tests for multi-subscription pinned-TLS webhook dispatch."""
from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from wifi_analyzer_backend.webhook_delivery_store import WebhookDeliveryStore
from wifi_analyzer_backend.webhook_dispatch_worker import WebhookDispatchWorker

NOW = datetime(2026, 11, 21, 0, 0, tzinfo=timezone.utc)


def prepared(batch_id="a" * 64):
    body = json.dumps({
        "schema_version": "1.0",
        "batch_id": batch_id,
        "key_id": "office-key-v1",
        "created_at": NOW.isoformat(),
        "events": [{
            "event_id": "b" * 64,
            "event_type": "router.health",
            "severity": "warning",
            "occurred_at": NOW.isoformat(),
            "site_id": "office",
            "router_id": "router-1",
            "summary": "Router health warning",
            "attributes": {},
        }],
    }, sort_keys=True, separators=(",", ":"))
    return {
        "subscription_id": "office-alerts",
        "batch_id": batch_id,
        "event_count": 1,
        "status": "prepared",
        "endpoint": "https://hooks.example.net/router/events",
        "allowed_hosts": ["hooks.example.net"],
        "headers": {
            "Content-Type": "application/json",
            "X-WiFiAnalyzer-Key-Id": "office-key-v1",
            "X-WiFiAnalyzer-Timestamp": str(int(NOW.timestamp())),
            "X-WiFiAnalyzer-Signature": "v1=" + ("c" * 64),
            "Idempotency-Key": batch_id,
        },
        "body": body,
    }


class FakeConnection:
    def __init__(self, host, peer_ip, timeout, *, status=202, redirected=False,
                 tls_version="TLSv1.3", tls_verified=True, hostname_verified=True):
        self.host = host
        self.peer_ip = peer_ip
        self.connected_port = 443
        self.tls_version = tls_version
        self.tls_verified = tls_verified
        self.hostname_verified = hostname_verified
        self.status = status
        self.redirected = redirected
        self.closed = False
        self.requests = []

    def post(self, endpoint, headers, body, *, max_response_bytes):
        self.requests.append({
            "endpoint": endpoint, "headers": dict(headers), "body": body,
            "max_response_bytes": max_response_bytes,
        })
        return {
            "status": self.status, "redirected": self.redirected,
            "response_bytes": 32,
        }

    def close(self):
        self.closed = True


class WebhookDispatchWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = WebhookDeliveryStore(Path(self.temp.name) / "deliveries.sqlite3")
        self.store.enqueue_many([prepared()], now=NOW)
        self.connections = []
        self.peer_ip = "1.1.1.1"
        self.addresses = ["1.1.1.1", "2606:4700:4700::1111"]
        self.status = 202
        self.redirected = False
        self.tls_verified = True
        self.hostname_verified = True
        self.clock = [NOW + timedelta(seconds=2)]

        def factory(host, address, timeout):
            connection = FakeConnection(
                host, self.peer_ip, timeout, status=self.status,
                redirected=self.redirected, tls_verified=self.tls_verified,
                hostname_verified=self.hostname_verified,
            )
            self.connections.append(connection)
            return connection

        self.worker = WebhookDispatchWorker(
            self.store, "dispatch-test",
            resolver=lambda _host: list(self.addresses),
            connection_factory=factory,
            clock=lambda: self.clock[0],
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_sends_signed_envelope_and_marks_delivered_only_after_2xx(self):
        result = self.worker.run_once(now=self.clock[0], max_jobs=1)
        self.assertEqual(result["claimed_count"], 1)
        self.assertEqual(result["delivered_count"], 1)
        delivery = result["deliveries"][0]
        self.assertEqual(delivery["status"], "delivered")
        self.assertEqual(delivery["http_status"], 202)
        request = self.connections[0].requests[0]
        self.assertEqual(request["endpoint"], "https://hooks.example.net/router/events")
        self.assertEqual(request["headers"]["Idempotency-Key"], "a" * 64)
        self.assertTrue(request["headers"]["X-WiFiAnalyzer-Signature"].startswith("v1="))
        self.assertTrue(self.connections[0].closed)

    def test_private_dns_answer_blocks_before_socket_creation(self):
        self.addresses = ["1.1.1.1", "10.0.0.8"]
        result = self.worker.run_once(now=self.clock[0])
        self.assertEqual(self.connections, [])
        self.assertEqual(result["deliveries"][0]["error_code"], "dns_policy_blocked")
        self.assertEqual(self.store.summary()["counts_by_status"]["retry_wait"], 1)

    def test_peer_outside_dns_pin_is_rejected(self):
        self.peer_ip = "8.8.8.8"
        result = self.worker.run_once(now=self.clock[0])
        self.assertEqual(len(self.connections), 1)
        self.assertEqual(result["deliveries"][0]["error_code"], "egress_policy_blocked")
        self.assertEqual(self.store.summary()["counts_by_status"]["retry_wait"], 1)

    def test_unverified_tls_hostname_is_rejected(self):
        self.hostname_verified = False
        result = self.worker.run_once(now=self.clock[0])
        self.assertEqual(result["deliveries"][0]["error_code"], "egress_policy_blocked")
        self.assertEqual(self.connections[0].requests, [])

    def test_redirect_is_never_followed_and_http_errors_retry(self):
        self.redirected = True
        result = self.worker.run_once(now=self.clock[0])
        self.assertEqual(result["deliveries"][0]["error_code"], "redirect_refused")
        self.assertEqual(len(self.connections[0].requests), 1)
        self.assertEqual(self.store.summary()["counts_by_status"]["retry_wait"], 1)

    def test_successful_http_result_only_is_marked_delivered(self):
        self.status = 503
        result = self.worker.run_once(now=self.clock[0])
        self.assertEqual(result["deliveries"][0]["error_code"], "delivery_http_error")
        self.assertEqual(self.store.summary()["counts_by_status"]["retry_wait"], 1)

    def test_empty_queue_never_resolves_or_connects(self):
        empty = WebhookDeliveryStore(Path(self.temp.name) / "empty.sqlite3")
        worker = WebhookDispatchWorker(
            empty, "idle-worker",
            resolver=lambda _host: self.fail("DNS must not run for an empty queue"),
            connection_factory=lambda *_args: self.fail("socket must not open"),
            clock=lambda: self.clock[0],
        )
        self.assertEqual(worker.run_once(now=self.clock[0])["claimed_count"], 0)


if __name__ == "__main__":
    unittest.main()
