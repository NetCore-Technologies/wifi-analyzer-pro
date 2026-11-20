"""Integration tests for pinned-TLS scheduled report webhook delivery."""
from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from wifi_analyzer_backend.feature_plugins.feature_182_router_audit_report_bundle_builder import run as build_report
from wifi_analyzer_backend.feature_plugins.feature_188_router_scheduled_report_job_intake import run as prepare_job
from wifi_analyzer_backend.report_worker import MAX_RESPONSE_BYTES, RouterReportWebhookWorker
from wifi_analyzer_backend.router_adapters.report_job_store import RouterReportJobStore

NOW = datetime(2026, 11, 20, 10, 0, tzinfo=timezone.utc)
DUE = NOW + timedelta(minutes=1)
SECRET = "worker-test-signing-secret-with-more-than-thirty-two-bytes"
WEBHOOK = {
    "endpoint": "https://hooks.example.net/router/events",
    "allowed_hosts": ["hooks.example.net"],
    "key_id": "office-webhook-v1",
    "signing_secret": SECRET,
}


def prepared_job(occurrence="a" * 64):
    bundle = build_report({
        "report_id": "weekly-office",
        "title": "Weekly office report",
        "generated_at": NOW.isoformat(),
        "sources": [{
            "source_id": "office-health",
            "source_type": "router_fleet_health_audit",
            "result": {
                "status": "audited",
                "summary": {"router_count": 1, "warning_count": 1},
                "routers": [{
                    "router_id": "router-1",
                    "site_id": "office",
                    "findings": [{
                        "code": "resource.cpu_high", "severity": "warning",
                        "resource_type": "router", "resource_id": "router-1",
                        "observed": 91, "threshold": 85,
                    }],
                }],
            },
        }],
    })
    return prepare_job({
        "schedule_id": "daily-office", "occurrence_id": occurrence,
        "scheduled_at": DUE.isoformat(), "report_bundle": bundle, "max_attempts": 3,
    })


class FakeConnection:
    def __init__(
        self, host, peer_ip, timeout, *, status=202, redirected=False,
        response_bytes=32, tls_version="TLSv1.3", tls_verified=True,
        hostname_verified=True, on_post=None,
    ):
        self.host = host
        self.peer_ip = peer_ip
        self.connected_port = 443
        self.tls_version = tls_version
        self.tls_verified = tls_verified
        self.hostname_verified = hostname_verified
        self.status = status
        self.redirected = redirected
        self.response_bytes = response_bytes
        self.on_post = on_post
        self.requests = []
        self.closed = False

    def post(self, endpoint, headers, body, *, max_response_bytes):
        self.requests.append({
            "endpoint": endpoint, "headers": dict(headers),
            "body": body, "max_response_bytes": max_response_bytes,
        })
        if self.on_post:
            self.on_post()
        return {
            "status": self.status, "redirected": self.redirected,
            "response_bytes": self.response_bytes,
        }

    def close(self):
        self.closed = True


class RouterReportWebhookWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = RouterReportJobStore(Path(self.temp.name) / "jobs.sqlite3")
        self.store.enqueue(prepared_job(), now=NOW)
        self.clock_value = DUE
        self.connections = []
        self.addresses = ["1.1.1.1", "2606:4700:4700::1111"]
        self.next_status = 202
        self.next_redirect = False
        self.next_response_bytes = 32
        self.next_tls_verified = True
        self.next_hostname_verified = True
        self.on_post = None

        def factory(host, peer_ip, timeout):
            connection = FakeConnection(
                host, peer_ip, timeout,
                status=self.next_status, redirected=self.next_redirect,
                response_bytes=self.next_response_bytes,
                tls_verified=self.next_tls_verified,
                hostname_verified=self.next_hostname_verified,
                on_post=self.on_post,
            )
            self.connections.append(connection)
            return connection

        self.worker = RouterReportWebhookWorker(
            self.store, "worker-test",
            resolver=lambda _host: list(self.addresses),
            connection_factory=factory, clock=lambda: self.clock_value,
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_delivers_signed_report_and_completes_only_after_2xx(self):
        result = self.worker.run_once(WEBHOOK, now=DUE)
        self.assertEqual(result["claimed_count"], 1)
        self.assertEqual(result["delivered_count"], 1)
        delivered = result["jobs"][0]
        self.assertEqual(delivered["status"], "completed")
        self.assertEqual(delivered["http_status"], 202)
        self.assertEqual(delivered["report_id"], "weekly-office")
        self.assertEqual(delivered["event_count"], 1)
        self.assertEqual(self.store.summary()["counts_by_status"]["completed"], 1)
        request = self.connections[0].requests[0]
        self.assertEqual(request["endpoint"], WEBHOOK["endpoint"])
        self.assertEqual(request["headers"]["Idempotency-Key"], delivered["idempotency_key"])
        self.assertTrue(request["headers"]["X-WiFiAnalyzer-Signature"].startswith("v1="))
        self.assertTrue(self.connections[0].closed)
        self.assertNotIn(SECRET, str(self.store.get(delivered["job_id"])))
        self.assertNotIn(SECRET, request["body"])

    def test_does_not_resolve_or_connect_when_no_jobs_are_due(self):
        empty_store = RouterReportJobStore(Path(self.temp.name) / "empty.sqlite3")
        worker = RouterReportWebhookWorker(
            empty_store, "worker-empty",
            resolver=lambda _host: self.fail("DNS must not be queried for an empty queue"),
            connection_factory=lambda *_args: self.fail("No socket may be opened"),
            clock=lambda: DUE,
        )
        result = worker.run_once(WEBHOOK, now=DUE)
        self.assertEqual(result["claimed_count"], 0)
        self.assertEqual(result["delivered_count"], 0)

    def test_rejects_mixed_public_private_dns_before_connecting(self):
        self.addresses = ["1.1.1.1", "10.0.0.8"]
        result = self.worker.run_once(WEBHOOK, now=DUE)
        self.assertEqual(self.connections, [])
        self.assertEqual(result["jobs"][0]["error_code"], "dns_policy_blocked")
        self.assertEqual(self.store.summary()["counts_by_status"]["retry_wait"], 1)

    def test_rejects_peer_outside_the_pinned_dns_answer_set(self):
        worker = RouterReportWebhookWorker(
            self.store, "worker-peer", resolver=lambda _host: ["1.1.1.1"],
            connection_factory=lambda host, _ip, timeout: FakeConnection(host, "8.8.8.8", timeout),
            clock=lambda: self.clock_value,
        )
        result = worker.run_once(WEBHOOK, now=DUE)
        self.assertEqual(result["jobs"][0]["error_code"], "egress_policy_blocked")
        self.assertEqual(self.store.summary()["counts_by_status"]["retry_wait"], 1)

    def test_requires_verified_tls_before_preparing_or_sending(self):
        self.next_tls_verified = False
        result = self.worker.run_once(WEBHOOK, now=DUE)
        self.assertEqual(result["jobs"][0]["error_code"], "egress_policy_blocked")
        self.assertEqual(self.connections[0].requests, [])

    def test_requires_hostname_verification_before_preparing_or_sending(self):
        self.next_hostname_verified = False
        result = self.worker.run_once(WEBHOOK, now=DUE)
        self.assertEqual(result["jobs"][0]["error_code"], "egress_policy_blocked")
        self.assertEqual(self.connections[0].requests, [])

    def test_refuses_redirects_without_following_them(self):
        self.next_status = 302
        self.next_redirect = True
        result = self.worker.run_once(WEBHOOK, now=DUE)
        self.assertEqual(result["jobs"][0]["error_code"], "redirect_refused")
        self.assertEqual(len(self.connections[0].requests), 1)
        self.assertEqual(self.store.summary()["counts_by_status"]["retry_wait"], 1)

    def test_non_2xx_response_retries_with_a_stable_idempotency_key(self):
        self.next_status = 503
        failed = self.worker.run_once(WEBHOOK, now=DUE)
        self.assertEqual(failed["jobs"][0]["error_code"], "delivery_http_error")
        first_key = self.connections[0].requests[0]["headers"]["Idempotency-Key"]
        self.clock_value = DUE + timedelta(seconds=31)
        self.next_status = 204
        retried = self.worker.run_once(WEBHOOK, now=self.clock_value)
        self.assertEqual(retried["jobs"][0]["status"], "completed")
        self.assertEqual(self.connections[1].requests[0]["headers"]["Idempotency-Key"], first_key)

    def test_rejects_oversized_responses(self):
        self.next_response_bytes = MAX_RESPONSE_BYTES + 1
        result = self.worker.run_once(WEBHOOK, now=DUE)
        self.assertEqual(result["jobs"][0]["error_code"], "delivery_response_too_large")
        self.assertEqual(self.store.summary()["counts_by_status"]["retry_wait"], 1)

    def test_bad_configuration_is_rejected_before_claiming_jobs(self):
        invalid = {**WEBHOOK, "endpoint": "https://hooks.example.net.attacker.test/events"}
        with self.assertRaisesRegex(ValueError, "exact host allowlist"):
            self.worker.run_once(invalid, now=DUE)
        with self.assertRaisesRegex(ValueError, "32 to 4096"):
            self.worker.run_once({**WEBHOOK, "signing_secret": "too-short"}, now=DUE)
        self.assertEqual(self.store.summary()["counts_by_status"]["pending"], 1)
        self.assertEqual(self.connections, [])

    def test_lease_expiry_after_remote_acceptance_is_reported_as_lease_lost(self):
        self.on_post = lambda: setattr(self, "clock_value", DUE + timedelta(minutes=10))
        result = self.worker.run_once(WEBHOOK, now=DUE)
        self.assertEqual(result["jobs"][0]["status"], "lease_lost")
        self.assertEqual(self.store.summary()["counts_by_status"]["completed"], 0)
        self.assertEqual(len(self.connections[0].requests), 1)

    def test_rejects_unbounded_worker_settings(self):
        with self.assertRaisesRegex(ValueError, "timeout_seconds"):
            RouterReportWebhookWorker(self.store, "worker-bad", timeout_seconds=60)
        with self.assertRaisesRegex(ValueError, "max_jobs"):
            self.worker.run_once(WEBHOOK, max_jobs=MAX_WORKER_BATCH + 1, now=DUE)
        self.assertEqual(self.store.summary()["counts_by_status"]["pending"], 1)

    def test_signing_material_is_never_persisted_or_returned(self):
        result = self.worker.run_once(WEBHOOK, now=DUE)
        rendered = str(result) + str(self.store.get(result["jobs"][0]["job_id"]))
        self.assertNotIn(SECRET, rendered)
        self.assertNotIn("signing_secret", rendered)
        self.assertEqual(result["jobs"][0]["status"], "completed")


if __name__ == "__main__":
    unittest.main()
