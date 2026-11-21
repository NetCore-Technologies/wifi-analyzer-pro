"""HTTP integration tests for the local account gate and feature API."""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import tempfile
import threading
import unittest
from unittest.mock import patch
from pathlib import Path
from http.client import HTTPConnection
from unittest.mock import Mock, patch

from wifi_analyzer_backend import server
from wifi_analyzer_backend.auth import AuthManager
from wifi_analyzer_backend.audit_checkpoint import verify_signed_checkpoint
from wifi_analyzer_backend.rate_limit import TokenBucketRateLimiter, DEFAULT_POLICIES
from wifi_analyzer_backend.router_adapters.health_store import RouterAgentHealthStore
from wifi_analyzer_backend.router_adapters.report_job_store import RouterReportJobStore
from wifi_analyzer_backend.feature_plugins.feature_182_router_audit_report_bundle_builder import run as build_report_bundle


class AuthenticatedApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.previous_auth = server.AUTH
        self.previous_history = server.HISTORY
        self.previous_agent_health = server.AGENT_HEALTH
        self.previous_report_jobs = server.REPORT_JOBS
        self.previous_audit = server.AUDIT
        self.previous_live_capture = server.LIVE_CAPTURE
        self.previous_webhook_deliveries = server.WEBHOOK_DELIVERIES
        self.previous_webhook_subscriptions = server.WEBHOOK_SUBSCRIPTIONS
        self.previous_rate_limiter = server.RATE_LIMITER
        self.previous_rate_policies = server.RATE_LIMIT_POLICIES
        server.RATE_LIMITER = TokenBucketRateLimiter()
        server.RATE_LIMIT_POLICIES = dict(DEFAULT_POLICIES)
        server.WEBHOOK_DELIVERIES = __import__(
            "wifi_analyzer_backend.webhook_delivery_store",
            fromlist=["WebhookDeliveryStore"],
        ).WebhookDeliveryStore(path=str(Path(self.temp.name) / "webhook-deliveries.sqlite3"))
        server.WEBHOOK_SUBSCRIPTIONS = __import__(
            "wifi_analyzer_backend.webhook_subscription_store",
            fromlist=["WebhookSubscriptionStore"],
        ).WebhookSubscriptionStore(path=str(Path(self.temp.name) / "webhook-subscriptions.sqlite3"))
        server.LIVE_CAPTURE = Mock()
        server.LIVE_CAPTURE.list_interfaces.return_value = {
            "available": True,
            "interfaces": [{"name": "eth0", "description": "1.eth0"}],
            "maximum_duration_seconds": 60,
            "maximum_packets": 1000,
            "maximum_capture_bytes": 512 * 1024,
        }
        server.LIVE_CAPTURE.status.return_value = {"capture": None}
        server.AUTH = AuthManager(path=str(Path(self.temp.name) / "auth.json"), session_ttl_seconds=300)
        server.HISTORY = __import__("wifi_analyzer_backend.site_history", fromlist=["SiteHistoryStore"]).SiteHistoryStore(path=str(Path(self.temp.name) / "history.sqlite3"))
        server.AGENT_HEALTH = RouterAgentHealthStore(path=str(Path(self.temp.name) / "agent-health.sqlite3"))
        server.REPORT_JOBS = RouterReportJobStore(path=str(Path(self.temp.name) / "report-jobs.sqlite3"))
        server.AUDIT = __import__("wifi_analyzer_backend.audit_store", fromlist=["SecurityAuditStore"]).SecurityAuditStore(
            path=str(Path(self.temp.name) / "security-audit.sqlite3")
        )
        self.httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.httpd.server_address[1]

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        server.AUTH = self.previous_auth
        server.HISTORY = self.previous_history
        server.AGENT_HEALTH = self.previous_agent_health
        server.REPORT_JOBS = self.previous_report_jobs
        server.AUDIT = self.previous_audit
        server.LIVE_CAPTURE = self.previous_live_capture
        server.WEBHOOK_DELIVERIES = self.previous_webhook_deliveries
        server.WEBHOOK_SUBSCRIPTIONS = self.previous_webhook_subscriptions
        server.RATE_LIMITER = self.previous_rate_limiter
        server.RATE_LIMIT_POLICIES = self.previous_rate_policies
        self.temp.cleanup()

    def request(self, method, path, payload=None, token=None, origin=None, extra_headers=None):
        headers = {}
        body = None
        if payload is not None:
            body = json.dumps(payload)
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if origin:
            headers["Origin"] = origin
        if extra_headers:
            headers.update(extra_headers)
        connection = HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
        finally:
            connection.close()


    def enroll_agent(self, admin_token, agent_id, capabilities, site_id=None):
        status, response = self.request("POST", "/api/agents/enroll", {
            "agent_id": agent_id,
            "adapter_id": "openwrt",
            "agent_version": "1.2.0",
            "advertised_capabilities": capabilities,
            "requested_capabilities": capabilities,
            "requested_permissions": ["read"],
            **({"site_id": site_id} if site_id is not None else {}),
        }, token=admin_token)
        self.assertEqual(status, 201, response)
        return response["credential"]["token"]

    def test_expensive_api_rate_limits_return_429_and_standard_retry_headers(self):
        _, setup = self.request("POST", "/api/auth/setup", {
            "password": "rate limit owner password",
        })
        token = setup["token"]
        server.RATE_LIMIT_POLICIES["api.feature.execution"] = (2, 60)

        status, first = self.request("POST", "/api/features/frequency_to_channel", {
            "frequency_mhz": 5975,
        }, token=token)
        self.assertEqual(status, 200)
        status, second = self.request("POST", "/api/features/frequency_to_channel", {
            "frequency_mhz": 2412,
        }, token=token)
        self.assertEqual(status, 200)

        connection = HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            connection.request(
                "POST",
                "/api/features/frequency_to_channel",
                body=json.dumps({"frequency_mhz": 5180}),
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
            )
            response = connection.getresponse()
            payload = json.loads(response.read())
            self.assertEqual(response.status, 429)
            self.assertEqual(response.getheader("Retry-After"), "30")
            self.assertEqual(response.getheader("X-RateLimit-Limit"), "2")
            self.assertEqual(response.getheader("X-RateLimit-Remaining"), "0")
            self.assertEqual(payload["error"], "Rate limit exceeded")
            self.assertEqual(payload["retry_after_seconds"], 30)
        finally:
            connection.close()

    def test_login_rate_limit_uses_peer_ip_and_ignores_spoofed_forwarding_headers(self):
        server.RATE_LIMIT_POLICIES["auth.login"] = (1, 60)
        status, first = self.request(
            "POST", "/api/auth/login",
            {"username": "ip.rate.user", "password": "incorrect password"},
            extra_headers={"X-Forwarded-For": "198.51.100.10"},
        )
        self.assertEqual(status, 401)
        self.assertIn("error", first)

        status, limited = self.request(
            "POST", "/api/auth/login",
            {"username": "ip.rate.user", "password": "incorrect password"},
            extra_headers={"X-Forwarded-For": "203.0.113.20"},
        )
        self.assertEqual(status, 429)
        self.assertEqual(limited["retry_after_seconds"], 60)

    def test_expensive_feature_budget_is_isolated_by_stable_account_identity(self):
        _, setup = self.request("POST", "/api/auth/setup", {
            "password": "correct horse battery staple",
        })
        owner_token = setup["token"]
        status, created = self.request("POST", "/api/users", {
            "username": "isolated.analyst",
            "password": "isolated analyst password",
            "role": "analyst",
        }, token=owner_token)
        self.assertEqual(status, 201, created)
        _, login = self.request("POST", "/api/auth/login", {
            "username": "isolated.analyst",
            "password": "isolated analyst password",
        })
        analyst_token = login["token"]

        server.RATE_LIMIT_POLICIES["api.feature.execution"] = (1, 60)
        for token in (owner_token, analyst_token):
            status, result = self.request("POST", "/api/features/frequency_to_channel", {
                "frequency_mhz": 5975,
            }, token=token)
            self.assertEqual(status, 200, result)

        status, limited = self.request("POST", "/api/features/frequency_to_channel", {
            "frequency_mhz": 2412,
        }, token=owner_token)
        self.assertEqual(status, 429)
        self.assertEqual(limited["retry_after_seconds"], 60)

    def test_totp_mfa_requires_second_factor_and_supports_audited_self_service(self):
        _, setup = self.request("POST", "/api/auth/setup", {
            "password": "owner passphrase is secure",
        })
        token = setup["token"]
        status, denied = self.request("POST", "/api/auth/mfa/setup", {
            "password": "owner passphrase is secure",
        })
        self.assertEqual(status, 401)

        status, pending = self.request("POST", "/api/auth/mfa/setup", {
            "password": "owner passphrase is secure",
        }, token=token)
        self.assertEqual(status, 200, pending)
        secret = pending["setup"]["secret"]
        code = AuthManager._totp_code(secret)

        status, confirmed = self.request("POST", "/api/auth/mfa/confirm", {
            "password": "owner passphrase is secure", "code": code,
        }, token=token)
        self.assertEqual(status, 200, confirmed)
        self.assertTrue(confirmed["mfa"]["mfa_enabled"])
        self.assertEqual(len(confirmed["mfa"]["recovery_codes"]), 10)

        status, status_data = self.request("GET", "/api/auth/status", token=token)
        self.assertEqual(status, 200)
        self.assertTrue(status_data["identity"]["mfa_enabled"])
        self.assertEqual(status_data["identity"]["recovery_codes_remaining"], 10)

        self.request("POST", "/api/auth/logout", token=token)
        status, challenge = self.request("POST", "/api/auth/login", {
            "username": "admin", "password": "owner passphrase is secure",
        })
        self.assertEqual(status, 401)
        self.assertTrue(challenge["mfa_required"])

        status, login = self.request("POST", "/api/auth/login", {
            "username": "admin",
            "password": "owner passphrase is secure",
            "code": AuthManager._totp_code(secret),
        })
        self.assertEqual(status, 200, login)
        self.assertTrue(login["status"]["identity"]["mfa_enabled"])

        status, disabled = self.request("POST", "/api/auth/mfa/disable", {
            "password": "owner passphrase is secure",
            "code": AuthManager._totp_code(secret),
        }, token=login["token"])
        self.assertEqual(status, 200, disabled)
        self.assertFalse(disabled["mfa"]["mfa_enabled"])

    def test_webhook_delivery_queue_is_permission_gated_idempotent_and_site_scoped(self):
        _, setup = self.request("POST", "/api/auth/setup", {
            "password": "owner passphrase is secure",
        })
        owner_token = setup["token"]

        def item(batch_id, site_id="office"):
            body = json.dumps({
                "schema_version": "1.0", "batch_id": batch_id,
                "key_id": "office-key-v1", "created_at": "2026-11-21T00:00:00Z",
                "events": [{
                    "event_id": "b" * 64, "event_type": "router.health",
                    "severity": "warning", "occurred_at": "2026-11-21T00:00:00Z",
                    "site_id": site_id, "router_id": "router-" + site_id,
                    "summary": "Router health warning", "attributes": {},
                }],
            }, sort_keys=True, separators=(",", ":"))
            return {
                "subscription_id": "office-alerts", "batch_id": batch_id,
                "event_count": 1, "status": "prepared",
                "endpoint": "https://hooks.example.net/router/events",
                "allowed_hosts": ["hooks.example.net"],
                "headers": {
                    "Content-Type": "application/json",
                    "X-WiFiAnalyzer-Key-Id": "office-key-v1",
                    "X-WiFiAnalyzer-Timestamp": "1795219200",
                    "X-WiFiAnalyzer-Signature": "v1=" + ("c" * 64),
                    "Idempotency-Key": batch_id,
                },
                "body": body,
            }

        status, _ = self.request("GET", "/api/webhooks/deliveries")
        self.assertEqual(status, 401)

        status, created = self.request("POST", "/api/webhooks/deliveries/enqueue", {
            "deliveries": [item("a" * 64)],
        }, token=owner_token)
        self.assertEqual(status, 201, created)
        delivery_id = created["deliveries"][0]["id"]
        self.assertEqual(created["created_count"], 1)

        status, duplicate = self.request("POST", "/api/webhooks/deliveries/enqueue", {
            "deliveries": [item("a" * 64)],
        }, token=owner_token)
        self.assertEqual(status, 200, duplicate)
        self.assertEqual(duplicate["duplicate_count"], 1)
        self.assertEqual(duplicate["deliveries"][0]["id"], delivery_id)

        status, branch_result = self.request("POST", "/api/webhooks/deliveries/enqueue", {
            "deliveries": [item("d" * 64, "branch")],
        }, token=owner_token)
        self.assertEqual(status, 201, branch_result)
        branch_id = branch_result["deliveries"][0]["id"]

        status, user = self.request("POST", "/api/users", {
            "username": "office.webhooks", "password": "office webhook user password",
            "role": "network_admin", "all_sites": False, "site_ids": ["office"],
        }, token=owner_token)
        self.assertEqual(status, 201, user)
        scoped_token = self.request("POST", "/api/auth/login", {
            "username": "office.webhooks", "password": "office webhook user password",
        })[1]["token"]

        status, listing = self.request("GET", "/api/webhooks/deliveries", token=scoped_token)
        self.assertEqual(status, 200, listing)
        self.assertEqual(listing["summary"]["delivery_count"], 1)
        self.assertEqual([entry["id"] for entry in listing["deliveries"]], [delivery_id])

        status, hidden = self.request("GET", f"/api/webhooks/deliveries/{branch_id}", token=scoped_token)
        self.assertEqual(status, 404)
        status, forbidden = self.request("POST", "/api/webhooks/deliveries/enqueue", {
            "deliveries": [item("e" * 64, "branch")],
        }, token=scoped_token)
        self.assertEqual(status, 403)
        status, forbidden = self.request(
            "POST", f"/api/webhooks/deliveries/{branch_id}/cancel", {}, token=scoped_token,
        )
        self.assertEqual(status, 404)

        status, cancelled = self.request(
            "POST", f"/api/webhooks/deliveries/{delivery_id}/cancel", {}, token=scoped_token,
        )
        self.assertEqual(status, 200, cancelled)
        self.assertEqual(cancelled["delivery"]["status"], "cancelled")

        status, viewer = self.request("POST", "/api/users", {
            "username": "viewer.webhooks", "password": "viewer webhook user password",
            "role": "viewer", "all_sites": False, "site_ids": ["office"],
        }, token=owner_token)
        self.assertEqual(status, 201, viewer)
        viewer_token = self.request("POST", "/api/auth/login", {
            "username": "viewer.webhooks", "password": "viewer webhook user password",
        })[1]["token"]
        status, denied_read = self.request("GET", "/api/webhooks/deliveries", token=viewer_token)
        self.assertEqual(status, 403)

    def test_webhook_permissions_are_registered_for_owner_network_admin_and_analyst(self):
        _, setup = self.request("POST", "/api/auth/setup", {
            "password": "owner passphrase is secure",
        })
        owner_token = setup["token"]
        self.assertTrue(server.AUTH.has_permission(owner_token, "webhooks.manage"))
        self.assertTrue(server.AUTH.has_permission(owner_token, "webhooks.read"))

        status, _ = self.request("POST", "/api/users", {
            "username": "webhook.network",
            "password": "webhook network admin password",
            "role": "network_admin",
            "all_sites": True,
            "site_ids": [],
        }, token=owner_token)
        self.assertEqual(status, 201)
        network_token = self.request("POST", "/api/auth/login", {
            "username": "webhook.network",
            "password": "webhook network admin password",
        })[1]["token"]
        self.assertTrue(server.AUTH.has_permission(network_token, "webhooks.manage"))
        self.assertTrue(server.AUTH.has_permission(network_token, "webhooks.read"))

        status, _ = self.request("POST", "/api/users", {
            "username": "webhook.analyst",
            "password": "webhook analyst user password",
            "role": "analyst",
            "all_sites": True,
            "site_ids": [],
        }, token=owner_token)
        self.assertEqual(status, 201)
        analyst_token = self.request("POST", "/api/auth/login", {
            "username": "webhook.analyst",
            "password": "webhook analyst user password",
        })[1]["token"]
        self.assertFalse(server.AUTH.has_permission(analyst_token, "webhooks.manage"))
        self.assertTrue(server.AUTH.has_permission(analyst_token, "webhooks.read"))

        status, _ = self.request("POST", "/api/users", {
            "username": "webhook.viewer",
            "password": "webhook viewer password",
            "role": "viewer",
            "all_sites": True,
            "site_ids": [],
        }, token=owner_token)
        self.assertEqual(status, 201)
        viewer_token = self.request("POST", "/api/auth/login", {
            "username": "webhook.viewer",
            "password": "webhook viewer password",
        })[1]["token"]
        self.assertFalse(server.AUTH.has_permission(viewer_token, "webhooks.read"))
        self.assertFalse(server.AUTH.has_permission(viewer_token, "webhooks.manage"))

    def test_webhook_subscriptions_are_persisted_site_scoped_and_secret_free(self):
        _, setup = self.request("POST", "/api/auth/setup", {
            "password": "owner passphrase is secure",
        })
        owner_token = setup["token"]

        def subscription(subscription_id, sites):
            return {
                "subscription_id": subscription_id,
                "endpoint": "https://hooks.example.net/router/events",
                "allowed_hosts": ["hooks.example.net"],
                "key_id": subscription_id + "-key",
                "event_types": ["router.health", "radio.down"],
                "minimum_severity": "warning",
                "site_allowlist": sites,
                "maximum_events_per_batch": 100,
                "maximum_batches": 10,
                "enabled": True,
            }

        status, created = self.request("POST", "/api/webhooks/subscriptions", {
            "subscription": subscription("office-alerts", ["office"]),
        }, token=owner_token)
        self.assertEqual(status, 201, created)
        self.assertEqual(created["subscription"]["subscription_id"], "office-alerts")

        status, duplicate = self.request("POST", "/api/webhooks/subscriptions", {
            "subscription": subscription("office-alerts", ["office"]),
        }, token=owner_token)
        self.assertEqual(status, 409)

        status, created_branch = self.request("POST", "/api/webhooks/subscriptions", {
            "subscription": subscription("branch-alerts", ["branch"]),
        }, token=owner_token)
        self.assertEqual(status, 201, created_branch)

        status, user = self.request("POST", "/api/users", {
            "username": "office.webhook-owner",
            "password": "office webhook owner password",
            "role": "network_admin",
            "all_sites": False,
            "site_ids": ["office"],
        }, token=owner_token)
        self.assertEqual(status, 201, user)
        scoped_token = self.request("POST", "/api/auth/login", {
            "username": "office.webhook-owner",
            "password": "office webhook owner password",
        })[1]["token"]

        status, listing = self.request("GET", "/api/webhooks/subscriptions", token=scoped_token)
        self.assertEqual(status, 200, listing)
        self.assertEqual([item["subscription_id"] for item in listing["subscriptions"]], ["office-alerts"])

        status, forbidden = self.request("POST", "/api/webhooks/subscriptions", {
            "subscription": subscription("branch-intrusion", ["branch"]),
        }, token=scoped_token)
        self.assertEqual(status, 403)

        status, hidden_update = self.request(
            "POST", "/api/webhooks/subscriptions/branch-alerts/update", {
                "subscription": subscription("branch-alerts", ["branch"], enabled=False),
            }, token=scoped_token,
        )
        self.assertEqual(status, 404)

        status, updated = self.request(
            "POST", "/api/webhooks/subscriptions/office-alerts/update", {
                "subscription": subscription("office-alerts", ["office"], enabled=False),
            }, token=scoped_token,
        )
        self.assertEqual(status, 200, updated)
        self.assertFalse(updated["subscription"]["enabled"])
        self.assertNotIn("signing_secret", str(updated))
        self.assertNotIn("hmac_secret", str(updated))

        status, viewer = self.request("POST", "/api/users", {
            "username": "viewer.webhook-read",
            "password": "viewer webhook read password",
            "role": "viewer",
            "all_sites": False,
            "site_ids": ["office"],
        }, token=owner_token)
        self.assertEqual(status, 201, viewer)
        viewer_token = self.request("POST", "/api/auth/login", {
            "username": "viewer.webhook-read",
            "password": "viewer webhook read password",
        })[1]["token"]
        status, denied_read = self.request("GET", "/api/webhooks/subscriptions", token=viewer_token)
        self.assertEqual(status, 403)

        status, deleted = self.request(
            "POST", "/api/webhooks/subscriptions/office-alerts/delete", {}, token=scoped_token,
        )
        self.assertEqual(status, 200, deleted)
        status, remaining = self.request("GET", "/api/webhooks/subscriptions", token=scoped_token)
        self.assertEqual(status, 200)
        self.assertEqual(remaining["subscriptions"], [])

    def test_saved_webhook_subscription_egress_probe_uses_pinned_tls_without_http(self):
        _, setup = self.request("POST", "/api/auth/setup", {
            "password": "owner passphrase is secure",
        })
        owner_token = setup["token"]
        configuration = {
            "subscription_id": "office-probe",
            "endpoint": "https://hooks.example.net/router/events",
            "allowed_hosts": ["hooks.example.net"],
            "key_id": "office-probe-key",
            "event_types": ["router.health"],
            "minimum_severity": "warning",
            "site_allowlist": ["office"],
            "maximum_events_per_batch": 100,
            "maximum_batches": 5,
            "enabled": True,
        }
        status, created = self.request(
            "POST", "/api/webhooks/subscriptions",
            {"subscription": configuration}, token=owner_token,
        )
        self.assertEqual(status, 201, created)

        class FakeConnection:
            peer_ip = "1.1.1.1"
            connected_port = 443
            tls_version = "TLSv1.3"
            tls_verified = True
            hostname_verified = True
            closed = False

            def close(self):
                self.closed = True

        fake = FakeConnection()
        with patch.object(server, "_resolve_public_addresses", return_value=["1.1.1.1"]), \
             patch.object(server, "_PinnedHTTPSConnection", return_value=fake) as connect, \
             patch.object(server, "run_feature", return_value={"result": {"approved": True, "reasons": []}}) as verify:
            status, result = self.request(
                "POST", "/api/webhooks/subscriptions/office-probe/probe", {}, token=owner_token,
            )
        self.assertEqual(status, 200, result)
        self.assertTrue(result["approved"])
        self.assertEqual(result["evidence"]["peer_ip"], "1.1.1.1")
        self.assertEqual(result["evidence"]["tls_version"], "TLSv1.3")
        self.assertIn("no HTTP request was sent", result["note"])
        connect.assert_called_once_with("hooks.example.net", "1.1.1.1", 5)
        verify.assert_called_once()
        self.assertTrue(fake.closed)

    def test_saved_subscription_egress_probe_checks_pinned_tls_without_sending_http(self):
        _, setup = self.request("POST", "/api/auth/setup", {
            "password": "owner passphrase is secure",
        })
        owner_token = setup["token"]
        configuration = {
            "subscription_id": "office-probe",
            "endpoint": "https://hooks.example.net/router/events",
            "allowed_hosts": ["hooks.example.net"],
            "key_id": "office-probe-key",
            "event_types": ["router.health"],
            "minimum_severity": "warning",
            "site_allowlist": ["office"],
            "maximum_events_per_batch": 100,
            "maximum_batches": 5,
            "enabled": True,
        }
        status, created = self.request(
            "POST", "/api/webhooks/subscriptions",
            {"subscription": configuration}, token=owner_token,
        )
        self.assertEqual(status, 201, created)

        class FakeConnection:
            peer_ip = "1.1.1.1"
            connected_port = 443
            tls_version = "TLSv1.3"
            tls_verified = True
            hostname_verified = True
            closed = False

            def close(self):
                self.closed = True

        fake = FakeConnection()
        with patch.object(server, "_resolve_public_addresses", return_value=["1.1.1.1"]), \
             patch.object(server, "_PinnedHTTPSConnection", return_value=fake) as connect, \
             patch.object(server, "run_feature", return_value={"result": {"approved": True, "reasons": []}}) as verify:
            status, result = self.request(
                "POST", "/api/webhooks/subscriptions/office-probe/probe", {}, token=owner_token,
            )
        self.assertEqual(status, 200, result)
        self.assertTrue(result["approved"])
        self.assertEqual(result["evidence"]["peer_ip"], "1.1.1.1")
        self.assertEqual(result["evidence"]["tls_version"], "TLSv1.3")
        self.assertIn("no HTTP request was sent", result["note"])
        connect.assert_called_once_with("hooks.example.net", "1.1.1.1", 5)
        verify.assert_called_once()
        self.assertTrue(fake.closed)

    def test_restricted_user_cannot_probe_another_sites_subscription(self):
        _, setup = self.request("POST", "/api/auth/setup", {
            "password": "owner passphrase is secure",
        })
        owner_token = setup["token"]
        configuration = {
            "subscription_id": "branch-probe",
            "endpoint": "https://hooks.example.net/router/events",
            "allowed_hosts": ["hooks.example.net"],
            "key_id": "branch-key",
            "event_types": ["router.health"],
            "minimum_severity": "warning",
            "site_allowlist": ["branch"],
            "maximum_events_per_batch": 100,
            "maximum_batches": 5,
            "enabled": True,
        }
        status, _ = self.request(
            "POST", "/api/webhooks/subscriptions",
            {"subscription": configuration}, token=owner_token,
        )
        self.assertEqual(status, 201)
        status, _ = self.request("POST", "/api/users", {
            "username": "office.probe",
            "password": "office probe user password",
            "role": "network_admin",
            "all_sites": False,
            "site_ids": ["office"],
        }, token=owner_token)
        self.assertEqual(status, 201)
        scoped_token = self.request("POST", "/api/auth/login", {
            "username": "office.probe",
            "password": "office probe user password",
        })[1]["token"]
        with patch.object(server, "_PinnedHTTPSConnection") as connect:
            status, hidden = self.request(
                "POST", "/api/webhooks/subscriptions/branch-probe/probe", {}, token=scoped_token,
            )
        self.assertEqual(status, 404)
        connect.assert_not_called()

    def test_auth_status_is_available_before_first_run_setup(self):
        status, payload = self.request("GET", "/api/auth/status")
        self.assertEqual(status, 200)
        self.assertFalse(payload["configured"])
        self.assertFalse(payload["authenticated"])

    def test_feature_catalog_requires_login_and_exposes_all_registered_features(self):
        status, payload = self.request("GET", "/api/features")
        self.assertEqual(status, 401)
        self.assertIn("Authentication required", payload["error"])

        status, setup = self.request(
            "POST", "/api/auth/setup", {"password": "correct horse battery staple"}
        )
        self.assertEqual(status, 201)
        token = setup["token"]
        self.assertTrue(server.AUTH.validate(token))

        status, catalog = self.request("GET", "/api/features", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(catalog["count"], 189)
        self.assertEqual(len(catalog["features"]), 189)
        self.assertIn("site_topology_history_timeline", {item["slug"] for item in catalog["features"]})
        self.assertIn("site_topology_gateway_path_audit", {item["slug"] for item in catalog["features"]})
        self.assertIn("site_radio_configuration_audit", {item["slug"] for item in catalog["features"]})
        self.assertIn("site_topology_visualisation", {item["slug"] for item in catalog["features"]})
        self.assertIn("site_discovery_history_snapshot", {item["slug"] for item in catalog["features"]})
        self.assertIn("site_to_site_change_report", {item["slug"] for item in catalog["features"]})
        self.assertIn("consolidated_site_audit_report", {item["slug"] for item in catalog["features"]})
        self.assertIn("router_agent_capability_negotiation", {item["slug"] for item in catalog["features"]})
        self.assertIn("openwrt_snapshot_normalizer", {item["slug"] for item in catalog["features"]})
        self.assertIn("router_agent_health_report", {item["slug"] for item in catalog["features"]})
        self.assertIn("openwrt_agent_snapshot_ingest", {item["slug"] for item in catalog["features"]})
        self.assertIn("openwrt_agent_snapshot_diff", {item["slug"] for item in catalog["features"]})
        self.assertIn("router_agent_credential_scope", {item["slug"] for item in catalog["features"]})
        self.assertIn("openwrt_snapshot_delivery_envelope", {item["slug"] for item in catalog["features"]})
        self.assertIn("router_agent_negotiation_audit", {item["slug"] for item in catalog["features"]})

    def test_multi_subscription_delivery_orchestrator_requires_site_scope_and_fresh_egress(self):
        _, setup = self.request("POST", "/api/auth/setup", {
            "password": "owner passphrase is secure",
        })
        owner_token = setup["token"]
        payload = {
            "now": "2026-11-20T10:00:00Z",
            "subscriptions": [{
                "subscription_id": "home-health",
                "endpoint": "https://hooks.example.net/router/events",
                "allowed_hosts": ["hooks.example.net"],
                "key_id": "webhook-key-01",
                "event_types": ["router.health"],
                "minimum_severity": "warning",
                "site_allowlist": ["home"],
                "maximum_events_per_batch": 100,
                "maximum_batches": 10,
            }],
            "events": [{
                "event_id": "a" * 64,
                "event_type": "router.health",
                "severity": "warning",
                "occurred_at": "2026-11-20T09:59:00Z",
                "site_id": "home",
                "router_id": "openwrt-home",
                "summary": "Router health warning",
                "attributes": {"finding_count": 1, "password": "must-not-leak"},
            }],
            "signing_keys": {"webhook-key-01": "sample-signing-material-at-least-32-bytes"},
            "egress_evidence": [{
                "subscription_id": "home-health",
                "endpoint": "https://hooks.example.net/router/events",
                "allowed_hosts": ["hooks.example.net"],
                "resolution_at": "2026-11-20T09:59:55Z",
                "connected_at": "2026-11-20T10:00:00Z",
                "resolved_addresses": ["1.1.1.1"],
                "peer_ip": "1.1.1.1",
                "connected_port": 443,
                "tls_version": "TLSv1.3",
                "tls_verified": True,
                "hostname_verified": True,
                "redirect_location": None,
            }],
        }

        status, prepared = self.request(
            "POST", "/api/features/router_webhook_delivery_orchestrator",
            payload, token=owner_token,
        )
        self.assertEqual(status, 200, prepared)
        result = prepared["result"]
        self.assertEqual(result["status"], "prepared")
        self.assertEqual(result["summary"]["prepared_delivery_count"], 1)
        delivery = result["prepared_deliveries"][0]
        self.assertEqual(delivery["subscription_id"], "home-health")
        self.assertEqual(delivery["egress"]["connected_peer_ip"], "1.1.1.1")
        self.assertIn("X-WiFiAnalyzer-Signature", delivery["headers"])
        self.assertEqual(delivery["headers"]["Idempotency-Key"], delivery["batch_id"])
        rendered = str(result)
        self.assertNotIn("sample-signing-material-at-least-32-bytes", rendered)
        self.assertNotIn("must-not-leak", rendered)

        status, created = self.request("POST", "/api/users", {
            "username": "branch.webhook-viewer",
            "password": "branch webhook viewer password",
            "role": "viewer",
            "all_sites": False,
            "site_ids": ["branch"],
        }, token=owner_token)
        self.assertEqual(status, 201, created)
        branch_token = self.request("POST", "/api/auth/login", {
            "username": "branch.webhook-viewer",
            "password": "branch webhook viewer password",
        })[1]["token"]
        status, denied = self.request(
            "POST", "/api/features/router_webhook_delivery_orchestrator",
            payload, token=branch_token,
        )
        self.assertEqual(status, 403)

        blocked_payload = {
            **payload,
            "egress_evidence": [{
                **payload["egress_evidence"][0],
                "resolution_at": "2026-11-20T09:57:55Z",
                "connected_at": "2026-11-20T09:58:00Z",
            }],
        }
        status, blocked = self.request(
            "POST", "/api/features/router_webhook_delivery_orchestrator",
            blocked_payload, token=owner_token,
        )
        self.assertEqual(status, 200, blocked)
        self.assertEqual(blocked["result"]["status"], "blocked")
        self.assertEqual(
            blocked["result"]["blocked_deliveries"][0]["reasons"],
            ["egress_evidence_stale"],
        )

    def test_feature_execution_returns_the_selected_tool_result(self):
        _, setup = self.request(
            "POST", "/api/auth/setup", {"password": "correct horse battery staple"}
        )
        status, result = self.request(
            "POST",
            "/api/features/frequency_to_channel",
            {"frequency_mhz": 5975},
            token=setup["token"],
        )
        self.assertEqual(status, 200)
        self.assertEqual(result["feature"], "F007")
        self.assertEqual(result["result"]["channel"], 5)
        self.assertEqual(result["result"]["band"], "6GHz")

    def test_untrusted_browser_origin_is_rejected(self):
        status, payload = self.request(
            "POST",
            "/api/auth/setup",
            {"password": "correct horse battery staple"},
            origin="https://untrusted.invalid",
        )
        self.assertEqual(status, 403)
        self.assertIn("Origin is not allowed", payload["error"])
        self.assertFalse(server.AUTH.configured())

    def test_logout_revokes_feature_api_access(self):
        _, setup = self.request(
            "POST", "/api/auth/setup", {"password": "correct horse battery staple"}
        )
        token = setup["token"]
        status, payload = self.request("POST", "/api/auth/logout", token=token)
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])

        status, _ = self.request("GET", "/api/features", token=token)
        self.assertEqual(status, 401)

    def test_feature_api_rejects_invalid_json_content_type(self):
        connection = HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            connection.request(
                "POST",
                "/api/auth/setup",
                body='{"password":"correct horse battery staple"}',
                headers={"Content-Type": "text/plain"},
            )
            response = connection.getresponse()
            payload = json.loads(response.read())
            self.assertEqual(response.status, 400)
            self.assertIn("Content-Type", payload["error"])
        finally:
            connection.close()


    def test_site_radio_configuration_audit_is_executable_through_the_authenticated_api(self):
        _, setup = self.request(
            "POST", "/api/auth/setup", {"password": "correct horse battery staple"}
        )
        status, result = self.request(
            "POST",
            "/api/features/site_radio_configuration_audit",
            {
                "radios": [{"radio_id": "ap-1-5g", "site_id": "home", "band": "5GHz", "channel_width_mhz": 80, "security": "WPA3", "tx_power_dbm": 18}],
                "standards": [{"site_id": "home", "band": "5GHz", "channel_width_mhz": 80, "security": "WPA3", "min_tx_power_dbm": 10, "max_tx_power_dbm": 23}],
            },
            token=setup["token"],
        )
        self.assertEqual(status, 200)
        self.assertEqual(result["feature"], "F156")
        self.assertEqual(result["result"]["radios"][0]["status"], "compliant")

    def test_site_topology_visualisation_is_available_through_the_authenticated_api(self):
        _, setup = self.request(
            "POST", "/api/auth/setup", {"password": "correct horse battery staple"}
        )
        status, result = self.request(
            "POST",
            "/api/features/site_topology_visualisation",
            {
                "access_points": [{"ap_id": "gw", "site_id": "home"}, {"ap_id": "ap-1", "site_id": "home"}],
                "gateway_ap_ids": ["gw"],
                "links": [{"from_ap_id": "gw", "to_ap_id": "ap-1", "relationship": "wired_uplink"}],
            },
            token=setup["token"],
        )
        self.assertEqual(status, 200)
        self.assertEqual(result["feature"], "F157")
        self.assertEqual(result["result"]["summary"]["access_point_count"], 2)

    def test_site_history_requires_auth_and_supports_persisted_save_list_and_read(self):
        status, denied = self.request("GET", "/api/sites/history")
        self.assertEqual(status, 401)
        self.assertIn("Authentication required", denied["error"])

        _, setup = self.request("POST", "/api/auth/setup", {"password": "correct horse battery staple"})
        token = setup["token"]
        snapshot = {
            "site_id": "home",
            "captured_at": "2026-11-20T10:00:00Z",
            "access_points": [{"ap_id": "gw"}, {"ap_id": "ap-1"}],
            "links": [{"from_ap_id": "gw", "to_ap_id": "ap-1", "relationship": "wired_uplink"}],
        }
        status, saved = self.request("POST", "/api/sites/history", snapshot, token=token)
        self.assertEqual(status, 201)
        snapshot_id = saved["snapshot"]["id"]
        self.assertEqual(saved["snapshot"]["access_point_count"], 2)

        status, listing = self.request("GET", "/api/sites/history?site_id=home&limit=1", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(len(listing["snapshots"]), 1)
        self.assertEqual(listing["snapshots"][0]["id"], snapshot_id)

        status, detail = self.request("GET", f"/api/sites/history/{snapshot_id}", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(detail["snapshot"]["snapshot"]["access_points"][0]["site_id"], "home")

        status, missing = self.request("GET", "/api/sites/history/999999", token=token)
        self.assertEqual(status, 404)
        self.assertIn("not found", missing["error"].lower())

    def test_site_history_rejects_duplicate_snapshots_and_invalid_payloads(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password": "correct horse battery staple"})
        token = setup["token"]
        snapshot = {"site_id": "home", "captured_at": "2026-11-20T10:00:00Z", "access_points": [], "links": []}
        self.assertEqual(self.request("POST", "/api/sites/history", snapshot, token=token)[0], 201)
        status, duplicate = self.request("POST", "/api/sites/history", snapshot, token=token)
        self.assertEqual(status, 409)
        self.assertIn("already exists", duplicate["error"])
        status, invalid = self.request("POST", "/api/sites/history", {**snapshot, "captured_at": "invalid"}, token=token)
        self.assertEqual(status, 400)
        self.assertIn("ISO-8601", invalid["error"])

    def test_saved_history_report_compares_latest_site_snapshots(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password": "correct horse battery staple"})
        token = setup["token"]
        def save(site_id, timestamp, access_points):
            status, saved = self.request("POST", "/api/sites/history", {
                "site_id": site_id, "captured_at": timestamp,
                "access_points": access_points, "links": [],
            }, token=token)
            self.assertEqual(status, 201)
            return saved

        shared = "00:11:22:33:44:55"
        save("home", "2026-11-20T09:00:00Z", [
            {"ap_id": "old", "bssid": "00:11:22:33:44:66", "band": "2.4GHz"}
        ])
        save("home", "2026-11-20T10:00:00Z", [
            {"ap_id": "new", "bssid": shared, "band": "5GHz"}
        ])
        save("branch", "2026-11-20T10:00:00Z", [
            {"ap_id": "branch-ap", "bssid": shared, "band": "5GHz"}
        ])
        status, response = self.request("GET", "/api/sites/history/report?site_ids=home,branch", token=token)
        self.assertEqual(status, 200)
        report = response["report"]["result"]
        self.assertEqual(report["summary"]["site_count"], 2)
        self.assertEqual(report["summary"]["sites_with_baseline"], 1)
        self.assertEqual(report["summary"]["cross_site_bssid_collision_count"], 1)
        self.assertEqual(report["summary"]["added_access_point_count"], 1)
        self.assertEqual(report["summary"]["removed_access_point_count"], 1)

    def test_site_scope_filters_saved_history_and_blocks_cross_site_reads_and_inputs(self):
        _, setup = self.request("POST", "/api/auth/setup", {
            "password": "owner passphrase is secure",
        })
        owner_token = setup["token"]
        home = server.HISTORY.record({
            "site_id": "home", "captured_at": "2026-11-20T10:00:00Z",
            "access_points": [], "links": [],
        })
        branch = server.HISTORY.record({
            "site_id": "branch", "captured_at": "2026-11-20T10:01:00Z",
            "access_points": [], "links": [],
        })
        status, created = self.request("POST", "/api/users", {
            "username": "home.viewer", "password": "home viewer password",
            "role": "viewer", "all_sites": False, "site_ids": ["home"],
        }, token=owner_token)
        self.assertEqual(status, 201, created)
        viewer_token = self.request(
            "POST", "/api/auth/login",
            {"username": "home.viewer", "password": "home viewer password"},
        )[1]["token"]

        status, catalog = self.request("GET", "/api/sites", token=viewer_token)
        self.assertEqual(status, 200)
        self.assertEqual(catalog["site_ids"], ["home"])
        status, listing = self.request("GET", "/api/sites/history?limit=50", token=viewer_token)
        self.assertEqual(status, 200)
        self.assertEqual({item["site_id"] for item in listing["snapshots"]}, {"home"})
        status, listing = self.request("GET", "/api/sites/history?site_id=branch", token=viewer_token)
        self.assertEqual(status, 403)
        status, detail = self.request("GET", f"/api/sites/history/{branch['id']}", token=viewer_token)
        self.assertEqual(status, 404)
        status, report = self.request("GET", "/api/sites/history/report", token=viewer_token)
        self.assertEqual(status, 200)
        self.assertEqual(report["reported_site_count"], 1)
        status, denied = self.request(
            "GET", "/api/sites/history/report?site_ids=home,branch", token=viewer_token,
        )
        self.assertEqual(status, 403)
        status, denied = self.request("POST", "/api/sites/audit", {
            "sites": [{"site_id": "branch", "access_points": [], "links": []}],
        }, token=viewer_token)
        self.assertEqual(status, 403)
        status, denied = self.request("POST", "/api/sites/history", {
            "site_id": "branch", "captured_at": "2026-11-20T10:02:00Z",
            "access_points": [], "links": [],
        }, token=viewer_token)
        self.assertEqual(status, 403)
        status, denied = self.request("POST", "/api/features/site_to_site_change_report", {
            "sites": [{"site_id": "branch"}],
        }, token=viewer_token)
        self.assertEqual(status, 403)
        self.assertEqual(server.HISTORY.get(home["id"])["site_id"], "home")
    def test_saved_history_report_requires_auth_and_limits_site_count(self):
        status, denied = self.request("GET", "/api/sites/history/report")
        self.assertEqual(status, 401)
        self.assertIn("Authentication required", denied["error"])
        _, setup = self.request("POST", "/api/auth/setup", {"password": "correct horse battery staple"})
        token = setup["token"]
        too_many = ",".join(f"site-{index}" for index in range(21))
        status, response = self.request("GET", f"/api/sites/history/report?site_ids={too_many}", token=token)
        self.assertEqual(status, 400)
        self.assertIn("no more than 20", response["error"])

    def test_consolidated_site_audit_is_available_through_authenticated_api(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password": "correct horse battery staple"})
        token = setup["token"]
        status, report = self.request("POST", "/api/sites/audit", {
            "sites": [{
                "site_id": "home",
                "access_points": [{"ap_id": "gw", "bssid": "00:11:22:33:44:55"}],
                "links": [],
            }]
        }, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(report["feature"], "F160")
        self.assertEqual(report["result"]["summary"]["site_count"], 1)

    def test_consolidated_site_audit_requires_authentication(self):
        status, response = self.request("POST", "/api/sites/audit", {"sites": []})
        self.assertEqual(status, 401)
        self.assertIn("Authentication required", response["error"])

    def test_read_only_adapter_catalog_and_capability_negotiation_require_auth(self):
        status, denied = self.request("GET", "/api/adapters")
        self.assertEqual(status, 401)
        self.assertIn("Authentication required", denied["error"])
        _, setup = self.request("POST", "/api/auth/setup", {"password": "correct horse battery staple"})
        token = setup["token"]
        status, catalogue = self.request("GET", "/api/adapters", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(catalogue["count"], 3)
        adapters = {item["adapter_id"]: item for item in catalogue["adapters"]}
        self.assertTrue(adapters["openwrt"]["read_only"])
        self.assertEqual(adapters["openwrt"]["transport"], "local_agent")
        self.assertTrue(adapters["unifi"]["read_only"])
        self.assertEqual(adapters["unifi"]["transport"], "controller_export")
        self.assertTrue(adapters["mikrotik"]["read_only"])
        self.assertEqual(adapters["mikrotik"]["transport"], "controller_export")

        status, negotiated = self.request("POST", "/api/adapters/negotiate", {
            "adapter_id": "openwrt",
            "agent_version": "1.0.0",
            "advertised_capabilities": ["system.board", "network.routes"],
            "requested_capabilities": ["system.board", "network.routes"],
            "requested_permissions": ["read", "config.write"],
        }, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(negotiated["result"]["status"], "partial")
        self.assertEqual(negotiated["result"]["negotiated_permissions"], ["read"])

    def test_unifi_snapshot_normalizer_is_available_through_authenticated_api(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password": "correct horse battery staple"})
        token = setup["token"]
        status, result = self.request("POST", "/api/features/unifi_snapshot_normalizer", {
            "captured_at": "2026-11-20T10:00:00Z",
            "devices": [{
                "mac": "00:11:22:33:44:55",
                "radio_table": [{"radio": "na", "channel": 36, "ht": "VHT80"}],
            }],
            "clients": [],
            "networks": [{"name": "Office", "vlan_enabled": False, "vlan": 0}],
        }, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(result["feature"], "F172")
        self.assertEqual(result["result"]["adapter_id"], "unifi")
        self.assertEqual(result["result"]["summary"]["wireless_radio_count"], 1)
        self.assertIsNone(result["result"]["networks"][0]["vlan_id"])

    def test_router_webhook_egress_policy_verifier_is_available_through_authenticated_api(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password": "correct horse battery staple"})
        token = setup["token"]
        status, result = self.request("POST", "/api/features/router_webhook_egress_policy_verifier", {
            "endpoint": "https://hooks.example.net/router/events",
            "allowed_hosts": ["hooks.example.net"],
            "resolution_at": "2026-11-20T09:59:55Z",
            "connected_at": "2026-11-20T10:00:00Z",
            "resolved_addresses": ["1.1.1.1"],
            "peer_ip": "1.1.1.1",
            "connected_port": 443,
            "tls_version": "TLSv1.3",
            "tls_verified": True,
            "hostname_verified": True,
            "redirect_location": None,
        }, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(result["feature"], "F187")
        self.assertTrue(result["result"]["approved"])
        self.assertEqual(result["result"]["connection_policy"]["connect_to_exact_peer_ip"], "1.1.1.1")

    def test_router_encrypted_report_archive_is_available_through_authenticated_api(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password": "correct horse battery staple"})
        token = setup["token"]
        passphrase = "api-test-passphrase-for-encrypted-router-reports"
        status, encrypted = self.request("POST", "/api/features/router_encrypted_report_archive", {
            "mode": "encrypt",
            "archive_id": "api-backup-001",
            "created_at": "2026-11-20T10:00:00Z",
            "passphrase": passphrase,
            "data": {"reports": [{"report_id": "office-weekly", "finding_count": 1}]},
        }, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(encrypted["feature"], "F186")
        self.assertEqual(encrypted["result"]["status"], "encrypted")
        self.assertNotIn(passphrase, str(encrypted))
        self.assertNotIn(passphrase, str(encrypted))

        status, restored = self.request("POST", "/api/features/router_encrypted_report_archive", {
            "mode": "restore",
            "passphrase": passphrase,
            "archive": encrypted["result"]["archive"],
        }, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(restored["result"]["status"], "restored")
        self.assertEqual(restored["result"]["data"], {"reports": [{"report_id": "office-weekly", "finding_count": 1}]})

    def test_router_webhook_envelope_builder_is_available_through_authenticated_api(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password": "correct horse battery staple"})
        token = setup["token"]
        status, result = self.request("POST", "/api/features/router_webhook_envelope_builder", {
            "now": "2026-11-20T10:00:00Z",
            "batch_id": "api-batch-001",
            "key_id": "router-key-v1",
            "signing_secret": "api-test-secret-that-is-over-thirty-two-bytes-long",
            "endpoint": "https://hooks.example.net/router/events",
            "allowed_hosts": ["hooks.example.net"],
            "events": [{
                "event_id": "api-event-001", "event_type": "router.health.warning",
                "severity": "warning", "occurred_at": "2026-11-20T10:00:00Z",
                "site_id": "office", "router_id": "openwrt-office",
                "summary": "Router CPU warning", "attributes": {"observed": 90, "threshold": 85},
            }],
        }, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(result["feature"], "F185")
        self.assertEqual(result["result"]["status"], "prepared")
        self.assertEqual(result["result"]["summary"]["event_count"], 1)
        self.assertNotIn("signing_secret", str(result))
        self.assertNotIn("api-test-secret", str(result))

    def test_webhook_subscription_router_is_available_through_authenticated_api(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password": "correct horse battery staple"})
        token = setup["token"]
        status, result = self.request("POST", "/api/features/router_webhook_subscription_router", {
            "subscriptions": [{
                "subscription_id": "home-alerts",
                "endpoint": "https://hooks.example.net/router/events",
                "allowed_hosts": ["hooks.example.net"],
                "key_id": "webhook-key-01",
                "event_types": ["router.health"],
                "minimum_severity": "warning",
                "site_allowlist": ["home"],
                "maximum_events_per_batch": 25,
            }],
            "events": [{
                "event_id": "a" * 64,
                "event_type": "router.health",
                "severity": "warning",
                "occurred_at": "2026-11-20T10:00:00Z",
                "site_id": "home",
                "router_id": "openwrt-home",
                "summary": "Router health warning",
                "attributes": {"observed": 90, "threshold": 85},
            }],
        }, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(result["feature"], "F190")
        self.assertEqual(result["result"]["summary"]["batch_count"], 1)
        self.assertEqual(result["result"]["batches"][0]["subscription_id"], "home-alerts")

    def test_pcap_capture_analyzer_is_available_through_authenticated_api(self):
        denied, response = self.request("POST", "/api/features/pcap_capture_analyzer", {
            "capture_base64": "1MOyoQIABAAAAAAAAAAAAP//AAABAAAA",
        })
        self.assertEqual(denied, 401)
        _, setup = self.request("POST", "/api/auth/setup", {"password": "correct horse battery staple"})
        token = setup["token"]
        status, result = self.request("POST", "/api/features/pcap_capture_analyzer", {
            "capture_base64": "1MOyoQIABAAAAAAAAAAAAP//AAABAAAA",
        }, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(result["feature"], "F191")
        self.assertEqual(result["result"]["status"], "analysed")
        self.assertEqual(result["result"]["capture"]["link_type_name"], "ethernet")
        self.assertEqual(result["result"]["summary"]["packet_count"], 0)
        self.assertFalse(result["result"]["privacy"]["packet_payloads_returned"])

        pcapng = "Cg0NChwAAABNPCsaAQAAAP//////////HAAAAAEAAAAUAAAAAQAAAP//AAAUAAAA"
        status, ng_result = self.request("POST", "/api/features/pcap_capture_analyzer", {
            "capture_base64": pcapng,
        }, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(ng_result["result"]["capture"]["format"], "pcapng")
        self.assertEqual(ng_result["result"]["capture"]["link_type_name"], "ethernet")
        self.assertEqual(ng_result["result"]["capture"]["interface_count"], 1)
        self.assertEqual(ng_result["result"]["summary"]["packet_count"], 0)

    def test_scheduled_report_delivery_package_uses_active_job_lease_and_approved_egress(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password": "correct horse battery staple"})
        token = setup["token"]
        bundle = build_report_bundle({
            "report_id": "weekly-home",
            "title": "Weekly home router report",
            "generated_at": "2026-11-20T09:59:00Z",
            "sources": [{
                "source_id": "home-health",
                "source_type": "router_fleet_health_audit",
                "result": {"status": "audited", "summary": {"router_count": 1}, "routers": []},
            }],
        })
        occurrence_id = "c" * 64
        intake = server.run_feature("router_scheduled_report_job_intake", {
            "schedule_id": "daily-home",
            "occurrence_id": occurrence_id,
            "scheduled_at": "2026-11-20T09:59:00Z",
            "report_bundle": bundle,
        })["result"]
        server.REPORT_JOBS.enqueue(intake, now="2026-11-20T09:58:00Z")
        claimed = server.REPORT_JOBS.claim_due(
            "api-worker", now="2026-11-20T10:00:00Z", lease_seconds=120,
        )["jobs"][0]
        delivery_payload = {
            "now": "2026-11-20T10:00:00Z",
            "lease_id": claimed["lease_id"],
            "webhook": {
                "endpoint": "https://hooks.example.net/reports",
                "allowed_hosts": ["hooks.example.net"],
                "key_id": "api-key",
                "signing_secret": "api-test-secret-with-at-least-32-bytes",
            },
            "egress_evidence": {
                "resolution_at": "2026-11-20T09:59:55Z",
                "connected_at": "2026-11-20T10:00:00Z",
                "resolved_addresses": ["1.1.1.1"],
                "peer_ip": "1.1.1.1",
                "connected_port": 443,
                "tls_version": "TLSv1.3",
                "tls_verified": True,
                "hostname_verified": True,
                "redirect_location": None,
            },
        }
        delivery_path = f"/api/reports/jobs/{claimed['id']}/delivery-package"
        status, rejected = self.request(
            "POST", delivery_path,
            {**delivery_payload, "lease_id": "00000000-0000-4000-8000-000000000000"},
            token=token,
        )
        self.assertEqual(status, 409)
        status, result = self.request("POST", delivery_path, delivery_payload, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(result["feature"], "F189")
        self.assertEqual(result["result"]["status"], "ready")
        self.assertTrue(result["result"]["egress"]["approved"])
        self.assertEqual(result["result"]["delivery"]["method"], "POST")
        self.assertNotIn("api-test-secret-with-at-least-32-bytes", str(result))

    def test_scheduled_report_job_queue_is_authenticated_idempotent_and_lease_guarded(self):
        status, denied = self.request("GET", "/api/reports/jobs")
        self.assertEqual(status, 401)
        _, setup = self.request("POST", "/api/auth/setup", {"password": "correct horse battery staple"})
        token = setup["token"]
        bundle = build_report_bundle({
            "report_id": "weekly-home",
            "title": "Weekly home router report",
            "generated_at": "2026-11-20T10:00:00Z",
            "sources": [{
                "source_id": "health-home",
                "source_type": "router_fleet_health_audit",
                "result": {"status": "audited", "summary": {"router_count": 1}, "routers": []},
            }],
        })
        prepared = {
            "schedule_id": "daily-home",
            "occurrence_id": "a" * 64,
            "scheduled_at": "2026-11-20T10:01:00Z",
            "report_bundle": bundle,
            "max_attempts": 2,
        }
        status, first = self.request("POST", "/api/reports/jobs/enqueue", prepared, token=token)
        self.assertEqual(status, 201)
        self.assertTrue(first["created"])
        status, retry = self.request("POST", "/api/reports/jobs/enqueue", prepared, token=token)
        self.assertEqual(status, 200)
        self.assertTrue(retry["replayed"])
        self.assertEqual(first["job"]["id"], retry["job"]["id"])

        changed_bundle = {**bundle, "title": "Altered title"}
        body = {key: value for key, value in changed_bundle.items() if key != "content_hash"}
        changed_bundle["content_hash"] = hashlib.sha256(
            json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        status, conflict = self.request("POST", "/api/reports/jobs/enqueue", {
            **prepared, "report_bundle": changed_bundle,
        }, token=token)
        self.assertEqual(status, 409)
        self.assertIn("different report content", conflict["error"])

        status, early = self.request("POST", "/api/reports/jobs/claim", {
            "worker_id": "report-worker",
            "now": "2026-11-20T10:00:30Z",
        }, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(early["jobs"], [])
        status, claimed = self.request("POST", "/api/reports/jobs/claim", {
            "worker_id": "report-worker",
            "now": "2026-11-20T10:01:00Z",
            "lease_seconds": 60,
        }, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(len(claimed["jobs"]), 1)
        lease = claimed["jobs"][0]
        self.assertEqual(lease["status"], "leased")
        self.assertEqual(lease["report_bundle"]["report_id"], "weekly-home")

        renewal_path = f"/api/reports/jobs/{lease['id']}/renew"
        status, denied_renewal = self.request("POST", renewal_path, {
            "lease_id": lease["lease_id"],
            "now": "2026-11-20T10:01:20Z",
        })
        self.assertEqual(status, 401)
        status, invalid_renewal = self.request("POST", renewal_path, {
            "lease_id": lease["lease_id"],
            "now": "2026-11-20T10:01:20Z",
            "lease_seconds": 1,
        }, token=token)
        self.assertEqual(status, 400)
        status, renewed = self.request("POST", renewal_path, {
            "lease_id": lease["lease_id"],
            "now": "2026-11-20T10:01:20Z",
            "lease_seconds": 120,
        }, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(renewed["job"]["lease_expires_at"], "2026-11-20T10:03:20+00:00")

        status, stale = self.request("POST", f"/api/reports/jobs/{lease['id']}/complete", {
            "lease_id": "00000000-0000-4000-8000-000000000000",
            "result": {"delivery_status": "delivered"},
            "now": "2026-11-20T10:01:01Z",
        }, token=token)
        self.assertEqual(status, 409)

        status, failed = self.request("POST", f"/api/reports/jobs/{lease['id']}/fail", {
            "lease_id": lease["lease_id"],
            "error_code": "delivery_timeout",
            "now": "2026-11-20T10:01:01Z",
        }, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(failed["job"]["status"], "retry_wait")
        self.assertEqual(failed["job"]["error_code"], "delivery_timeout")

        status, second_claim = self.request("POST", "/api/reports/jobs/claim", {
            "worker_id": "report-worker-2",
            "now": "2026-11-20T10:01:31Z",
            "lease_seconds": 60,
        }, token=token)
        self.assertEqual(status, 200)
        second = second_claim["jobs"][0]
        self.assertEqual(second["attempts"], 2)

        status, completed = self.request("POST", f"/api/reports/jobs/{second['id']}/complete", {
            "lease_id": second["lease_id"],
            "result": {
                "report_id": "weekly-home",
                "content_hash": bundle["content_hash"],
                "delivery_status": "prepared",
                "api_token": "must-not-be-stored",
            },
            "now": "2026-11-20T10:01:32Z",
        }, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(completed["job"]["status"], "completed")
        self.assertNotIn("api_token", str(completed))

        status, listing = self.request("GET", "/api/reports/jobs?status=completed", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(len(listing["jobs"]), 1)
        self.assertEqual(listing["summary"]["counts_by_status"]["completed"], 1)

    def test_report_jobs_are_isolated_by_site_scope_for_reads_enqueue_and_worker_claims(self):
        _, setup = self.request("POST", "/api/auth/setup", {
            "password": "owner passphrase is secure",
        })
        owner_token = setup["token"]

        def make_bundle(site_id, report_id):
            return build_report_bundle({
                "report_id": report_id,
                "title": "Scoped report " + site_id,
                "generated_at": "2026-11-20T10:00:00Z",
                "site_allowlist": [site_id],
                "sources": [{
                    "source_id": site_id + "-health",
                    "source_type": "router_fleet_health_audit",
                    "result": {
                        "status": "audited",
                        "summary": {"router_count": 1, "warning_count": 0},
                        "routers": [{
                            "router_id": "router-" + site_id,
                            "site_id": site_id,
                            "findings": [],
                        }],
                    },
                }],
            })

        def enqueue(site_id, report_id, occurrence):
            return self.request("POST", "/api/reports/jobs/enqueue", {
                "schedule_id": "daily-" + site_id,
                "occurrence_id": occurrence * 64,
                "scheduled_at": "2026-11-20T10:01:00Z",
                "report_bundle": make_bundle(site_id, report_id),
            }, token=owner_token)

        status, home_result = enqueue("home", "weekly-home", "a")
        self.assertEqual(status, 201, home_result)
        status, branch_result = enqueue("branch", "weekly-branch", "b")
        self.assertEqual(status, 201, branch_result)
        home_job_id = home_result["job"]["id"]
        branch_job_id = branch_result["job"]["id"]

        status, created = self.request("POST", "/api/users", {
            "username": "home.reports",
            "password": "home reports user password",
            "role": "network_admin",
            "all_sites": False,
            "site_ids": ["home"],
        }, token=owner_token)
        self.assertEqual(status, 201, created)
        user_token = self.request("POST", "/api/auth/login", {
            "username": "home.reports",
            "password": "home reports user password",
        })[1]["token"]

        status, listing = self.request("GET", "/api/reports/jobs", token=user_token)
        self.assertEqual(status, 200, listing)
        self.assertEqual([item["id"] for item in listing["jobs"]], [home_job_id])
        self.assertEqual(listing["summary"]["job_count"], 1)
        self.assertEqual(listing["summary"]["counts_by_status"]["pending"], 1)

        status, visible = self.request("GET", "/api/reports/jobs/" + str(home_job_id), token=user_token)
        self.assertEqual(status, 200, visible)
        status, hidden = self.request("GET", "/api/reports/jobs/" + str(branch_job_id), token=user_token)
        self.assertEqual(status, 404, hidden)

        status, rejected_enqueue = self.request("POST", "/api/reports/jobs/enqueue", {
            "schedule_id": "daily-branch-unauthorised",
            "occurrence_id": "c" * 64,
            "scheduled_at": "2026-11-20T10:01:00Z",
            "report_bundle": make_bundle("branch", "outside-branch"),
        }, token=user_token)
        self.assertEqual(status, 403, rejected_enqueue)

        status, claim = self.request("POST", "/api/reports/jobs/claim", {
            "worker_id": "home-worker",
            "now": "2026-11-20T10:02:00Z",
            "limit": 10,
        }, token=user_token)
        self.assertEqual(status, 200, claim)
        self.assertEqual([item["id"] for item in claim["jobs"]], [home_job_id])

        status, denied_cancel = self.request(
            "POST", "/api/reports/jobs/" + str(branch_job_id) + "/cancel",
            {}, token=user_token,
        )
        self.assertEqual(status, 404, denied_cancel)
        self.assertEqual(server.REPORT_JOBS.get(branch_job_id)["status"], "pending")

    def test_router_scheduled_report_planner_is_available_through_authenticated_api(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password": "correct horse battery staple"})
        token = setup["token"]
        status, result = self.request("POST", "/api/features/router_scheduled_report_planner", {
            "now": "2026-11-20T00:00:00Z",
            "schedules": [{
                "schedule_id": "daily-office",
                "report_id": "office-weekly",
                "timezone": "Australia/Sydney",
                "frequency": "daily",
                "local_time": "18:30",
            }],
            "occurrences_per_schedule": 2,
        }, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(result["feature"], "F184")
        self.assertEqual(result["result"]["summary"]["planned_occurrence_count"], 2)
        self.assertEqual(result["result"]["schedules"][0]["status"], "scheduled")

    def test_router_audit_report_comparator_is_available_through_authenticated_api(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password": "correct horse battery staple"})
        token = setup["token"]
        previous = build_report_bundle({
            "report_id": "api-before",
            "generated_at": "2026-11-20T09:00:00Z",
            "sources": [{
                "source_id": "office-health",
                "source_type": "router_fleet_health_audit",
                "result": {
                    "status": "audited",
                    "summary": {"router_count": 1},
                    "routers": [{
                        "router_id": "openwrt-office",
                        "site_id": "office",
                        "findings": [{
                            "code": "resource.cpu_high",
                            "severity": "warning",
                            "resource_type": "router",
                            "resource_id": "openwrt-office",
                            "observed": 90,
                            "threshold": 85,
                        }],
                    }],
                },
            }],
        })
        current = build_report_bundle({
            "report_id": "api-after",
            "generated_at": "2026-11-20T10:00:00Z",
            "sources": [{
                "source_id": "office-health",
                "source_type": "router_fleet_health_audit",
                "result": {
                    "status": "audited",
                    "summary": {"router_count": 1},
                    "routers": [{
                        "router_id": "openwrt-office",
                        "site_id": "office",
                        "findings": [{
                            "code": "resource.cpu_high",
                            "severity": "warning",
                            "resource_type": "router",
                            "resource_id": "openwrt-office",
                            "observed": 95,
                            "threshold": 85,
                        }],
                    }],
                },
            }],
        })
        status, result = self.request("POST", "/api/features/router_audit_report_comparator", {
            "previous": previous,
            "current": current,
        }, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(result["feature"], "F183")
        self.assertEqual(result["result"]["summary"]["changed_count"], 1)
        self.assertEqual(result["result"]["findings"]["changed"][0]["code"], "resource.cpu_high")

    def test_router_audit_report_bundle_builder_is_available_through_authenticated_api(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password": "correct horse battery staple"})
        token = setup["token"]
        status, result = self.request("POST", "/api/features/router_audit_report_bundle_builder", {
            "report_id": "office-weekly",
            "title": "Office weekly router report",
            "generated_at": "2026-11-20T10:00:00Z",
            "sources": [{
                "source_id": "office-fleet",
                "source_type": "router_fleet_health_audit",
                "result": {
                    "status": "audited",
                    "summary": {"router_count": 1, "site_count": 1},
                    "routers": [{
                        "router_id": "openwrt-office",
                        "site_id": "office",
                        "findings": [{
                            "code": "resource.cpu_high",
                            "severity": "warning",
                            "resource_type": "router",
                            "resource_id": "openwrt-office",
                            "observed": 90,
                            "threshold": 85,
                        }],
                    }],
                },
            }],
        }, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(result["feature"], "F182")
        self.assertEqual(result["result"]["summary"]["finding_count"], 1)
        self.assertEqual(len(result["result"]["content_hash"]), 64)

    def test_router_incident_alert_policy_evaluator_is_available_through_authenticated_api(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password": "correct horse battery staple"})
        token = setup["token"]
        status, result = self.request("POST", "/api/features/router_incident_alert_policy_evaluator", {
            "generated_at": "2026-11-20T10:00:00Z",
            "policies": [{
                "policy_id": "cpu-pressure",
                "match_codes": ["resource.cpu_high"],
                "minimum_severity": "warning",
                "group_by": "router",
            }],
            "findings": [{
                "site_id": "office", "router_id": "openwrt-office", "adapter_id": "openwrt",
                "code": "resource.cpu_high", "severity": "warning",
                "resource_type": "router", "resource_id": "openwrt-office",
                "observed": 90, "threshold": 85,
            }],
        }, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(result["feature"], "F181")
        self.assertEqual(result["result"]["summary"]["new_alert_count"], 1)
        self.assertEqual(result["result"]["alerts"][0]["status"], "new")

    def test_router_gateway_redundancy_audit_is_available_through_authenticated_api(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password": "correct horse battery staple"})
        token = setup["token"]
        status, result = self.request("POST", "/api/features/router_gateway_redundancy_audit", {
            "snapshots": [
                {
                    "router_id": "openwrt-office",
                    "site_id": "office",
                    "snapshot": {
                        "adapter_id": "openwrt",
                        "captured_at": "2026-11-20T10:00:00Z",
                        "routes": [{
                            "target": "0.0.0.0/0", "gateway": "192.0.2.1",
                            "device": "wan", "metric": 10,
                        }],
                    },
                },
                {
                    "router_id": "mikrotik-office",
                    "site_id": "office",
                    "snapshot": {
                        "adapter_id": "mikrotik",
                        "captured_at": "2026-11-20T10:00:00Z",
                        "routes": [{
                            "target": "0.0.0.0/0", "gateway": "198.51.100.1",
                            "gateway_interface": "ether1", "routing_table": "main",
                            "distance": 1, "active": True,
                        }],
                    },
                },
            ],
        }, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(result["feature"], "F180")
        self.assertEqual(result["result"]["summary"]["router_count"], 2)
        self.assertEqual(result["result"]["groups"][0]["distinct_gateway_count"], 2)

    def test_router_vlan_segmentation_audit_is_available_through_authenticated_api(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password": "correct horse battery staple"})
        token = setup["token"]
        status, result = self.request("POST", "/api/features/router_vlan_segmentation_audit", {
            "snapshots": [{
                "router_id": "unifi-office",
                "site_id": "office",
                "snapshot": {
                    "adapter_id": "unifi",
                    "captured_at": "2026-11-20T10:00:00Z",
                    "controller": {"hostname": "unifi.office.local"},
                    "networks": [{
                        "id": "office", "name": "Office", "vlan_enabled": True,
                        "vlan_id": 20, "ip_subnet": "192.0.2.0/24",
                    }],
                },
            }],
        }, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(result["feature"], "F179")
        self.assertEqual(result["result"]["summary"]["segment_count"], 1)
        self.assertEqual(result["result"]["segments"][0]["vlan_id"], 20)

    def test_router_route_table_audit_is_available_through_authenticated_api(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password": "correct horse battery staple"})
        token = setup["token"]
        status, result = self.request("POST", "/api/features/router_route_table_audit", {
            "snapshots": [{
                "router_id": "openwrt-office",
                "site_id": "office",
                "snapshot": {
                    "adapter_id": "openwrt",
                    "captured_at": "2026-11-20T10:00:00Z",
                    "interfaces": [{"interface": "lan", "ipv4_addresses": ["192.0.2.2/24"]}],
                    "routes": [{
                        "target": "0.0.0.0/0", "gateway": "192.0.2.1",
                        "device": "wan", "metric": 10,
                    }],
                },
            }],
        }, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(result["feature"], "F178")
        self.assertEqual(result["result"]["summary"]["default_route_count"], 1)
        self.assertEqual(result["result"]["routers"][0]["route_count"], 1)

    def test_router_client_roaming_audit_is_available_through_authenticated_api(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password": "correct horse battery staple"})
        token = setup["token"]
        status, result = self.request("POST", "/api/features/router_client_roaming_audit", {
            "snapshots": [{
                "router_id": "unifi-office",
                "site_id": "office",
                "snapshot": {
                    "adapter_id": "unifi",
                    "captured_at": "2026-11-20T10:00:00Z",
                    "controller": {"hostname": "unifi.office.local"},
                    "associations": [{
                        "client_mac": "AA:BB:CC:DD:EE:01",
                        "ap_mac": "00:11:22:33:44:55",
                        "ssid": "Office",
                        "signal_dbm": -55,
                        "is_wired": False,
                    }],
                },
            }],
        }, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(result["feature"], "F177")
        self.assertEqual(result["result"]["summary"]["client_count"], 1)
        self.assertEqual(result["result"]["summary"]["observation_count"], 1)

    def test_router_subnet_overlap_audit_is_available_through_authenticated_api(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password": "correct horse battery staple"})
        token = setup["token"]
        status, result = self.request("POST", "/api/features/router_subnet_overlap_audit", {
            "snapshots": [
                {
                    "router_id": "openwrt-gateway",
                    "site_id": "home",
                    "snapshot": {
                        "adapter_id": "openwrt", "captured_at": "2026-11-20T10:00:00Z",
                        "interfaces": [{"interface": "lan", "ipv4_addresses": ["192.0.2.1/24"]}],
                    },
                },
                {
                    "router_id": "unifi-controller",
                    "site_id": "home",
                    "snapshot": {
                        "adapter_id": "unifi", "captured_at": "2026-11-20T10:00:00Z",
                        "controller": {"hostname": "unifi.home.local"},
                        "networks": [{"id": "lan", "name": "LAN", "ip_subnet": "192.0.2.0/24"}],
                    },
                },
            ],
        }, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(result["feature"], "F176")
        self.assertEqual(result["result"]["summary"]["duplicate_subnet_count"], 1)
        self.assertEqual(result["result"]["overlaps"][0]["overlap_type"], "duplicate")

    def test_router_fleet_health_audit_is_available_through_authenticated_api(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password": "correct horse battery staple"})
        token = setup["token"]
        status, result = self.request("POST", "/api/features/router_fleet_health_audit", {
            "now": "2026-11-20T10:00:00Z",
            "snapshots": [{
                "router_id": "mikrotik-office",
                "site_id": "office",
                "snapshot": {
                    "adapter_id": "mikrotik",
                    "captured_at": "2026-11-20T09:59:00Z",
                    "resource": {
                        "cpu_load_pct": 20,
                        "free_memory_bytes": 800,
                        "total_memory_bytes": 1000,
                    },
                    "interfaces": [{"name": "bridge", "state": "up"}],
                    "wireless_radios": [{"interface": "wifi1", "state": "up"}],
                    "associations": [],
                },
            }],
        }, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(result["feature"], "F175")
        self.assertEqual(result["result"]["summary"]["healthy_count"], 1)
        self.assertEqual(result["result"]["routers"][0]["adapter_id"], "mikrotik")

    def test_router_snapshot_drift_report_is_available_through_authenticated_api(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password": "correct horse battery staple"})
        token = setup["token"]
        status, result = self.request("POST", "/api/features/router_snapshot_drift_report", {
            "previous": {
                "adapter_id": "unifi",
                "captured_at": "2026-11-20T09:00:00Z",
                "access_points": [{"mac": "00:11:22:33:44:55", "name": "Office AP", "ip_address": "192.0.2.10"}],
            },
            "current": {
                "adapter_id": "unifi",
                "captured_at": "2026-11-20T10:00:00Z",
                "access_points": [{"mac": "00:11:22:33:44:55", "name": "Office AP", "ip_address": "192.0.2.11"}],
            },
        }, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(result["feature"], "F174")
        self.assertEqual(result["result"]["adapter_id"], "unifi")
        self.assertEqual(result["result"]["summary"]["access_points_changed"], 1)

    def test_mikrotik_snapshot_normalizer_is_available_through_authenticated_api(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password": "correct horse battery staple"})
        token = setup["token"]
        status, result = self.request("POST", "/api/features/mikrotik_snapshot_normalizer", {
            "captured_at": "2026-11-20T10:00:00Z",
            "router": {"board_name": "MikroTik sample", "version": "7.17.2"},
            "interfaces": [{"name": "bridge", "running": True}],
            "wireless": [{"name": "wifi1", "band": "5ghz-ax", "channel": 36, "channel_width": "80mhz"}],
            "addresses": [{"interface": "bridge", "address": "192.0.2.1/24"}],
            "vlans": [{"name": "vlan20", "interface": "bridge", "vlan_id": "20"}],
        }, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(result["feature"], "F173")
        self.assertEqual(result["result"]["adapter_id"], "mikrotik")
        self.assertEqual(result["result"]["summary"]["wireless_radio_count"], 1)
        self.assertEqual(result["result"]["vlans"][0]["vlan_id"], 20)

    def test_openwrt_snapshot_normalizer_is_available_through_authenticated_api(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password": "correct horse battery staple"})
        token = setup["token"]
        status, result = self.request("POST", "/api/adapters/openwrt/normalise", {
            "captured_at":"2026-11-20T10:00:00Z","board":{"model":"OpenWrt test router"},"interfaces":[],
        }, token=token)
        self.assertEqual(status, 200)
        self.assertEqual(result["feature"], "F162")
        self.assertEqual(result["result"]["adapter_id"], "openwrt")

    def test_router_agent_heartbeat_persists_and_health_endpoint_reports_agent_status(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password": "correct horse battery staple"})
        admin_token = setup["token"]
        agent_token = self.enroll_agent(admin_token, "openwrt-home", ["system.board", "wireless.radios"])
        heartbeat = {
            "agent_id": "openwrt-home", "adapter_id": "openwrt", "agent_version": "1.2.0",
            "status": "healthy", "capabilities": ["system.board", "wireless.radios", "untrusted.write"],
            "api_token": "must-not-be-persisted",
        }
        status, denied = self.request("POST", "/api/agents/heartbeat", heartbeat, token=admin_token)
        self.assertEqual(status, 401)
        status, saved = self.request("POST", "/api/agents/heartbeat", heartbeat, token=agent_token)
        self.assertEqual(status, 201)
        self.assertEqual(saved["agent"]["rejected_capabilities"], ["untrusted.write"])
        status, report = self.request("GET", "/api/agents/health", token=admin_token)
        self.assertEqual(status, 200)
        self.assertEqual(report["result"]["summary"]["agent_count"], 1)
        self.assertEqual(report["result"]["agents"][0]["health_status"], "healthy")
        self.assertNotIn("api_token", report["result"]["agents"][0])
        self.assertNotIn("untrusted.write", report["result"]["agents"][0]["capabilities"])
        status, updated = self.request("POST", "/api/agents/heartbeat", {**heartbeat, "status": "degraded"}, token=agent_token)
        self.assertEqual(status, 200)
        self.assertFalse(updated["agent"]["created"])
        self.assertEqual(updated["agent"]["status"], "degraded")
    def test_router_agent_heartbeat_requires_an_enrolled_agent_credential(self):
        status, denied = self.request("POST", "/api/agents/heartbeat", {
            "agent_id":"edge","adapter_id":"openwrt","agent_version":"1.0.0",
        })
        self.assertEqual(status, 401)
        _, setup = self.request("POST", "/api/auth/setup", {"password":"correct horse battery staple"})
        admin_token = setup["token"]
        agent_token = self.enroll_agent(admin_token, "edge", ["system.board"])
        for adapter_id in ("unifi", "mikrotik"):
            status, invalid = self.request("POST", "/api/agents/heartbeat", {
                "agent_id":"edge","adapter_id":adapter_id,"agent_version":"1.0.0",
            }, token=agent_token)
            self.assertEqual(status, 400)
            self.assertIn("not installed", invalid["error"])
        for field, value in (("status", []), ("error_code", {})):
            bad = {"agent_id":"edge","adapter_id":"openwrt","agent_version":"1.0.0",field:value}
            status, response = self.request("POST", "/api/agents/heartbeat", bad, token=agent_token)
            self.assertEqual(status, 400)
            self.assertIn(field, response["error"])
    def test_openwrt_agent_snapshot_is_retained_and_only_normalised_data_is_returned(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password":"correct horse battery staple"})
        admin_token = setup["token"]
        agent_token = self.enroll_agent(admin_token, "openwrt-home", ["system.board", "inventory.snapshot"])
        status, heartbeat = self.request("POST", "/api/agents/heartbeat", {
            "agent_id":"openwrt-home","adapter_id":"openwrt","agent_version":"1.2.0",
            "status":"healthy","capabilities":["system.board","inventory.snapshot"],
        }, token=agent_token)
        self.assertEqual(status, 201)
        raw_snapshot = {
            "captured_at":"2026-11-20T10:00:00Z",
            "board":{"model":"OpenWrt sample","release":{"distribution":"OpenWrt","version":"24.10.0"}},
            "interfaces":[{"interface":"lan","ipv4-address":[{"address":"192.168.1.1","mask":24}]}],
            "wireless":[{"interface":"phy0-ap0","ssid":"Home","bssid":"00:11:22:33:44:55","frequency_mhz":5180,"channel":36,"channel_width_mhz":80,"password":"never-store-me"}],
            "associations":[],
            "routes":[{"target":"0.0.0.0/0","nexthop":"192.168.1.1","device":"eth0"}],
        }
        status, saved = self.request("POST", "/api/agents/snapshot", {
            "agent_id":"openwrt-home","snapshot":raw_snapshot,
        }, token=agent_token)
        self.assertEqual(status, 201)
        self.assertEqual(saved["snapshot"]["wireless_radio_count"], 1)
        status, latest = self.request("GET", "/api/agents/snapshots/openwrt-home", token=admin_token)
        self.assertEqual(status, 200)
        self.assertEqual(latest["snapshot"]["snapshot"]["adapter_id"], "openwrt")
        self.assertNotIn("password", latest["snapshot"]["snapshot"]["wireless_radios"][0])
        status, listing = self.request("GET", "/api/agents/snapshots", token=admin_token)
        self.assertEqual(status, 200)
        self.assertEqual(len(listing["snapshots"]), 1)
        self.assertEqual(listing["snapshots"][0]["agent_id"], "openwrt-home")
        status, duplicate = self.request("POST", "/api/agents/snapshot", {
            "agent_id":"openwrt-home","snapshot":raw_snapshot,
        }, token=agent_token)
        self.assertEqual(status, 409)
        self.assertIn("already exists", duplicate["error"])
    def test_openwrt_agent_snapshot_requires_agent_credential_and_heartbeat(self):
        status, denied = self.request("POST", "/api/agents/snapshot", {
            "agent_id":"missing","snapshot":{"captured_at":"2026-11-20T10:00:00Z"}
        })
        self.assertEqual(status, 401)
        _, setup = self.request("POST", "/api/auth/setup", {"password":"correct horse battery staple"})
        admin_token = setup["token"]
        agent_token = self.enroll_agent(admin_token, "not-yet-online", ["system.board", "inventory.snapshot"])
        status, admin_denied = self.request("POST", "/api/agents/snapshot", {
            "agent_id":"not-yet-online","snapshot":{"captured_at":"2026-11-20T10:00:00Z","board":{}}
        }, token=admin_token)
        self.assertEqual(status, 401)
        status, rejected = self.request("POST", "/api/agents/snapshot", {
            "agent_id":"not-yet-online","snapshot":{"captured_at":"2026-11-20T10:00:00Z","board":{}}
        }, token=agent_token)
        self.assertEqual(status, 400)
        self.assertIn("heartbeat", rejected["error"])
    def test_openwrt_agent_snapshot_requires_credential_inventory_capability(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password":"correct horse battery staple"})
        admin_token = setup["token"]
        agent_token = self.enroll_agent(admin_token, "openwrt-no-inventory", ["system.board"])
        status, _ = self.request("POST", "/api/agents/heartbeat", {
            "agent_id":"openwrt-no-inventory","adapter_id":"openwrt","agent_version":"1.2.0",
            "status":"healthy","capabilities":["system.board"],
        }, token=agent_token)
        self.assertEqual(status, 201)
        status, rejected = self.request("POST", "/api/agents/snapshot", {
            "agent_id":"openwrt-no-inventory",
            "snapshot":{"captured_at":"2026-11-20T10:00:00Z","board":{}},
        }, token=agent_token)
        self.assertEqual(status, 400)
        self.assertIn("credential does not include", rejected["error"])
    def test_openwrt_agent_snapshot_diff_endpoint_compares_two_retained_captures(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password":"correct horse battery staple"})
        admin_token = setup["token"]
        agent_token = self.enroll_agent(admin_token, "diff-agent", ["system.board", "inventory.snapshot"])
        self.request("POST", "/api/agents/heartbeat", {
            "agent_id":"diff-agent","adapter_id":"openwrt","agent_version":"1.2.0",
            "status":"healthy","capabilities":["system.board","inventory.snapshot"],
        }, token=agent_token)
        def capture(when, channel, kernel):
            snapshot = {
                "captured_at":when,
                "board":{"model":"Router","kernel":kernel},
                "interfaces":[{"interface":"lan","up":True}],
                "wireless":[{"interface":"phy0-ap0","ssid":"Home","bssid":"00:11:22:33:44:55","frequency_mhz":5180,"channel":channel,"channel_width_mhz":80}],
                "associations":[],
                "routes":[],
            }
            return self.request("POST", "/api/agents/snapshot", {
                "agent_id":"diff-agent","snapshot":snapshot,
            }, token=agent_token)
        self.assertEqual(capture("2026-11-20T09:00:00Z",36,"6.6.1")[0],201)
        self.assertEqual(capture("2026-11-20T10:00:00Z",40,"6.6.2")[0],201)
        status, report = self.request("GET", "/api/agents/snapshots/diff-agent/diff", token=admin_token)
        self.assertEqual(status, 200)
        self.assertEqual(report["result"]["status"], "compared")
        self.assertEqual(report["result"]["summary"]["board_changed_field_count"], 1)
        self.assertEqual(report["result"]["summary"]["radio_changed"], 1)

    def test_agent_credentials_are_scoped_rotatable_revocable_and_never_listed(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password":"correct horse battery staple"})
        admin_token = setup["token"]
        capabilities = ["system.board", "inventory.snapshot"]
        agent_token = self.enroll_agent(admin_token, "managed-openwrt", capabilities)
        self.assertTrue(agent_token.startswith("wpa_"))
        status, catalogue = self.request("GET", "/api/agents/credentials", token=admin_token)
        self.assertEqual(status, 200)
        credential = catalogue["credentials"][0]
        self.assertEqual(credential["agent_id"], "managed-openwrt")
        self.assertEqual(credential["status"], "active")
        self.assertEqual(credential["allowed_capabilities"], ["inventory.snapshot", "system.board"])
        self.assertNotIn("token", credential)
        self.assertNotIn("token_hash", credential)

        bad_scope = {
            "agent_id":"managed-openwrt","adapter_id":"openwrt","agent_version":"1.2.0",
            "status":"healthy","capabilities":["system.board","wireless.config.write"],
        }
        status, filtered = self.request("POST", "/api/agents/heartbeat", bad_scope, token=agent_token)
        self.assertEqual(status, 201)
        self.assertEqual(filtered["agent"]["capabilities"], ["system.board"])
        self.assertEqual(filtered["agent"]["rejected_capabilities"], ["wireless.config.write"])

        status, rotated = self.request("POST", "/api/agents/managed-openwrt/credentials/rotate", {}, token=admin_token)
        self.assertEqual(status, 200)
        new_token = rotated["credential"]["token"]
        self.assertNotEqual(agent_token, new_token)
        status, old_denied = self.request("POST", "/api/agents/heartbeat", {
            "agent_id":"managed-openwrt","adapter_id":"openwrt","agent_version":"1.2.0",
        }, token=agent_token)
        self.assertEqual(status, 401)
        status, new_allowed = self.request("POST", "/api/agents/heartbeat", {
            "agent_id":"managed-openwrt","adapter_id":"openwrt","agent_version":"1.2.0",
            "capabilities":["system.board"],
        }, token=new_token)
        self.assertEqual(status, 200)

        status, revoked = self.request("POST", "/api/agents/managed-openwrt/credentials/revoke", {}, token=admin_token)
        self.assertEqual(status, 200)
        self.assertTrue(revoked["credential"]["revoked"])
        status, revoked_denied = self.request("POST", "/api/agents/heartbeat", {
            "agent_id":"managed-openwrt","adapter_id":"openwrt","agent_version":"1.2.0",
        }, token=new_token)
        self.assertEqual(status, 401)
        status, final = self.request("GET", "/api/agents/credentials", token=admin_token)
        self.assertEqual(status, 200)
        self.assertEqual(final["credentials"][0]["status"], "revoked")

    def test_router_agent_inventory_and_management_are_filtered_by_site_scope(self):
        _, setup = self.request("POST", "/api/auth/setup", {
            "password": "owner passphrase is secure",
        })
        owner_token = setup["token"]
        home_token = self.enroll_agent(
            owner_token, "scope-agent-home", ["system.board", "inventory.snapshot"], site_id="home"
        )
        branch_token = self.enroll_agent(
            owner_token, "scope-agent-branch", ["system.board", "inventory.snapshot"], site_id="branch"
        )
        for agent_id, token in (
            ("scope-agent-home", home_token),
            ("scope-agent-branch", branch_token),
        ):
            status, heartbeat = self.request("POST", "/api/agents/heartbeat", {
                "agent_id": agent_id, "adapter_id": "openwrt", "agent_version": "1.2.0",
                "status": "healthy", "capabilities": ["system.board", "inventory.snapshot"],
            }, token=token)
            self.assertIn(status, (200, 201), heartbeat)

        status, user = self.request("POST", "/api/users", {
            "username": "home.netadmin", "password": "home network admin password",
            "role": "network_admin", "all_sites": False, "site_ids": ["home"],
        }, token=owner_token)
        self.assertEqual(status, 201, user)
        site_admin = self.request("POST", "/api/auth/login", {
            "username": "home.netadmin", "password": "home network admin password",
        })[1]["token"]

        status, site_catalog = self.request("GET", "/api/sites", token=site_admin)
        self.assertEqual(status, 200)
        self.assertEqual(site_catalog["site_ids"], ["home"])

        status, credentials = self.request("GET", "/api/agents/credentials", token=site_admin)
        self.assertEqual(status, 200)
        self.assertEqual([item["agent_id"] for item in credentials["credentials"]], ["scope-agent-home"])
        self.assertEqual(credentials["credentials"][0]["site_id"], "home")

        status, health = self.request("GET", "/api/agents/health", token=site_admin)
        self.assertEqual(status, 200)
        self.assertEqual(
            {item["agent_id"] for item in health["result"]["agents"]},
            {"scope-agent-home"},
        )

        status, denied = self.request(
            "POST", "/api/agents/scope-agent-branch/credentials/rotate", {}, token=site_admin,
        )
        self.assertEqual(status, 404)
        status, denied = self.request(
            "POST", "/api/agents/scope-agent-branch/credentials/revoke", {}, token=site_admin,
        )
        self.assertEqual(status, 404)
        status, denied = self.request(
            "GET", "/api/agents/snapshots/scope-agent-branch", token=site_admin,
        )
        self.assertEqual(status, 404)

        status, denied = self.request("POST", "/api/agents/enroll", {
            "agent_id": "scope-agent-outside", "adapter_id": "openwrt", "agent_version": "1.2.0",
            "advertised_capabilities": ["system.board", "inventory.snapshot"],
            "requested_capabilities": ["system.board", "inventory.snapshot"],
            "requested_permissions": ["read"], "site_id": "branch",
        }, token=site_admin)
        self.assertEqual(status, 403)

        status, updated = self.request("POST", "/api/agents/scope-agent-home/site", {
            "site_id": "branch",
        }, token=site_admin)
        self.assertEqual(status, 403)
        status, updated = self.request("POST", "/api/agents/scope-agent-home/site", {
            "site_id": "home",
        }, token=site_admin)
        self.assertEqual(status, 200)
        self.assertEqual(updated["assignment"]["site_id"], "home")

    def test_agent_enrollment_rejects_write_scopes_and_duplicate_active_agents(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password":"correct horse battery staple"})
        admin_token = setup["token"]
        denied_scope = {
            "agent_id":"least-privilege","adapter_id":"openwrt","agent_version":"1.2.0",
            "advertised_capabilities":["system.board","inventory.snapshot"],
            "requested_capabilities":["system.board","inventory.snapshot"],
            "requested_permissions":["read","config.write"],
        }
        status, denied = self.request("POST", "/api/agents/enroll", denied_scope, token=admin_token)
        self.assertEqual(status, 400)
        self.assertIn("read permission", denied["error"])
        self.enroll_agent(admin_token, "least-privilege", ["system.board"])
        status, duplicate = self.request("POST", "/api/agents/enroll", {
            **denied_scope,
            "requested_permissions":["read"],
            "advertised_capabilities":["system.board"],
            "requested_capabilities":["system.board"],
        }, token=admin_token)
        self.assertEqual(status, 409)
        self.assertIn("rotate", duplicate["error"])


    def test_openwrt_snapshot_delivery_is_idempotent_and_rejects_payload_reuse(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password":"correct horse battery staple"})
        admin_token = setup["token"]
        agent_token = self.enroll_agent(
            admin_token, "delivery-agent", ["system.board", "system.health", "inventory.snapshot"]
        )
        status, heartbeat = self.request("POST", "/api/agents/heartbeat", {
            "agent_id":"delivery-agent","adapter_id":"openwrt","agent_version":"1.2.0",
            "status":"healthy","capabilities":["system.board","system.health","inventory.snapshot"],
        }, token=agent_token)
        self.assertEqual(status, 201)
        delivery_id = "6c6329b5-8611-4c45-8926-5d6a85bc9f7d"
        snapshot = {
            "captured_at":"2026-11-20T10:00:00Z",
            "board":{"model":"OpenWrt sample","release":{"distribution":"OpenWrt","version":"24.10.0"}},
            "interfaces":[{"interface":"lan","ipv4-address":[{"address":"192.168.1.1","mask":24}]}],
            "wireless":[{"interface":"phy0-ap0","ssid":"Home","bssid":"00:11:22:33:44:55","frequency_mhz":5180,"channel":36,"channel_width_mhz":80}],
            "associations":[],
            "routes":[{"target":"0.0.0.0/0","nexthop":"192.168.1.1","device":"eth0"}],
            "system_health":{
                "uptime_seconds":1234,
                "load_average":{"1m":1.0,"5m":0.5,"15m":0.25},
                "memory_bytes":{"total":1048576,"free":524288,"available":540672},
                "swap_bytes":{"total":262144,"free":131072},
            },
        }
        payload = {"agent_id":"delivery-agent","delivery_id":delivery_id,"snapshot":snapshot}
        status, first = self.request("POST", "/api/agents/snapshots/batch", payload, token=agent_token)
        self.assertEqual(status, 201)
        self.assertFalse(first["delivery"]["replayed"])
        status, retry = self.request("POST", "/api/agents/snapshots/batch", payload, token=agent_token)
        self.assertEqual(status, 200)
        self.assertTrue(retry["delivery"]["replayed"])
        self.assertEqual(retry["delivery"]["id"], first["delivery"]["id"])
        status, latest = self.request("GET", "/api/agents/snapshots/delivery-agent", token=admin_token)
        self.assertEqual(status, 200)
        health = latest["snapshot"]["snapshot"]["system_health"]
        self.assertEqual(health["uptime_seconds"], 1234)
        self.assertEqual(health["load_average"]["1m"], 1.0)
        self.assertEqual(health["memory_bytes"]["available"], 540672)

        changed = {**snapshot, "board": {"model":"Different router"}}
        status, conflict = self.request("POST", "/api/agents/snapshots/batch", {
            **payload, "snapshot":changed,
        }, token=agent_token)
        self.assertEqual(status, 409)
        self.assertIn("different snapshot contents", conflict["error"])

        status, invalid = self.request("POST", "/api/agents/snapshots/batch", {
            "agent_id":"delivery-agent","delivery_id":"invalid","snapshot":snapshot,
        }, token=agent_token)
        self.assertEqual(status, 400)
        self.assertIn("UUID", invalid["error"])

        status, denied = self.request("POST", "/api/agents/snapshots/batch", payload)
        self.assertEqual(status, 401)

    def test_snapshot_health_metrics_require_credential_and_heartbeat_scope(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password":"correct horse battery staple"})
        admin_token = setup["token"]
        token_without_health = self.enroll_agent(
            admin_token, "no-health-agent", ["system.board", "inventory.snapshot"]
        )
        self.request("POST", "/api/agents/heartbeat", {
            "agent_id":"no-health-agent","adapter_id":"openwrt","agent_version":"1.2.0",
            "capabilities":["system.board","inventory.snapshot"],
        }, token=token_without_health)
        snapshot = {
            "captured_at":"2026-11-20T10:00:00Z",
            "board":{},
            "interfaces":[],
            "wireless":[],
            "associations":[],
            "routes":[],
            "system_health":{
                "uptime_seconds":10,
                "load_average":{"1m":0.1,"5m":0.1,"15m":0.1},
                "memory_bytes":{"total":1024,"free":512},
                "swap_bytes":{"total":0,"free":0},
            },
        }
        status, denied = self.request("POST", "/api/agents/snapshots/batch", {
            "agent_id":"no-health-agent",
            "delivery_id":"6c6329b5-8611-4c45-8926-5d6a85bc9f7e",
            "snapshot":snapshot,
        }, token=token_without_health)
        self.assertEqual(status, 400)
        self.assertIn("credential does not include the system.health", denied["error"])

        token_with_health = self.enroll_agent(
            admin_token, "not-negotiated-health", ["system.board", "system.health", "inventory.snapshot"]
        )
        self.request("POST", "/api/agents/heartbeat", {
            "agent_id":"not-negotiated-health","adapter_id":"openwrt","agent_version":"1.2.0",
            "capabilities":["system.board","inventory.snapshot"],
        }, token=token_with_health)
        status, denied = self.request("POST", "/api/agents/snapshots/batch", {
            "agent_id":"not-negotiated-health",
            "delivery_id":"6c6329b5-8611-4c45-8926-5d6a85bc9f7f",
            "snapshot":snapshot,
        }, token=token_with_health)
        self.assertEqual(status, 400)
        self.assertIn("not negotiated the system.health", denied["error"])

    def test_concurrent_snapshot_delivery_retries_share_one_acknowledgement(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password":"correct horse battery staple"})
        admin_token = setup["token"]
        agent_token = self.enroll_agent(admin_token, "parallel-delivery", ["system.board", "inventory.snapshot"])
        self.request("POST", "/api/agents/heartbeat", {
            "agent_id":"parallel-delivery","adapter_id":"openwrt","agent_version":"1.2.0",
            "status":"healthy","capabilities":["system.board","inventory.snapshot"],
        }, token=agent_token)
        payload = {
            "agent_id":"parallel-delivery",
            "delivery_id":"b8a29c1f-6af2-4f37-92d2-2db31ce890c1",
            "snapshot":{
                "captured_at":"2026-11-20T10:00:00Z",
                "board":{"model":"Parallel retry router"},
                "interfaces":[{"interface":"lan"}],
                "wireless":[],
                "associations":[],
                "routes":[],
            },
        }
        barrier = threading.Barrier(2)
        def send():
            barrier.wait(timeout=2)
            return self.request("POST", "/api/agents/snapshots/batch", payload, token=agent_token)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = [future.result(timeout=8) for future in (pool.submit(send), pool.submit(send))]
        self.assertEqual(sorted(status for status, _ in results), [200, 201])
        snapshot_ids = {body["delivery"]["id"] for _, body in results}
        self.assertEqual(len(snapshot_ids), 1)
        self.assertEqual(sum(body["delivery"]["replayed"] for _, body in results), 1)


    def test_named_users_are_authenticated_separately_and_permissions_are_enforced(self):
        status, setup = self.request("POST", "/api/auth/setup", {
            "username": "office.owner",
            "password": "owner passphrase is secure",
        })
        self.assertEqual(status, 201)
        owner_token = setup["token"]
        self.assertEqual(setup["status"]["identity"]["role"], "owner")

        status, created = self.request("POST", "/api/users", {
            "username": "floor.analyst",
            "password": "analyst password secure",
            "role": "analyst",
        }, token=owner_token)
        self.assertEqual(status, 201, created)
        user = created["user"]
        self.assertEqual(user["role"], "analyst")
        self.assertNotIn("salt", user)
        self.assertNotIn("verifier", user)

        status, login = self.request("POST", "/api/auth/login", {
            "username": "FLOOR.ANALYST",
            "password": "analyst password secure",
        })
        self.assertEqual(status, 200)
        analyst_token = login["token"]
        self.assertEqual(login["status"]["identity"]["username"], "floor.analyst")

        status, catalog = self.request("GET", "/api/features", token=analyst_token)
        self.assertEqual(status, 200)
        self.assertEqual(catalog["count"], 189)

        status, result = self.request("POST", "/api/features/frequency_to_channel", {
            "frequency_mhz": 5975,
        }, token=analyst_token)
        self.assertEqual(status, 200)
        self.assertEqual(result["result"]["channel"], 5)

        status, denied = self.request("POST", "/api/agents/enroll", {}, token=analyst_token)
        self.assertEqual(status, 403)
        self.assertEqual(denied["required_permission"], "agents.manage")

        status, denied = self.request("GET", "/api/agents/credentials", token=analyst_token)
        self.assertEqual(status, 403)
        self.assertEqual(denied["required_permission"], "agents.manage")

    def test_viewer_is_read_only_and_cannot_run_diagnostics_or_manage_users(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password": "owner passphrase is secure"})
        owner_token = setup["token"]
        _, created = self.request("POST", "/api/users", {
            "username": "office.viewer",
            "password": "viewer passphrase secure",
            "role": "viewer",
        }, token=owner_token)
        status, login = self.request("POST", "/api/auth/login", {
            "username": "office.viewer",
            "password": "viewer passphrase secure",
        })
        self.assertEqual(status, 200)
        viewer_token = login["token"]

        status, _ = self.request("GET", "/api/features", token=viewer_token)
        self.assertEqual(status, 200)
        status, denied = self.request("POST", "/api/features/frequency_to_channel", {
            "frequency_mhz": 5975,
        }, token=viewer_token)
        self.assertEqual(status, 403)
        self.assertEqual(denied["required_permission"], "diagnostics.run")

        status, denied = self.request("POST", "/api/users", {
            "username": "intruder", "password": "some long password", "role": "viewer",
        }, token=viewer_token)
        self.assertEqual(status, 403)
        self.assertEqual(denied["required_permission"], "users.manage")

        status, denied = self.request("POST", "/api/sites/history", {}, token=viewer_token)
        self.assertEqual(status, 403)
        self.assertEqual(denied["required_permission"], "sites.manage")

    def test_network_admin_can_manage_agents_but_not_the_user_directory(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password": "owner passphrase is secure"})
        owner_token = setup["token"]
        status, created = self.request("POST", "/api/users", {
            "username": "network.ops",
            "password": "network admin password",
            "role": "network_admin",
        }, token=owner_token)
        self.assertEqual(status, 201)
        status, login = self.request("POST", "/api/auth/login", {
            "username": "network.ops", "password": "network admin password",
        })
        self.assertEqual(status, 200)
        token = login["token"]

        status, _ = self.request("GET", "/api/agents/credentials", token=token)
        self.assertEqual(status, 200)
        status, denied = self.request("GET", "/api/users", token=token)
        self.assertEqual(status, 403)
        self.assertEqual(denied["required_permission"], "users.manage")

    def test_user_directory_lists_only_safe_metadata_and_owner_cannot_be_disabled(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password": "owner passphrase is secure"})
        owner_token = setup["token"]
        status, created = self.request("POST", "/api/users", {
            "username": "temporary.user",
            "password": "temporary user password",
            "role": "viewer",
        }, token=owner_token)
        self.assertEqual(status, 201)
        status, listing = self.request("GET", "/api/users", token=owner_token)
        self.assertEqual(status, 200)
        self.assertEqual(len(listing["users"]), 2)
        self.assertNotIn("salt", json.dumps(listing))
        self.assertNotIn("verifier", json.dumps(listing))

        owner_id = setup["status"]["identity"]["id"]
        status, denied = self.request("POST", f"/api/users/{owner_id}/update", {
            "enabled": False,
        }, token=owner_token)
        self.assertEqual(status, 403)
        self.assertIn("owner account", denied["error"])

        status, updated = self.request("POST", f"/api/users/{created['user']['id']}/update", {
            "enabled": False,
        }, token=owner_token)
        self.assertEqual(status, 200)
        self.assertFalse(updated["user"]["enabled"])

    def test_security_audit_is_permission_gated_persisted_and_verifiable(self):
        status, setup = self.request("POST", "/api/auth/setup", {
            "username": "workspace.owner", "password": "owner passphrase is secure",
        })
        self.assertEqual(status, 201)
        owner_token = setup["token"]

        status, created = self.request("POST", "/api/users", {
            "username": "audit.viewer", "password": "viewer password secure", "role": "viewer",
        }, token=owner_token)
        self.assertEqual(status, 201)
        status, viewer_login = self.request("POST", "/api/auth/login", {
            "username": "audit.viewer", "password": "viewer password secure",
        })
        self.assertEqual(status, 200)
        viewer_token = viewer_login["token"]

        status, denied = self.request("POST", "/api/agents/enroll", {}, token=viewer_token)
        self.assertEqual(status, 403)
        self.assertEqual(denied["required_permission"], "agents.manage")

        status, hidden = self.request("GET", "/api/security/audit", token=viewer_token)
        self.assertEqual(status, 403)
        status, audit = self.request("GET", "/api/security/audit?limit=100", token=owner_token)
        self.assertEqual(status, 200)
        actions = {event["action"] for event in audit["events"]}
        self.assertIn("auth.setup.completed", actions)
        self.assertIn("auth.login.succeeded", actions)
        self.assertIn("user.created", actions)
        self.assertIn("authorization.denied", actions)
        self.assertNotIn("viewer password secure", json.dumps(audit))
        self.assertNotIn(owner_token, json.dumps(audit))

        status, verification = self.request("GET", "/api/security/audit/verify", token=owner_token)
        self.assertEqual(status, 200)
        self.assertTrue(verification["verification"]["valid"])
        self.assertEqual(verification["verification"]["event_count"], len(audit["events"]))

        status, checkpoint_denied = self.request("GET", "/api/security/audit/checkpoint", token=viewer_token)
        self.assertEqual(status, 403)
        self.assertEqual(checkpoint_denied["required_permission"], "users.manage")

        status, latest_audit = self.request("GET", "/api/security/audit?limit=100", token=owner_token)
        self.assertEqual(status, 200)

        status, checkpoint_response = self.request("GET", "/api/security/audit/checkpoint", token=owner_token)
        self.assertEqual(status, 200)
        bundle = checkpoint_response["checkpoint"]
        verified = verify_signed_checkpoint(
            bundle,
            expected_public_key_fingerprint=bundle["public_key_fingerprint"],
        )
        self.assertTrue(verified["valid"], verified)
        self.assertEqual(bundle["checkpoint"]["event_count"], len(latest_audit["events"]))
        tampered = dict(bundle)
        tampered["checkpoint"] = {**bundle["checkpoint"], "event_count": bundle["checkpoint"]["event_count"] + 1}
        self.assertFalse(verify_signed_checkpoint(tampered)["valid"])

    def test_live_capture_routes_require_diagnostics_run_and_pass_only_bounded_options(self):
        _, setup = self.request("POST", "/api/auth/setup", {
            "username": "capture.owner", "password": "capture owner password",
        })
        owner_token = setup["token"]
        status, created = self.request("POST", "/api/users", {
            "username": "capture.viewer", "password": "capture viewer password", "role": "viewer",
        }, token=owner_token)
        self.assertEqual(status, 201)
        self.assertEqual(created["user"]["role"], "viewer")
        _, login = self.request("POST", "/api/auth/login", {
            "username": "capture.viewer", "password": "capture viewer password",
        })
        viewer_token = login["token"]

        status, _ = self.request("GET", "/api/capture/interfaces", token=viewer_token)
        self.assertEqual(status, 403)
        status, _ = self.request("GET", "/api/capture/status", token=viewer_token)
        self.assertEqual(status, 403)
        status, _ = self.request("POST", "/api/capture/start", {
            "interface": "eth0",
        }, token=viewer_token)
        self.assertEqual(status, 403)
        status, _ = self.request("POST", "/api/capture/stop", {
            "capture_id": "a" * 32,
        }, token=viewer_token)
        self.assertEqual(status, 403)
        server.LIVE_CAPTURE.start.assert_not_called()
        server.LIVE_CAPTURE.stop.assert_not_called()

        status, inventory = self.request("GET", "/api/capture/interfaces", token=owner_token)
        self.assertEqual(status, 200)
        self.assertEqual(inventory["interfaces"][0]["name"], "eth0")
        status, current = self.request("GET", "/api/capture/status", token=owner_token)
        self.assertEqual(status, 200)
        self.assertIsNone(current["capture"])

        started = {
            "capture_id": "b" * 32, "interface": "eth0", "filter_profile": "dns",
            "duration_limit_seconds": 15, "packet_limit": 250, "state": "running",
            "started_at": "2026-11-21T00:00:00Z", "finished_at": None,
            "captured_bytes": 0, "error": None,
        }
        server.LIVE_CAPTURE.start.return_value = started
        status, response = self.request("POST", "/api/capture/start", {
            "interface": "eth0", "duration_seconds": 15,
            "packet_limit": 250, "filter_profile": "dns",
        }, token=owner_token)
        self.assertEqual(status, 201)
        self.assertEqual(response["capture"]["capture_id"], "b" * 32)
        server.LIVE_CAPTURE.start.assert_called_once_with(
            interface="eth0", duration_seconds=15, packet_limit=250, filter_profile="dns",
        )

        stopped = {**started, "state": "completed", "captured_bytes": 24}
        server.LIVE_CAPTURE.stop.return_value = stopped
        status, response = self.request("POST", "/api/capture/stop", {
            "capture_id": "b" * 32,
        }, token=owner_token)
        self.assertEqual(status, 200)
        self.assertEqual(response["capture"]["state"], "completed")
        server.LIVE_CAPTURE.stop.assert_called_once_with("b" * 32)

    def test_agent_negotiations_are_persisted_versioned_and_append_only(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password":"correct horse battery staple"})
        admin_token = setup["token"]
        self.enroll_agent(admin_token, "audit-agent", ["system.board"])
        status, history = self.request("GET", "/api/agents/audit-agent/negotiations", token=admin_token)
        self.assertEqual(status, 200)
        self.assertEqual(len(history["negotiations"]), 1)
        first = history["negotiations"][0]
        self.assertEqual(first["negotiation"]["adapter_id"], "openwrt")
        self.assertEqual(first["negotiation"]["adapter_version"], "0.1.0")
        self.assertEqual(first["negotiation"]["capability_schema_version"], "1.0")
        self.assertEqual(first["negotiation"]["advertised_capabilities"], ["system.board"])
        self.assertEqual(first["negotiation"]["requested_capabilities"], ["system.board"])
        self.assertEqual(first["negotiation"]["negotiated_capabilities"], ["system.board"])
        self.assertEqual(first["negotiation"]["permission"], "read")
        self.assertNotIn("token", first)
        self.assertNotIn("token_hash", first["negotiation"])

        status, latest = self.request("GET", "/api/agents/negotiations", token=admin_token)
        self.assertEqual(status, 200)
        self.assertEqual(len(latest["negotiations"]), 1)
        self.assertEqual(latest["negotiations"][0]["id"], first["id"])

        self.request("POST", "/api/agents/audit-agent/credentials/revoke", {}, token=admin_token)
        self.enroll_agent(admin_token, "audit-agent", ["system.board", "inventory.snapshot"])
        status, history = self.request("GET", "/api/agents/audit-agent/negotiations", token=admin_token)
        self.assertEqual(status, 200)
        self.assertEqual(len(history["negotiations"]), 2)
        second = history["negotiations"][-1]
        self.assertGreater(second["id"], first["id"])
        self.assertEqual(
            second["negotiation"]["negotiated_capabilities"],
            ["inventory.snapshot", "system.board"],
        )
        self.assertEqual(history["negotiations"][0]["id"], first["id"])


if __name__ == "__main__":
    unittest.main()
