"""HTTP integration tests for the local account gate and feature API."""
from __future__ import annotations

import concurrent.futures
import json
import tempfile
import threading
import unittest
from pathlib import Path
from http.client import HTTPConnection

from wifi_analyzer_backend import server
from wifi_analyzer_backend.auth import AuthManager
from wifi_analyzer_backend.router_adapters.health_store import RouterAgentHealthStore


class AuthenticatedApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.previous_auth = server.AUTH
        self.previous_history = server.HISTORY
        self.previous_agent_health = server.AGENT_HEALTH
        server.AUTH = AuthManager(path=str(Path(self.temp.name) / "auth.json"), session_ttl_seconds=300)
        server.HISTORY = __import__("wifi_analyzer_backend.site_history", fromlist=["SiteHistoryStore"]).SiteHistoryStore(path=str(Path(self.temp.name) / "history.sqlite3"))
        server.AGENT_HEALTH = RouterAgentHealthStore(path=str(Path(self.temp.name) / "agent-health.sqlite3"))
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
        self.temp.cleanup()

    def request(self, method, path, payload=None, token=None, origin=None):
        headers = {}
        body = None
        if payload is not None:
            body = json.dumps(payload)
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if origin:
            headers["Origin"] = origin
        connection = HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
        finally:
            connection.close()


    def enroll_agent(self, admin_token, agent_id, capabilities):
        status, response = self.request("POST", "/api/agents/enroll", {
            "agent_id": agent_id,
            "adapter_id": "openwrt",
            "agent_version": "1.2.0",
            "advertised_capabilities": capabilities,
            "requested_capabilities": capabilities,
            "requested_permissions": ["read"],
        }, token=admin_token)
        self.assertEqual(status, 201, response)
        return response["credential"]["token"]

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
        self.assertEqual(catalog["count"], 184)
        self.assertEqual(len(catalog["features"]), 184)
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
        from wifi_analyzer_backend.feature_plugins.feature_182_router_audit_report_bundle_builder import run as build_report
        _, setup = self.request("POST", "/api/auth/setup", {"password": "correct horse battery staple"})
        token = setup["token"]
        previous = build_report({
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
        current = build_report({
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
