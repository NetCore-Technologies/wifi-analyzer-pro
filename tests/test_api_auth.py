"""HTTP integration tests for the local account gate and feature API."""
from __future__ import annotations

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
        self.assertEqual(catalog["count"], 164)
        self.assertEqual(len(catalog["features"]), 164)
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
        self.assertEqual(catalogue["count"], 1)
        self.assertEqual(catalogue["adapters"][0]["adapter_id"], "openwrt")
        self.assertTrue(catalogue["adapters"][0]["read_only"])

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
        token = setup["token"]
        heartbeat = {
            "agent_id": "openwrt-home",
            "adapter_id": "openwrt",
            "agent_version": "1.2.0",
            "status": "healthy",
            "capabilities": ["system.board", "wireless.radios", "untrusted.write"],
            "api_token": "must-not-be-persisted",
        }
        status, saved = self.request("POST", "/api/agents/heartbeat", heartbeat, token=token)
        self.assertEqual(status, 201)
        self.assertEqual(saved["agent"]["rejected_capabilities"], ["untrusted.write"])
        status, report = self.request("GET", "/api/agents/health", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(report["result"]["summary"]["agent_count"], 1)
        self.assertEqual(report["result"]["agents"][0]["health_status"], "healthy")
        self.assertNotIn("api_token", report["result"]["agents"][0])
        self.assertNotIn("untrusted.write", report["result"]["agents"][0]["capabilities"])

        status, updated = self.request("POST", "/api/agents/heartbeat", {**heartbeat, "status": "degraded"}, token=token)
        self.assertEqual(status, 200)
        self.assertFalse(updated["agent"]["created"])
        self.assertEqual(updated["agent"]["status"], "degraded")

    def test_router_agent_heartbeat_requires_authentication_and_rejects_unknown_adapter(self):
        status, denied = self.request("POST", "/api/agents/heartbeat", {"agent_id":"edge","adapter_id":"openwrt","agent_version":"1.0.0"})
        self.assertEqual(status, 401)
        _, setup = self.request("POST", "/api/auth/setup", {"password": "correct horse battery staple"})
        status, invalid = self.request("POST", "/api/agents/heartbeat", {
            "agent_id":"edge","adapter_id":"unifi","agent_version":"1.0.0",
        }, token=setup["token"])
        self.assertEqual(status, 400)
        self.assertIn("not installed", invalid["error"])

        for field, value in (("status", []), ("error_code", {})):
            bad = {"agent_id":"edge","adapter_id":"openwrt","agent_version":"1.0.0",field:value}
            status, response = self.request("POST", "/api/agents/heartbeat", bad, token=setup["token"])
            self.assertEqual(status, 400)
            self.assertIn(field, response["error"])


    def test_openwrt_agent_snapshot_is_retained_and_only_normalised_data_is_returned(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password":"correct horse battery staple"})
        token = setup["token"]
        status, heartbeat = self.request("POST", "/api/agents/heartbeat", {
            "agent_id":"openwrt-home","adapter_id":"openwrt","agent_version":"1.2.0",
            "status":"healthy","capabilities":["inventory.snapshot"],
        }, token=token)
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
        }, token=token)
        self.assertEqual(status, 201)
        self.assertEqual(saved["snapshot"]["wireless_radio_count"], 1)
        status, latest = self.request("GET", "/api/agents/snapshots/openwrt-home", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(latest["snapshot"]["snapshot"]["adapter_id"], "openwrt")
        self.assertNotIn("password", latest["snapshot"]["snapshot"]["wireless_radios"][0])
        status, listing = self.request("GET", "/api/agents/snapshots", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(len(listing["snapshots"]), 1)
        self.assertEqual(listing["snapshots"][0]["agent_id"], "openwrt-home")
        status, duplicate = self.request("POST", "/api/agents/snapshot", {
            "agent_id":"openwrt-home","snapshot":raw_snapshot,
        }, token=token)
        self.assertEqual(status, 409)
        self.assertIn("already exists", duplicate["error"])

    def test_openwrt_agent_snapshot_requires_registered_agent_and_authentication(self):
        status, denied = self.request("POST", "/api/agents/snapshot", {
            "agent_id":"missing","snapshot":{"captured_at":"2026-11-20T10:00:00Z"}
        })
        self.assertEqual(status, 401)
        _, setup = self.request("POST", "/api/auth/setup", {"password":"correct horse battery staple"})
        status, rejected = self.request("POST", "/api/agents/snapshot", {
            "agent_id":"missing","snapshot":{"captured_at":"2026-11-20T10:00:00Z"}
        }, token=setup["token"])
        self.assertEqual(status, 400)
        self.assertIn("heartbeat", rejected["error"])


    def test_openwrt_agent_snapshot_requires_negotiated_inventory_capability(self):
        _, setup = self.request("POST", "/api/auth/setup", {"password":"correct horse battery staple"})
        token = setup["token"]
        status, _ = self.request("POST", "/api/agents/heartbeat", {
            "agent_id":"openwrt-no-inventory","adapter_id":"openwrt","agent_version":"1.2.0",
            "status":"healthy","capabilities":["system.board"],
        }, token=token)
        self.assertEqual(status, 201)
        status, rejected = self.request("POST", "/api/agents/snapshot", {
            "agent_id":"openwrt-no-inventory",
            "snapshot":{"captured_at":"2026-11-20T10:00:00Z","board":{}},
        }, token=token)
        self.assertEqual(status, 400)
        self.assertIn("inventory.snapshot", rejected["error"])

if __name__ == "__main__":
    unittest.main()
