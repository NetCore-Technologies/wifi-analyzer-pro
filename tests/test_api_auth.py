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


class AuthenticatedApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.previous_auth = server.AUTH
        server.AUTH = AuthManager(path=str(Path(self.temp.name) / "auth.json"), session_ttl_seconds=300)
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
        self.assertEqual(catalog["count"], 154)
        self.assertEqual(len(catalog["features"]), 154)
        self.assertIn("site_topology_history_timeline", {item["slug"] for item in catalog["features"]})

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


if __name__ == "__main__":
    unittest.main()
