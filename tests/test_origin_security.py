"""Regression tests for host allowlisting and DNS-rebinding-resistant Origin checks."""
from __future__ import annotations

import unittest
import os
from types import SimpleNamespace
from unittest.mock import patch

from wifi_analyzer_backend import server


class OriginSecurityTests(unittest.TestCase):
    def setUp(self):
        self.cors = patch.object(server, "CORS_ORIGINS", {"https://trusted-portal.example"})
        self.hosts = patch.object(server, "ALLOWED_HOSTS", {"localhost", "127.0.0.1", "::1", "analyzer.lan"})
        self.cors.start()
        self.hosts.start()
        self.addCleanup(self.cors.stop)
        self.addCleanup(self.hosts.stop)

    @staticmethod
    def allowed(origin=None, host=None):
        handler = SimpleNamespace(headers={})
        if origin is not None:
            handler.headers["Origin"] = origin
        if host is not None:
            handler.headers["Host"] = host
        return server.Handler.origin_allowed(handler)

    def test_cors_allowlist_accepts_only_exact_http_origins(self):
        from unittest.mock import patch

        with patch.dict(os.environ, {
            "WIFI_ANALYZER_CORS_ORIGINS": "https://portal.example, http://192.168.1.20:5173",
        }):
            self.assertEqual(
                server._configured_cors_origins(),
                {"https://portal.example", "http://192.168.1.20:5173"},
            )
        for value in (
            "*",
            "https://portal.example/path",
            "https://user@portal.example",
            "ftp://portal.example",
            "http://portal.example:bad",
        ):
            with patch.dict(os.environ, {"WIFI_ANALYZER_CORS_ORIGINS": value}):
                with self.assertRaisesRegex(RuntimeError, "exact HTTP"):
                    server._configured_cors_origins()

    def test_options_preflight_echoes_only_an_explicitly_allowed_origin(self):
        class FakeOptionsHandler:
            headers = {
                "Origin": "https://trusted-portal.example",
                "Host": "analyzer.lan:199",
            }

            def origin_allowed(self):
                return server.Handler.origin_allowed(self)

            def send_response(self, status):
                self.status = status

            def send_header(self, name, value):
                self.response_headers[name] = value

            def end_headers(self):
                self.ended = True

            response_headers = {}

        handler = FakeOptionsHandler()
        server.Handler.do_OPTIONS(handler)
        self.assertEqual(handler.status, 204)
        self.assertEqual(
            handler.response_headers["Access-Control-Allow-Origin"],
            "https://trusted-portal.example",
        )
        self.assertEqual(
            handler.response_headers["Access-Control-Allow-Headers"],
            "Authorization, Content-Type",
        )
        self.assertTrue(handler.ended)

    def test_non_browser_requests_without_origin_remain_supported(self):
        self.assertTrue(self.allowed(host="127.0.0.1:199"))
        self.assertTrue(self.allowed())

    def test_explicit_cors_origins_remain_supported(self):
        self.assertTrue(self.allowed(
            origin="https://trusted-portal.example",
            host="analyzer.lan",
        ))

    def test_same_origin_loopback_and_explicit_lan_hosts_are_allowed(self):
        self.assertTrue(self.allowed(
            origin="http://127.0.0.1:199",
            host="127.0.0.1:199",
        ))
        self.assertTrue(self.allowed(
            origin="http://analyzer.lan:199",
            host="analyzer.lan:199",
        ))
        self.assertTrue(self.allowed(
            origin="http://localhost",
            host="localhost:80",
        ))

    def test_dns_rebinding_attacker_host_is_rejected_even_when_origin_matches_host(self):
        self.assertFalse(self.allowed(
            origin="http://attacker.example:199",
            host="attacker.example:199",
        ))
        self.assertFalse(self.allowed(
            origin="http://evil.example",
            host="evil.example",
        ))

    def test_mismatched_hosts_and_ports_are_rejected(self):
        self.assertFalse(self.allowed(
            origin="http://localhost:199",
            host="127.0.0.1:199",
        ))
        self.assertFalse(self.allowed(
            origin="http://localhost:199",
            host="localhost:198",
        ))

    def test_get_and_options_reject_dns_rebinding_origins_before_processing(self):
        class FakeHandler:
            headers = {
                "Origin": "http://attacker.example:199",
                "Host": "attacker.example:199",
            }
            path = "/api/sites"

            def origin_allowed(self):
                return server.Handler.origin_allowed(self)

            def send_json(self, payload, status=200):
                self.response = (payload, status)

        get_handler = FakeHandler()
        server.Handler.do_GET(get_handler)
        self.assertEqual(get_handler.response[1], 403)
        self.assertEqual(get_handler.response[0]["error"], "Origin is not allowed")

        options_handler = FakeHandler()
        server.Handler.do_OPTIONS(options_handler)
        self.assertEqual(options_handler.response[1], 403)
        self.assertEqual(options_handler.response[0]["error"], "Origin is not allowed")

    def test_invalid_origin_syntax_and_userinfo_are_rejected(self):
        self.assertFalse(self.allowed(
            origin="javascript://localhost",
            host="localhost",
        ))
        self.assertFalse(self.allowed(
            origin="http://user@localhost:199",
            host="localhost:199",
        ))
        self.assertFalse(self.allowed(
            origin="http://localhost/path",
            host="localhost",
        ))
        self.assertFalse(self.allowed(
            origin="http://localhost:bad",
            host="localhost",
        ))


if __name__ == "__main__":
    unittest.main()
