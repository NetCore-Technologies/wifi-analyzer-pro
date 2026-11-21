"""Network diagnostic probe policy: no implicit external reachability tests."""
from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from wifi_analyzer_backend import server


class NetworkDiagnosticProbePolicyTests(unittest.TestCase):
    def test_missing_default_route_skips_ping_instead_of_using_a_public_ip(self):
        with (
            patch.object(server, "OS", "Linux"),
            patch.object(server.subprocess, "check_output", return_value=b"") as command,
            patch.object(server, "get_wifi_iface", return_value=None),
            patch("socket.getaddrinfo") as resolver,
            patch.dict(os.environ, {"WIFI_ANALYZER_DIAGNOSTIC_DNS_TARGET": ""}),
        ):
            result = server.get_diagnostics()

        self.assertEqual(command.call_count, 1)
        self.assertEqual(command.call_args.args[0], ["ip", "route", "show", "default"])
        self.assertEqual(result["gateway"], None)
        self.assertEqual(result["gateway_probe_status"], "skipped_no_gateway")
        self.assertNotIn("latency_ms", result)
        self.assertEqual(result["dns_resolution_status"], "not_configured")
        resolver.assert_not_called()

    def test_existing_default_gateway_is_the_only_automatic_ping_target(self):
        route = b"default via 192.0.2.1 dev wlan0"
        ping = (
            b"64 bytes from 192.0.2.1: time=1.2 ms\n"
            b"64 bytes from 192.0.2.1: time=1.4 ms\n"
            b"64 bytes from 192.0.2.1: time=1.3 ms\n"
            b"3 packets transmitted, 3 received, 0% packet loss"
        )
        with (
            patch.object(server, "OS", "Linux"),
            patch.object(server.subprocess, "check_output", return_value=route) as command,
            patch.object(server.subprocess, "run", return_value=type("PingResult", (), {"stdout": ping, "returncode": 0})()) as ping_command,
            patch.object(server, "get_wifi_iface", return_value=None),
            patch("socket.getaddrinfo") as resolver,
            patch.dict(os.environ, {"WIFI_ANALYZER_DIAGNOSTIC_DNS_TARGET": ""}),
        ):
            result = server.get_diagnostics()

        command.assert_called_once_with(
            ["ip", "route", "show", "default"],
            stderr=server.subprocess.DEVNULL,
            timeout=3,
        )
        self.assertEqual(ping_command.call_count, 1)
        self.assertEqual(ping_command.call_args.args[0], ["ping", "-c", "3", "192.0.2.1"])
        self.assertEqual(result["gateway_probe_status"], "measured")
        self.assertEqual(result["latency_ms"], 1.3)
        self.assertEqual(result["packet_loss_pct"], 0.0)
        self.assertEqual(result["dns_resolution_status"], "not_configured")
        resolver.assert_not_called()

    def test_gateway_with_no_replies_reports_full_packet_loss(self):
        route = b"default via 192.0.2.1 dev wlan0"
        ping = b"3 packets transmitted, 0 received, 100% packet loss"
        with (
            patch.object(server, "OS", "Linux"),
            patch.object(server.subprocess, "check_output", return_value=route),
            patch.object(server.subprocess, "run", return_value=type("PingResult", (), {"stdout": ping, "returncode": 1})()),
            patch.object(server, "get_wifi_iface", return_value=None),
            patch.dict(os.environ, {"WIFI_ANALYZER_DIAGNOSTIC_DNS_TARGET": ""}),
        ):
            result = server.get_diagnostics()

        self.assertEqual(result["gateway_probe_status"], "measured")
        self.assertEqual(result["packet_loss_pct"], 100.0)
        self.assertNotIn("latency_ms", result)

    def test_gateway_permission_denial_is_reported_without_claiming_success(self):
        route = b"default via 192.0.2.1 dev wlan0"
        ping = b"ping: socket: Operation not permitted"
        with (
            patch.object(server, "OS", "Linux"),
            patch.object(server.subprocess, "check_output", return_value=route),
            patch.object(server.subprocess, "run", return_value=type("PingResult", (), {"stdout": ping, "returncode": 2})()),
            patch.object(server, "get_wifi_iface", return_value=None),
            patch.dict(os.environ, {"WIFI_ANALYZER_DIAGNOSTIC_DNS_TARGET": ""}),
        ):
            result = server.get_diagnostics()

        self.assertEqual(result["gateway_probe_status"], "permission_denied")
        self.assertNotIn("latency_ms", result)
        self.assertNotIn("packet_loss_pct", result)

    def test_gateway_timeout_is_reported_explicitly(self):
        route = b"default via 192.0.2.1 dev wlan0"
        with (
            patch.object(server, "OS", "Linux"),
            patch.object(server.subprocess, "check_output", return_value=route),
            patch.object(server.subprocess, "run", side_effect=server.subprocess.TimeoutExpired("ping", 7)),
            patch.object(server, "get_wifi_iface", return_value=None),
            patch.dict(os.environ, {"WIFI_ANALYZER_DIAGNOSTIC_DNS_TARGET": ""}),
        ):
            result = server.get_diagnostics()

        self.assertEqual(result["gateway_probe_status"], "timed_out")

    def test_external_dns_resolution_requires_an_explicit_valid_target(self):
        with (
            patch.object(server, "OS", "TestOS"),
            patch.object(server.subprocess, "check_output") as command,
            patch.object(server, "get_wifi_iface", return_value=None),
            patch("socket.getaddrinfo") as resolver,
            patch.dict(os.environ, {"WIFI_ANALYZER_DIAGNOSTIC_DNS_TARGET": "diagnostics.example.test"}),
        ):
            result = server.get_diagnostics()

        self.assertEqual(result["dns_resolution_status"], "resolved")
        self.assertEqual(result["dns_resolution_target"], "diagnostics.example.test")
        resolver.assert_called_once_with("diagnostics.example.test", None)
        command.assert_not_called()

    def test_invalid_dns_target_is_rejected_without_a_lookup(self):
        with (
            patch.object(server, "OS", "TestOS"),
            patch.object(server.subprocess, "check_output") as command,
            patch.object(server, "get_wifi_iface", return_value=None),
            patch("socket.getaddrinfo") as resolver,
            patch.dict(os.environ, {"WIFI_ANALYZER_DIAGNOSTIC_DNS_TARGET": "bad target;example.com"}),
        ):
            result = server.get_diagnostics()

        self.assertEqual(result["dns_resolution_status"], "invalid_configuration")
        resolver.assert_not_called()
        command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
