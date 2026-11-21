"""Integration contract for the live host capability diagnostic response."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from wifi_analyzer_backend import server


class HostDiagnosticsApiTests(unittest.TestCase):
    def test_live_diagnostics_include_host_capabilities_without_running_wifi_scan(self):
        host_report = {
            "platform": "Linux",
            "platform_supported": True,
            "scan_backend_status": "limited",
            "tools": [],
            "permission_status": "not_verified",
            "summary": "iw is missing; NetworkManager is available.",
        }
        with (
            patch.object(server, "OS", "TestOS"),
            patch.object(server, "diagnose_host", return_value=host_report) as diagnose,
            patch.object(server.subprocess, "check_output", return_value=b"") as command,
            patch("socket.getaddrinfo"),
            patch.object(server, "get_wifi_iface", return_value=None),
        ):
            result = server.get_diagnostics()

        self.assertEqual(result["host_capabilities"], host_report)
        diagnose.assert_called_once_with("TestOS")
        self.assertEqual(command.call_count, 1)
        self.assertEqual(command.call_args.args[0][0], "ping")
        self.assertNotIn("permission_granted", result["host_capabilities"])


if __name__ == "__main__":
    unittest.main()
