"""Platform diagnostics tests; all executable probes are injected."""
from __future__ import annotations

import unittest

from wifi_analyzer_backend.host_diagnostics import diagnose_host


class HostDiagnosticsTests(unittest.TestCase):
    def _probe(self, available):
        return lambda name: f"/test/bin/{name}" if name in available else None

    def test_linux_reports_missing_iw_and_available_networkmanager_fallback(self):
        result = diagnose_host(
            "Linux",
            find_executable=self._probe({"ip", "ping", "nmcli", "rfkill"}),
            executable_check=lambda path, mode: True,
        )
        self.assertEqual(result["platform"], "Linux")
        self.assertEqual(result["scan_backend_status"], "limited")
        self.assertEqual(result["available_wireless_tools"], ["nmcli"])
        self.assertIn("iw", result["missing_wireless_tools"])
        iw = next(item for item in result["tools"] if item["name"] == "iw")
        self.assertEqual(iw["status"], "missing")
        self.assertIsNotNone(iw["remediation"])
        self.assertEqual(result["permission_status"], "not_verified")
        self.assertEqual(len({item["name"] for item in result["tools"]}), len(result["tools"]))

    def test_linux_without_any_scan_backend_is_unavailable(self):
        result = diagnose_host("linux", find_executable=self._probe({"ip", "ping"}))
        self.assertEqual(result["scan_backend_status"], "unavailable")
        self.assertEqual(result["available_wireless_tools"], [])
        self.assertIn("iw", result["missing_wireless_tools"])
        self.assertIn("nmcli", result["missing_wireless_tools"])

    def test_present_but_non_executable_tool_is_reported(self):
        result = diagnose_host(
            "Linux",
            find_executable=self._probe({"ip", "ping", "iw"}),
            executable_check=lambda path, mode: path.endswith("/ip") or path.endswith("/ping"),
        )
        iw = next(item for item in result["tools"] if item["name"] == "iw")
        self.assertEqual(iw["status"], "not_executable")
        self.assertFalse(iw["available"])
        self.assertEqual(result["scan_backend_status"], "unavailable")

    def test_macos_reports_system_profiler_and_discloses_tcc_limitation(self):
        result = diagnose_host(
            "Darwin",
            find_executable=self._probe({"system_profiler", "networksetup", "ping"}),
            executable_check=lambda path, mode: True,
        )
        self.assertEqual(result["scan_backend_status"], "limited")
        self.assertEqual(result["available_wireless_tools"], ["system_profiler"])
        self.assertEqual(result["permission_status"], "not_verified")
        self.assertIn("TCC", result["permission_note"])
        self.assertIn("airport", result["missing_wireless_tools"])

    def test_windows_reports_netsh_fallback_without_claiming_service_health(self):
        result = diagnose_host(
            "Windows",
            find_executable=self._probe({"netsh", "ipconfig", "ping"}),
            executable_check=lambda path, mode: True,
        )
        self.assertEqual(result["scan_backend_status"], "limited")
        self.assertEqual(result["available_wireless_tools"], ["netsh"])
        self.assertIn("WLAN AutoConfig", result["permission_note"])
        self.assertEqual(result["permission_status"], "not_verified")

    def test_unknown_operating_system_does_not_guess_a_scan_method(self):
        result = diagnose_host("Plan9", find_executable=self._probe(set()))
        self.assertFalse(result["platform_supported"])
        self.assertEqual(result["scan_backend_status"], "unsupported")
        self.assertEqual(result["tools"], [])


if __name__ == "__main__":
    unittest.main()
