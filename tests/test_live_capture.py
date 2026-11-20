import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from wifi_analyzer_backend.live_capture import LiveCaptureManager, MAX_CAPTURE_BYTES


PCAP_HEADER = b"\xd4\xc3\xb2\xa1" + b"\x00" * 20


class FakeProcess:
    def __init__(self, command, *, returncode=0, running=False):
        self.command = command
        self.returncode = None if running else returncode
        self._running = running
        self.terminated = False
        output = Path(command[command.index("-w") + 1])
        output.write_bytes(PCAP_HEADER)

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.returncode = -9

    def wait(self, timeout=None):
        if self.returncode is None:
            self.returncode = -15
        return self.returncode


class LiveCaptureManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.manager = LiveCaptureManager(self.root / "captures")
        self.which = patch("wifi_analyzer_backend.live_capture.shutil.which", return_value="/usr/sbin/tcpdump")
        self.which.start()
        self.addCleanup(self.which.stop)
        self.inventory = patch(
            "wifi_analyzer_backend.live_capture.subprocess.run",
            return_value=type("Result", (), {"returncode": 0, "stdout": "1.eth0 [Up]\\n2.wlan0 [Up]\\n3.any [Up]\\n"})(),
        )
        self.inventory.start()
        self.addCleanup(self.inventory.stop)

    def tearDown(self):
        self.temp.cleanup()

    def test_lists_only_sanitised_libpcap_interfaces(self):
        result = self.manager.list_interfaces()
        self.assertTrue(result["available"])
        self.assertEqual([item["name"] for item in result["interfaces"]], ["eth0", "wlan0", "any"])

    def test_reports_missing_tcpdump_without_attempting_capture(self):
        with patch("wifi_analyzer_backend.live_capture.shutil.which", return_value=None):
            result = self.manager.list_interfaces()
            self.assertFalse(result["available"])
            self.assertIn("not installed", result["reason"])
            with self.assertRaises(ValueError):
                self.manager.start(interface="eth0")

    def test_rejects_unlisted_interface_and_unsafe_or_unbounded_inputs(self):
        with self.assertRaisesRegex(ValueError, "not available"):
            self.manager.start(interface="eth1")
        with self.assertRaisesRegex(ValueError, "interface is invalid"):
            self.manager.start(interface="eth0; touch /tmp/no")
        with self.assertRaisesRegex(ValueError, "duration_seconds"):
            self.manager.start(interface="eth0", duration_seconds=600)
        with self.assertRaisesRegex(ValueError, "packet_limit"):
            self.manager.start(interface="eth0", packet_limit=1001)
        with self.assertRaisesRegex(ValueError, "filter_profile"):
            self.manager.start(interface="eth0", filter_profile="tcp or (1=1)")

    def test_start_uses_argument_vector_fixed_filter_and_bounded_snaplen(self):
        processes = []

        def spawn(command, **kwargs):
            process = FakeProcess(command)
            processes.append(process)
            return process

        with patch("wifi_analyzer_backend.live_capture.subprocess.Popen", side_effect=spawn) as popen:
            capture = self.manager.start(
                interface="wlan0",
                duration_seconds=10,
                packet_limit=42,
                filter_profile="dns",
            )
            popen.assert_called_once()
        command = processes[0].command
        self.assertEqual(command[command.index("-i") + 1], "wlan0")
        self.assertEqual(command[command.index("-s") + 1], "256")
        self.assertEqual(command[command.index("-c") + 1], "42")
        self.assertEqual(command[-1], "port 53")
        self.assertEqual(capture["state"], "running")
        for _ in range(30):
            status = self.manager.status()["capture"]
            if status["state"] != "running":
                break
            time.sleep(0.02)
        self.assertEqual(status["state"], "completed")
        self.assertTrue(self.manager.capture_file(capture["capture_id"]))

    def test_only_one_capture_may_run_and_operator_can_stop_it(self):
        processes = []

        def spawn(command, **kwargs):
            process = FakeProcess(command, running=True)
            processes.append(process)
            return process

        with patch("wifi_analyzer_backend.live_capture.subprocess.Popen", side_effect=spawn):
            started = self.manager.start(interface="eth0")
            with self.assertRaisesRegex(RuntimeError, "already running"):
                self.manager.start(interface="wlan0")
            stopped = self.manager.stop(started["capture_id"])
        self.assertTrue(processes[0].terminated)
        self.assertEqual(stopped["state"], "completed")
        self.assertIsNotNone(self.manager.capture_file(started["capture_id"]))

    def test_nonzero_exit_discards_unusable_capture(self):
        with patch(
            "wifi_analyzer_backend.live_capture.subprocess.Popen",
            side_effect=lambda command, **kwargs: FakeProcess(command, returncode=1),
        ):
            started = self.manager.start(interface="eth0")
        for _ in range(30):
            status = self.manager.status()["capture"]
            if status["state"] != "running":
                break
            time.sleep(0.02)
        self.assertEqual(status["state"], "failed")
        self.assertIsNone(self.manager.capture_file(started["capture_id"]))

    def test_capture_size_limit_is_enforced_before_download(self):
        process_holder = {}

        def spawn(command, **kwargs):
            process = FakeProcess(command, running=True)
            output = Path(command[command.index("-w") + 1])
            output.write_bytes(b"\x00" * (MAX_CAPTURE_BYTES + 1))
            process_holder["process"] = process
            return process

        with patch("wifi_analyzer_backend.live_capture.subprocess.Popen", side_effect=spawn):
            started = self.manager.start(interface="eth0")
        for _ in range(30):
            status = self.manager.status()["capture"]
            if status["state"] != "running":
                break
            time.sleep(0.02)
        self.assertEqual(status["state"], "failed")
        self.assertIn("512 KiB", status["error"])
        self.assertIsNone(self.manager.capture_file(started["capture_id"]))


if __name__ == "__main__":
    unittest.main()
