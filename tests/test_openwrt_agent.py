"""Tests for the read-only OpenWrt agent, transport and durable retry outbox."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from urllib.request import Request
from types import SimpleNamespace

from agent.openwrt_agent import (
    AGENT_VERSION,
    CAPABILITIES,
    AgentApiClient,
    AgentConfig,
    AgentConfigError,
    AgentTransportError,
    CollectorError,
    _NoRedirect,
    DurableOutbox,
    OpenWrtAgent,
    OpenWrtCollector,
    load_config,
)
from wifi_analyzer_backend.router_adapters.openwrt import normalize_snapshot


TOKEN = "wpa_" + ("a" * 43)


def make_config(state_dir: str) -> AgentConfig:
    return AgentConfig.from_mapping({
        "agent_id": "openwrt-test",
        "server_url": "https://wifi-analyzer.example:199",
        "token": TOKEN,
        "state_dir": state_dir,
    })


class FakeRunner:
    def __init__(self):
        self.calls = []
        self.results = {
            ("ubus", "call", "system", "info", "{}"): {
                "uptime": 1234,
                "load": [65536, 32768, 16384],
                "memory": {"total": 1048576, "free": 524288, "shared": 8192, "buffered": 16384, "available": 540672, "cached": 32768},
                "swap": {"total": 262144, "free": 131072},
            },
            ("ubus", "call", "system", "board", "{}"): {
                "model": "Example OpenWrt Router",
                "board_name": "vendor,router",
                "hostname": "router",
                "kernel": "6.6.1",
                "release": {
                    "distribution": "OpenWrt",
                    "version": "24.10.0",
                    "revision": "r12345",
                    "target": "qualcommax/ipq807x",
                },
            },
            ("ubus", "call", "network.interface", "dump", "{}"): {
                "interface": [{
                    "interface": "lan",
                    "device": "br-lan",
                    "proto": "static",
                    "up": True,
                    "ipv4-address": [{"address": "192.168.1.1", "mask": 24}],
                    "ipv6-address": [],
                }],
            },
            ("ubus", "call", "network.wireless", "status", "{}"): {
                "radio0": {
                    "up": True,
                    "interfaces": [{
                        "ifname": "phy0-ap0",
                        "up": True,
                        "config": {
                            "ssid": "Home",
                            "encryption": "psk2",
                            "key": "must-never-leave-router",
                            "htmode": "HE80",
                        },
                        "iwinfo": {
                            "ssid": "Home",
                            "bssid": "00:11:22:33:44:55",
                            "frequency": 5180,
                            "channel": 36,
                            "signal": -55,
                            "noise": -95,
                            "txpower": 20,
                            "encryption": {"description": "WPA2 PSK (CCMP)"},
                        },
                    }],
                },
            },
            ("ip", "-j", "route", "show"): [{
                "dst": "default", "gateway": "192.168.1.254", "dev": "eth1", "metric": 10,
            }],
            ("ip", "-6", "-j", "route", "show"): [{
                "dst": "default", "gateway": "fe80::1", "dev": "eth1", "metric": 100,
            }],
            ("iw", "dev", "phy0-ap0", "station", "dump"): (
                "Station aa:bb:cc:dd:ee:01 (on phy0-ap0)\n"
                "\tsignal: -61 dBm\n"
                "\ttx bitrate: 433.0 MBit/s\n"
                "\trx bitrate: 600.0 MBit/s\n"
            ),
        }

    def __call__(self, argv, timeout):
        self.calls.append((list(argv), timeout))
        key = tuple(argv)
        if key not in self.results:
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        value = self.results[key]
        output = value if isinstance(value, str) else json.dumps(value)
        return SimpleNamespace(returncode=0, stdout=output, stderr="")


class CollectorTests(unittest.TestCase):
    def test_collector_only_reads_system_health_when_requested_and_converts_fixed_point_load(self):
        runner = FakeRunner()
        collector = OpenWrtCollector(runner=runner)
        without_health = collector.collect()
        self.assertNotIn("system_health", without_health)
        self.assertNotIn(("ubus", "call", "system", "info", "{}"), [tuple(argv) for argv, _ in runner.calls])

        runner = FakeRunner()
        collector = OpenWrtCollector(runner=runner)
        with_health = collector.collect(include_system_health=True)
        self.assertEqual(with_health["system_health"]["uptime_seconds"], 1234)
        self.assertEqual(with_health["system_health"]["load_average"], {"1m": 1.0, "5m": 0.5, "15m": 0.25})
        self.assertEqual(with_health["system_health"]["memory_bytes"]["available"], 540672)
        self.assertEqual(with_health["system_health"]["swap_bytes"]["total"], 262144)
        self.assertIn(("ubus", "call", "system", "info", "{}"), [tuple(argv) for argv, _ in runner.calls])
        self.assertEqual(collector.warnings, [])

    def test_collector_rejects_invalid_system_health_without_losing_base_inventory(self):
        runner = FakeRunner()
        runner.results[("ubus", "call", "system", "info", "{}")] = {
            "uptime": 12, "load": [-1, 2, 3],
            "memory": {"total": 1024, "free": 256}, "swap": {"total": 0, "free": 0},
        }
        collector = OpenWrtCollector(runner=runner)
        snapshot = collector.collect(include_system_health=True)
        self.assertNotIn("system_health", snapshot)
        self.assertIn("system_health_invalid", collector.warnings)
        self.assertEqual(snapshot["board"]["model"], "Example OpenWrt Router")

    def test_collector_uses_read_only_allowlisted_commands_and_produces_normalisable_data(self):
        runner = FakeRunner()
        collector = OpenWrtCollector(runner=runner)
        snapshot = collector.collect()

        self.assertEqual(snapshot["board"]["model"], "Example OpenWrt Router")
        self.assertEqual(snapshot["interfaces"][0]["interface"], "lan")
        self.assertEqual(snapshot["wireless"][0]["channel"], 36)
        self.assertEqual(snapshot["wireless"][0]["security"], "WPA2 PSK (CCMP)")
        self.assertEqual(snapshot["associations"][0]["stations"][0]["mac"], "AA:BB:CC:DD:EE:01")
        self.assertEqual(snapshot["routes"][0]["target"], "0.0.0.0/0")
        self.assertEqual(snapshot["routes"][1]["target"], "::/0")

        serialised = json.dumps(snapshot)
        self.assertNotIn("must-never-leave-router", serialised)
        self.assertNotIn('"key"', serialised)
        self.assertEqual(collector.warnings, [])
        self.assertTrue(runner.calls)
        self.assertTrue(all(isinstance(argv, list) and all(isinstance(arg, str) for arg in argv) for argv, _ in runner.calls))
        self.assertTrue(all(timeout <= 5 for _, timeout in runner.calls))
        self.assertFalse(any("uci" in argv or "set" in argv for argv, _ in runner.calls))

        normalised = normalize_snapshot(snapshot)
        self.assertEqual(normalised["adapter_id"], "openwrt")
        self.assertEqual(normalised["summary"]["interface_count"], 1)
        self.assertEqual(normalised["summary"]["wireless_radio_count"], 1)
        self.assertEqual(normalised["summary"]["association_count"], 1)
        self.assertEqual(normalised["summary"]["route_count"], 2)
        self.assertNotIn("key", json.dumps(normalised))

    def test_collector_fails_closed_when_required_ubus_board_command_is_missing(self):
        def missing_runner(argv, timeout):
            raise FileNotFoundError(argv[0])

        collector = OpenWrtCollector(runner=missing_runner)
        with self.assertRaises(CollectorError):
            collector.collect()

    def test_collector_records_partial_data_warnings_without_inventing_values(self):
        runner = FakeRunner()
        runner.results.pop(("ubus", "call", "network.wireless", "status", "{}"))
        collector = OpenWrtCollector(runner=runner)
        snapshot = collector.collect()
        self.assertEqual(snapshot["wireless"], [])
        self.assertTrue(any("wireless" in warning for warning in collector.warnings))

    def test_station_parser_ignores_invalid_mac_and_bounds_rate_values(self):
        output = (
            "Station not-a-mac (on wlan0)\n"
            "Station AA:BB:CC:DD:EE:FF (on wlan0)\n"
            "signal: -64 dBm\n"
            "tx bitrate: 300.5 MBit/s\n"
        )
        result = OpenWrtCollector._parse_stations(output)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["mac"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(result[0]["signal"], -64)
        self.assertEqual(result[0]["tx"]["rate"], 300.5)


class AgentApiClientSecurityTests(unittest.TestCase):
    def test_agent_api_client_refuses_redirects_to_protect_the_bearer_token(self):
        config = make_config("/tmp/wifi-analyzer-agent-redirect-test")
        client = AgentApiClient(config)
        director = client.opener.__self__
        handler = next((item for item in director.handlers if isinstance(item, _NoRedirect)), None)
        self.assertIsNotNone(handler)
        request = Request(
            config.server_url + "/api/agents/heartbeat",
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
        redirected = handler.redirect_request(
            request, None, 302, "Found", {},
            "https://attacker.invalid/collect",
        )
        self.assertIsNone(redirected)
        self.assertEqual(request.get_header("Authorization"), f"Bearer {TOKEN}")

class ConfigAndOutboxTests(unittest.TestCase):
    def test_https_config_is_validated_and_token_is_not_rendered(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "agent.json"
            path.write_text(json.dumps({
                "agent_id": "openwrt-home",
                "server_url": "https://wifi-analyzer.example:199",
                "token": TOKEN,
                "state_dir": str(Path(directory) / "state"),
            }), encoding="utf-8")
            if os.name != "nt":
                path.chmod(0o600)
            config = load_config(path)
            self.assertEqual(config.agent_id, "openwrt-home")
            self.assertEqual(config.interval_seconds, 300)
            self.assertNotIn(TOKEN, repr(config))

    def test_http_requires_explicit_insecure_lan_opt_in(self):
        base = {
            "agent_id": "openwrt-home",
            "server_url": "http://192.168.1.2:199",
            "token": TOKEN,
            "state_dir": "/var/lib/wifi-analyzer-agent",
        }
        with self.assertRaisesRegex(AgentConfigError, "HTTP is disabled"):
            AgentConfig.from_mapping(base)
        config = AgentConfig.from_mapping({**base, "allow_insecure_http": True})
        self.assertTrue(config.allow_insecure_http)

    def test_invalid_token_and_interval_are_rejected(self):
        base = {
            "agent_id": "openwrt-home",
            "server_url": "https://wifi-analyzer.example:199",
            "token": "not-a-token",
            "state_dir": "/var/lib/wifi-analyzer-agent",
        }
        with self.assertRaises(AgentConfigError):
            AgentConfig.from_mapping(base)
        with self.assertRaises(AgentConfigError):
            AgentConfig.from_mapping({**base, "token": TOKEN, "interval_seconds": 1})

    def test_config_permissions_must_be_private(self):
        if os.name == "nt":
            self.skipTest("POSIX file permission checks are not available on Windows")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "agent.json"
            path.write_text(json.dumps({
                "agent_id": "openwrt-home",
                "server_url": "https://wifi-analyzer.example:199",
                "token": TOKEN,
                "state_dir": str(Path(directory) / "state"),
            }), encoding="utf-8")
            path.chmod(0o644)
            with self.assertRaisesRegex(AgentConfigError, "chmod 600"):
                load_config(path)

    def test_outbox_atomically_persists_one_private_delivery(self):
        with tempfile.TemporaryDirectory() as directory:
            outbox = DurableOutbox(directory)
            payload = {
                "agent_id": "openwrt-home",
                "delivery_id": "6c6329b5-8611-4c45-8926-5d6a85bc9f7d",
                "snapshot": {"captured_at": "2026-11-20T10:00:00Z"},
            }
            outbox.save(payload)
            self.assertEqual(outbox.load(), payload)
            if os.name != "nt":
                self.assertEqual(outbox.path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(Path(directory).stat().st_mode & 0o777, 0o700)
            outbox.clear()
            self.assertIsNone(outbox.load())


class FakeCollector:
    def __init__(self, snapshot):
        self.snapshot = snapshot
        self.warnings = []
        self.calls = 0
        self.health_requests = []

    def collect(self, *, include_system_health=False):
        self.calls += 1
        self.health_requests.append(include_system_health)
        return self.snapshot


class FakeClient:
    def __init__(self, fail_first_delivery=False, accepted_capabilities=None):
        self.fail_first_delivery = fail_first_delivery
        self.accepted_capabilities = accepted_capabilities if accepted_capabilities is not None else CAPABILITIES
        self.calls = []
        self.deliveries = []

    def post(self, endpoint, payload):
        self.calls.append((endpoint, json.loads(json.dumps(payload))))
        if endpoint == "/api/agents/heartbeat":
            return {"agent": {"capabilities": self.accepted_capabilities}}
        if endpoint == "/api/agents/snapshots/batch":
            self.deliveries.append(json.loads(json.dumps(payload)))
            if self.fail_first_delivery:
                self.fail_first_delivery = False
                raise AgentTransportError("offline")
            return {"delivery": {"id": 42, "replayed": False}}
        raise AssertionError(f"Unexpected agent endpoint: {endpoint}")


class AgentRuntimeTests(unittest.TestCase):
    def _snapshot(self):
        return {
            "captured_at": "2026-11-20T10:00:00Z",
            "board": {"model": "Example router"},
            "interfaces": [],
            "wireless": [],
            "associations": [],
            "routes": [],
        }

    def test_failed_delivery_is_retried_with_identical_uuid_and_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(directory)
            collector = FakeCollector(self._snapshot())
            client = FakeClient(fail_first_delivery=True)
            outbox = DurableOutbox(Path(directory) / "state")
            agent = OpenWrtAgent(config, collector=collector, client=client, outbox=outbox)

            first = agent.run_once()
            self.assertEqual(first["status"], "pending")
            self.assertTrue(outbox.path.exists())
            saved = outbox.load()
            self.assertIsNotNone(saved)

            second = agent.run_once()
            self.assertEqual(second["status"], "delivered_pending")
            self.assertFalse(outbox.path.exists())
            self.assertEqual(collector.calls, 1)
            self.assertEqual(collector.health_requests, [True])
            self.assertEqual(len(client.deliveries), 2)
            self.assertEqual(client.deliveries[0]["delivery_id"], client.deliveries[1]["delivery_id"])
            self.assertEqual(client.deliveries[0], client.deliveries[1])
            self.assertEqual(
                [endpoint for endpoint, _ in client.calls],
                [
                    "/api/agents/heartbeat",
                    "/api/agents/snapshots/batch",
                    "/api/agents/heartbeat",
                    "/api/agents/snapshots/batch",
                ],
            )

    def test_agent_does_not_collect_system_health_without_negotiated_capability(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(directory)
            collector = FakeCollector(self._snapshot())
            client = FakeClient(accepted_capabilities=["system.board", "inventory.snapshot"])
            agent = OpenWrtAgent(config, collector=collector, client=client)
            result = agent.run_once()
            self.assertEqual(result["status"], "delivered")
            self.assertEqual(collector.health_requests, [False])

    def test_agent_does_not_submit_snapshot_without_negotiated_inventory_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            config = make_config(directory)
            collector = FakeCollector(self._snapshot())
            client = FakeClient(accepted_capabilities=["system.board"])
            outbox = DurableOutbox(Path(directory) / "state")
            agent = OpenWrtAgent(config, collector=collector, client=client, outbox=outbox)
            with self.assertRaisesRegex(AgentConfigError, "inventory.snapshot"):
                agent.run_once()
            self.assertFalse(outbox.path.exists())
            self.assertEqual(len(client.deliveries), 0)

    def test_collection_failure_reports_degraded_heartbeat_and_no_snapshot(self):
        class BrokenCollector:
            warnings = []

            def collect(self, *, include_system_health=False):
                raise CollectorError("No telemetry source", "SCAN_UNAVAILABLE")

        with tempfile.TemporaryDirectory() as directory:
            config = make_config(directory)
            client = FakeClient()
            agent = OpenWrtAgent(config, collector=BrokenCollector(), client=client)
            result = agent.run_once()
            self.assertEqual(result["status"], "degraded")
            self.assertEqual(result["error_code"], "SCAN_UNAVAILABLE")
            heartbeat_payloads = [payload for endpoint, payload in client.calls if endpoint == "/api/agents/heartbeat"]
            self.assertEqual(len(heartbeat_payloads), 2)
            self.assertEqual(heartbeat_payloads[-1]["status"], "degraded")
            self.assertEqual(heartbeat_payloads[-1]["error_code"], "SCAN_UNAVAILABLE")
            self.assertEqual(len(client.deliveries), 0)


    def test_unavailable_api_does_not_collect_or_discard_a_snapshot(self):
        class OfflineClient:
            def post(self, endpoint, payload):
                raise AgentTransportError("offline")

        with tempfile.TemporaryDirectory() as directory:
            config = make_config(directory)
            collector = FakeCollector(self._snapshot())
            outbox = DurableOutbox(Path(directory) / "state")
            agent = OpenWrtAgent(config, collector=collector, client=OfflineClient(), outbox=outbox)
            result = agent.run_once()
            self.assertEqual(result["status"], "offline")
            self.assertFalse(result["pending"])
            self.assertEqual(collector.calls, 0)
            self.assertFalse(outbox.path.exists())


if __name__ == "__main__":
    unittest.main()
