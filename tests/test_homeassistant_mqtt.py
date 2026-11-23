"""Tests for Home Assistant MQTT discovery and privacy-safe telemetry."""
from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from wifi_analyzer_backend.homeassistant_mqtt import (
    SENSORS,
    build_discovery_messages,
    build_home_assistant_snapshot,
)
from wifi_analyzer_backend.homeassistant_mqtt_worker import (
    HomeAssistantMqttPublisher,
    HomeAssistantMqttWorker,
    _read_password_file,
)


class FakePublishInfo:
    rc = 0

    def wait_for_publish(self, timeout=None):
        return None

    def is_published(self):
        return True


class FakeReasonCode:
    is_failure = False


class FakeClient:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.published = []
        self.subscriptions = []
        self.will = None
        self.connected = False
        self.disconnected = False
        self.tls_args = None
        self.username_password = None

    def will_set(self, *args, **kwargs):
        self.will = (args, kwargs)

    def username_pw_set(self, username, password=None):
        self.username_password = (username, password)

    def tls_set(self, **kwargs):
        self.tls_args = kwargs

    def tls_insecure_set(self, value):
        self.tls_insecure = value

    def reconnect_delay_set(self, **kwargs):
        self.reconnect_delay = kwargs

    def connect(self, host, port, keepalive):
        self.connection = (host, port, keepalive)
        return 0

    def loop_start(self):
        self.connected = True
        self.on_connect(self, None, None, FakeReasonCode(), None)

    def subscribe(self, topic, qos=0):
        self.subscriptions.append((topic, qos))
        return (0, 1)

    def publish(self, topic, payload, qos=0, retain=False):
        self.published.append({
            "topic": topic, "payload": payload, "qos": qos, "retain": retain,
        })
        return FakePublishInfo()

    def disconnect(self):
        self.disconnected = True

    def loop_stop(self):
        self.connected = False


class FakeMqttModule:
    class CallbackAPIVersion:
        VERSION2 = 2

    MQTTv311 = 4
    MQTT_ERR_SUCCESS = 0


class FakeTelemetry:
    def __init__(self, rows):
        self.rows = rows
        self.request = None

    def history(self, *, site_ids, days, limit):
        self.request = (site_ids, days, limit)
        return self.rows


class HomeAssistantMqttTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        self.rollup = {
            "site_id": "private-site-name",
            "minute_utc": self.now.isoformat(),
            "updated_at": self.now.isoformat(),
            "scan_count": 3,
            "diagnostics_count": 2,
            "speedtest_count": 1,
            "average_network_count": 12.5,
            "average_open_network_count": 1.0,
            "average_2_4ghz_network_count": 4.0,
            "average_5ghz_network_count": 6.0,
            "average_6ghz_network_count": 2.5,
            "average_rssi_dbm": -54.5,
            "average_latency_ms": 2.5,
            "average_jitter_ms": 0.5,
            "average_packet_loss_pct": 0.0,
            "average_speedtest_download_mbps": 540.2,
            "average_speedtest_upload_mbps": 81.4,
            "average_speedtest_ping_ms": 8.0,
            "ssid": "private-ssid",
            "bssid": "02:11:22:33:44:55",
            "client_mac": "02:aa:bb:cc:dd:ee",
        }

    def test_snapshot_contains_aggregate_metrics_and_excludes_identifiers(self):
        snapshot = build_home_assistant_snapshot([self.rollup], now=self.now + timedelta(seconds=20))
        self.assertTrue(snapshot["telemetry_available"])
        self.assertTrue(snapshot["telemetry_fresh"])
        self.assertEqual(snapshot["scan_samples_24h"], 3)
        self.assertEqual(snapshot["diagnostic_samples_24h"], 2)
        self.assertEqual(snapshot["speedtest_samples_24h"], 1)
        self.assertEqual(snapshot["networks_per_scan"], 12.5)
        self.assertEqual(snapshot["average_rssi_dbm"], -54.5)
        self.assertEqual(snapshot["speedtest_download_mbps"], 540.2)
        encoded = json.dumps(snapshot)
        self.assertNotIn("private-site-name", encoded)
        self.assertNotIn("private-ssid", encoded)
        self.assertNotIn("02:11:22:33:44:55", encoded)
        self.assertNotIn("02:aa:bb:cc:dd:ee", encoded)

    def test_empty_and_stale_telemetry_are_not_reported_as_fresh_or_measured_zero(self):
        empty = build_home_assistant_snapshot([], now=self.now)
        self.assertFalse(empty["telemetry_available"])
        self.assertFalse(empty["telemetry_fresh"])
        self.assertEqual(empty["scan_samples_24h"], 0)
        self.assertIsNone(empty.get("average_rssi_dbm"))

        stale = dict(self.rollup, minute_utc=(self.now - timedelta(minutes=10)).isoformat())
        stale_snapshot = build_home_assistant_snapshot([stale], now=self.now)
        self.assertFalse(stale_snapshot["telemetry_fresh"])
        self.assertIsNone(stale_snapshot["average_rssi_dbm"] if False else None)

    def test_discovery_messages_have_unique_entities_retained_topics_and_availability(self):
        messages = build_discovery_messages("office_gateway")
        self.assertEqual(len(messages), len(SENSORS) + 1)
        self.assertEqual(len({item["topic"] for item in messages}), len(messages))
        unique_ids = []
        for item in messages:
            config = json.loads(item["payload"])
            unique_ids.append(config["unique_id"])
            self.assertEqual(config["availability_topic"], "wifi-analyzer-pro/office_gateway/availability")
            self.assertEqual(config["payload_available"], "online")
            self.assertEqual(config["payload_not_available"], "offline")
            self.assertEqual(config["device"]["identifiers"], ["wifi_analyzer_pro_office_gateway"])
            self.assertIn("state_topic", config)
        self.assertEqual(len(set(unique_ids)), len(messages))
        self.assertTrue(all(item["topic"].startswith("homeassistant/") for item in messages))

    def test_discovery_input_validation_rejects_unsafe_topic_segments(self):
        with self.assertRaisesRegex(ValueError, "device_id"):
            build_discovery_messages("office/#")
        with self.assertRaisesRegex(ValueError, "discovery_prefix"):
            build_discovery_messages("office", discovery_prefix="home/+")

    def test_worker_connects_with_tls_and_publishes_retained_discovery_and_state(self):
        clients = []

        def factory(**kwargs):
            client = FakeClient(**kwargs)
            clients.append(client)
            return client

        publisher = HomeAssistantMqttPublisher(
            host="mqtt.example.internal",
            device_id="office_gateway",
            username="wifi-analyzer",
            password="p" * 48,
            tls=True,
            client_factory=factory,
            mqtt_module=FakeMqttModule,
        )
        publisher.start()
        client = clients[0]
        self.assertEqual(client.connection, ("mqtt.example.internal", 8883, 45))
        self.assertIsNotNone(client.tls_args)
        self.assertFalse(client.tls_insecure)
        self.assertEqual(client.username_password, ("wifi-analyzer", "p" * 48))
        self.assertEqual(client.will[0][0], "wifi-analyzer-pro/office_gateway/availability")
        self.assertEqual(client.will[0][1], "offline")
        self.assertEqual(client.subscriptions, [("homeassistant/status", 1)])

        telemetry = FakeTelemetry([self.rollup])
        worker = HomeAssistantMqttWorker(
            telemetry=telemetry,
            site_id="local",
            publisher=publisher,
        )
        result = worker.publish_once()
        self.assertEqual(telemetry.request, (["local"], 1, 1440))
        self.assertEqual(result["discovery_message_count"], len(SENSORS) + 1)
        self.assertTrue(result["telemetry_available"])
        self.assertEqual(client.published[0]["payload"], "online")
        self.assertTrue(all(item["qos"] == 1 and item["retain"] for item in client.published))
        topics = {item["topic"] for item in client.published}
        self.assertIn("wifi-analyzer-pro/office_gateway/state", topics)
        state = next(item["payload"] for item in client.published if item["topic"].endswith("/state"))
        self.assertNotIn("private-ssid", state)
        self.assertNotIn("private-site-name", state)

        # Home Assistant birth requests discovery to be republished.
        class Message:
            topic = "homeassistant/status"
            payload = b"online"
        publisher._on_message(client, None, Message())
        self.assertTrue(publisher.discovery_requested.is_set())
        publisher.stop()
        self.assertTrue(client.disconnected)
        self.assertEqual(client.published[-1]["payload"], "offline")

    @unittest.skipIf(os.name == "nt", "POSIX password-file permissions")
    def test_password_file_requires_owner_only_permissions_and_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mqtt-password"
            path.write_text("password-value\n", encoding="utf-8")
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
            self.assertEqual(_read_password_file(str(path)), "password-value")
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
            with self.assertRaisesRegex(ValueError, "group or other"):
                _read_password_file(str(path))
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
            link = Path(directory) / "password-link"
            link.symlink_to(path)
            with self.assertRaisesRegex(ValueError, "opened safely"):
                _read_password_file(str(link))


if __name__ == "__main__":
    unittest.main()
