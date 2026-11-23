"""Tests for the authenticated, privacy-preserving Prometheus exporter."""
from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.client import HTTPConnection
from pathlib import Path
from unittest.mock import patch

from wifi_analyzer_backend import server
from wifi_analyzer_backend.prometheus_exporter import render_prometheus_metrics
from wifi_analyzer_backend.telemetry_store import WiFiTelemetryStore


class PrometheusRendererTests(unittest.TestCase):
    def _rollup(self, *, minute: datetime, updated: datetime | None = None) -> dict:
        return {
            "minute_utc": minute.isoformat(timespec="seconds"),
            "updated_at": (updated or minute).isoformat(timespec="seconds"),
            "scan_count": 2,
            "diagnostics_count": 1,
            "speedtest_count": 1,
            "average_network_count": 4.5,
            "average_open_network_count": 0.5,
            "average_2_4ghz_network_count": 2.0,
            "average_5ghz_network_count": 2.5,
            "average_6ghz_network_count": 0.0,
            "average_rssi_dbm": -56.5,
            "average_latency_ms": 3.25,
            "average_jitter_ms": 0.5,
            "average_packet_loss_pct": 0.0,
            "average_speedtest_download_mbps": 165.2,
            "average_speedtest_upload_mbps": 83.3,
            "average_speedtest_ping_ms": 42.0,
        }

    def test_renders_latest_minute_measurements_and_rolling_sample_totals(self):
        now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        older = self._rollup(minute=now - timedelta(minutes=2))
        latest = self._rollup(minute=now, updated=now + timedelta(seconds=20))
        metrics = render_prometheus_metrics([latest, older], now=now + timedelta(seconds=25))

        self.assertIn("wifi_analyzer_up 1", metrics)
        self.assertIn("wifi_analyzer_telemetry_available 1", metrics)
        self.assertIn("wifi_analyzer_telemetry_fresh 1", metrics)
        self.assertIn("wifi_analyzer_scan_samples_24h 4", metrics)
        self.assertIn("wifi_analyzer_diagnostic_samples_24h 2", metrics)
        self.assertIn("wifi_analyzer_speedtest_samples_24h 2", metrics)
        self.assertIn("wifi_analyzer_networks_per_scan 4.5", metrics)
        self.assertIn("wifi_analyzer_average_rssi_dbm -56.5", metrics)
        self.assertIn("wifi_analyzer_gateway_latency_ms 3.25", metrics)
        self.assertIn("wifi_analyzer_speedtest_download_mbps 165.2", metrics)

    def test_empty_history_reports_missing_telemetry_without_fabricating_measurements(self):
        metrics = render_prometheus_metrics([])
        self.assertIn("wifi_analyzer_up 1", metrics)
        self.assertIn("wifi_analyzer_telemetry_available 0", metrics)
        self.assertIn("wifi_analyzer_telemetry_fresh 0", metrics)
        self.assertIn("wifi_analyzer_scan_samples_24h 0", metrics)
        self.assertNotIn("wifi_analyzer_average_rssi_dbm ", metrics)
        self.assertNotIn("wifi_analyzer_gateway_latency_ms ", metrics)

    def test_stale_history_is_not_reported_as_fresh(self):
        now = datetime.now(timezone.utc)
        stale = self._rollup(minute=now - timedelta(minutes=10))
        metrics = render_prometheus_metrics([stale], now=now)
        self.assertIn("wifi_analyzer_telemetry_fresh 0", metrics)

    def test_rejects_malformed_rollups_and_naive_clock(self):
        with self.assertRaisesRegex(ValueError, "rollups must be a list"):
            render_prometheus_metrics({})
        with self.assertRaisesRegex(ValueError, "must be an object"):
            render_prometheus_metrics([None])
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            render_prometheus_metrics([], now=datetime(2026, 1, 1))

    def test_dashboard_json_is_valid_and_uses_exported_metric_names(self):
        root = Path(__file__).resolve().parents[1]
        dashboard = json.loads(
            (root / "deploy" / "grafana" / "wifi-analyzer-pro.json").read_text(encoding="utf-8")
        )
        expressions = {
            target["expr"]
            for panel in dashboard["panels"]
            for target in panel.get("targets", [])
        }
        self.assertTrue(expressions)
        self.assertTrue(expressions.issubset({
            "wifi_analyzer_networks_per_scan",
            "wifi_analyzer_average_rssi_dbm",
            "wifi_analyzer_gateway_latency_ms",
            "wifi_analyzer_gateway_jitter_ms",
            "wifi_analyzer_gateway_packet_loss_percent",
            "wifi_analyzer_speedtest_download_mbps",
            "wifi_analyzer_speedtest_upload_mbps",
            "wifi_analyzer_telemetry_fresh",
            "wifi_analyzer_scan_samples_24h",
            "wifi_analyzer_diagnostic_samples_24h",
            "wifi_analyzer_speedtest_samples_24h",
        }))
        self.assertEqual(len(expressions), 11)


class PrometheusEndpointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.previous_telemetry = server.TELEMETRY
        self.previous_local_site_id = server.LOCAL_SITE_ID
        server.LOCAL_SITE_ID = "local"
        self.telemetry = WiFiTelemetryStore(path=Path(self.temp.name) / "telemetry.sqlite3")
        server.TELEMETRY = self.telemetry
        self.httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.httpd.server_address[1]

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)
        server.TELEMETRY = self.previous_telemetry
        server.LOCAL_SITE_ID = self.previous_local_site_id
        self.temp.cleanup()

    def request(self, *, token: str | None = None, path: str = "/metrics"):
        connection = HTTPConnection("127.0.0.1", self.port, timeout=3)
        headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
        try:
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            body = response.read().decode("utf-8")
            return response.status, body, dict(response.getheaders())
        finally:
            connection.close()

    def test_exporter_is_disabled_without_a_configured_token(self):
        with patch.dict(os.environ, {"WIFI_ANALYZER_PROMETHEUS_TOKEN": ""}, clear=False):
            status, body, _ = self.request()
        self.assertEqual(status, 404)
        self.assertEqual(body, "Not found\n")

    def test_exporter_hides_endpoint_for_a_short_configured_token(self):
        with patch.dict(os.environ, {"WIFI_ANALYZER_PROMETHEUS_TOKEN": "too-short"}, clear=False):
            status, body, _ = self.request()
        self.assertEqual(status, 404)
        self.assertEqual(body, "Not found\\n")

    def test_exporter_rejects_missing_wrong_and_query_string_credentials(self):
        token = "test-prometheus-export-token-0123456789abcdef"
        with patch.dict(os.environ, {"WIFI_ANALYZER_PROMETHEUS_TOKEN": token}, clear=False):
            self.assertEqual(self.request()[0], 401)
            self.assertEqual(self.request(token="incorrect-token")[0], 401)
            self.assertEqual(self.request(path=f"/metrics?token={token}")[0], 401)

    def test_exporter_returns_aggregate_metrics_only_after_bearer_authentication(self):
        token = "test-prometheus-export-token-0123456789abcdef"
        self.telemetry.record_scan("local", [{
            "ssid": "private-office-name",
            "bssid": "02:11:22:33:44:55",
            "band": "2.4GHz",
            "rssi": -48,
            "security": "Open",
        }])
        self.telemetry.record_scan("another-site", [{
            "ssid": "other-site-private-name",
            "bssid": "02:aa:bb:cc:dd:ee",
            "band": "5GHz",
            "rssi": -20,
        }])
        with patch.dict(os.environ, {"WIFI_ANALYZER_PROMETHEUS_TOKEN": token}, clear=False):
            status, body, headers = self.request(token=token)

        self.assertEqual(status, 200)
        self.assertIn("text/plain; version=0.0.4", headers.get("Content-Type", ""))
        self.assertIn("wifi_analyzer_up 1", body)
        self.assertIn("wifi_analyzer_networks_per_scan 1", body)
        self.assertIn("wifi_analyzer_average_rssi_dbm -48", body)
        self.assertIn("wifi_analyzer_scan_samples_24h 1", body)
        self.assertNotIn("private-office-name", body)
        self.assertNotIn("other-site-private-name", body)
        self.assertNotIn("wifi_analyzer_average_rssi_dbm -20", body)
        self.assertNotIn("02:11:22:33:44:55", body)
        self.assertNotIn("ssid=", body)
        self.assertNotIn("bssid=", body)
        self.assertNotIn('site_id=', body)
