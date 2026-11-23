"""Privacy-preserving Home Assistant MQTT discovery and telemetry snapshots."""
from __future__ import annotations

import json
import math
import re
from datetime import datetime, timezone
from typing import Any

DEVICE_ID = re.compile(r"^[A-Za-z0-9_-]{1,48}$")
DISCOVERY_PREFIX = re.compile(r"^[A-Za-z0-9_-]{1,48}$")
AVAILABILITY_ONLINE = "online"
AVAILABILITY_OFFLINE = "offline"
TELEMETRY_FRESHNESS_SECONDS = 300

# Each value is a privacy-minimised aggregate already persisted by the telemetry store.
SENSORS = (
    {"key":"networks_per_scan","name":"Access points per scan","unit":"networks","icon":"mdi:access-point-network","device_class":None},
    {"key":"open_networks_per_scan","name":"Open access points per scan","unit":"networks","icon":"mdi:access-point-network-off","device_class":None},
    {"key":"networks_2_4ghz_per_scan","name":"2.4 GHz access points per scan","unit":"networks","icon":"mdi:wifi","device_class":None},
    {"key":"networks_5ghz_per_scan","name":"5 GHz access points per scan","unit":"networks","icon":"mdi:wifi","device_class":None},
    {"key":"networks_6ghz_per_scan","name":"6 GHz access points per scan","unit":"networks","icon":"mdi:wifi-star","device_class":None},
    {"key":"average_rssi_dbm","name":"Average Wi-Fi signal","unit":"dBm","icon":"mdi:wifi-strength-2","device_class":"signal_strength"},
    {"key":"gateway_latency_ms","name":"Gateway latency","unit":"ms","icon":"mdi:lan-connect","device_class":"duration"},
    {"key":"gateway_jitter_ms","name":"Gateway jitter","unit":"ms","icon":"mdi:chart-line-variant","device_class":"duration"},
    {"key":"gateway_packet_loss_percent","name":"Gateway packet loss","unit":"%","icon":"mdi:network-pos","device_class":None},
    {"key":"speedtest_download_mbps","name":"Speed-test download","unit":"Mbit/s","icon":"mdi:download-network","device_class":"data_rate"},
    {"key":"speedtest_upload_mbps","name":"Speed-test upload","unit":"Mbit/s","icon":"mdi:upload-network","device_class":"data_rate"},
    {"key":"speedtest_ping_ms","name":"Speed-test ping","unit":"ms","icon":"mdi:timer-outline","device_class":"duration"},
    {"key":"scan_samples_24h","name":"Wi-Fi scans in 24 hours","unit":"scans","icon":"mdi:radar","device_class":None},
    {"key":"diagnostic_samples_24h","name":"Diagnostics in 24 hours","unit":"samples","icon":"mdi:heart-pulse","device_class":None},
    {"key":"speedtest_samples_24h","name":"Speed tests in 24 hours","unit":"tests","icon":"mdi:speedometer","device_class":None},
)


def _aware_now(value: datetime | None) -> datetime:
    moment = value or datetime.now(timezone.utc)
    if not isinstance(moment, datetime) or moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("now must be a timezone-aware datetime")
    return moment.astimezone(timezone.utc)


def _number(value: object) -> float | int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if not math.isfinite(number):
        return None
    return number


def _count(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value


def build_home_assistant_snapshot(
    rollups: list[dict[str, Any]],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build one JSON state object. No site, SSID, BSSID, client or IP data is emitted."""
    if not isinstance(rollups, list) or len(rollups) > 1_440:
        raise ValueError("rollups must be a list containing no more than 1440 minute records")
    if any(not isinstance(row, dict) for row in rollups):
        raise ValueError("each telemetry rollup must be an object")
    moment = _aware_now(now)
    dated_rows: list[tuple[datetime, dict[str, Any]]] = []
    for row in rollups:
        raw_minute = row.get("minute_utc")
        if not isinstance(raw_minute, str) or not raw_minute.strip():
            raise ValueError("each telemetry minute must be a timezone-aware timestamp")
        try:
            parsed_minute = datetime.fromisoformat(raw_minute.replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError("each telemetry minute must be a timezone-aware timestamp") from error
        if parsed_minute.tzinfo is None or parsed_minute.utcoffset() is None:
            raise ValueError("each telemetry minute must include a timezone offset")
        dated_rows.append((parsed_minute.astimezone(timezone.utc), row))
    dated_rows.sort(key=lambda item: item[0])
    latest_minute, latest = dated_rows[-1] if dated_rows else (None, None)

    snapshot: dict[str, Any] = {
        "telemetry_available": latest is not None,
        "telemetry_fresh": False,
        "telemetry_age_seconds": None,
        "scan_samples_24h": sum(_count(row.get("scan_count")) for row in rows),
        "diagnostic_samples_24h": sum(_count(row.get("diagnostics_count")) for row in rows),
        "speedtest_samples_24h": sum(_count(row.get("speedtest_count")) for row in rows),
    }
    if latest is None:
        return snapshot

    age = (moment - latest_minute).total_seconds()
    snapshot["telemetry_age_seconds"] = round(age, 1)
    snapshot["telemetry_fresh"] = 0 <= age <= TELEMETRY_FRESHNESS_SECONDS

    for key in (
        "networks_per_scan",
        "open_networks_per_scan",
        "networks_2_4ghz_per_scan",
        "networks_5ghz_per_scan",
        "networks_6ghz_per_scan",
        "average_rssi_dbm",
        "gateway_latency_ms",
        "gateway_jitter_ms",
        "gateway_packet_loss_percent",
        "speedtest_download_mbps",
        "speedtest_upload_mbps",
        "speedtest_ping_ms",
    ):
        source_key = {
            "networks_per_scan": "average_network_count",
            "open_networks_per_scan": "average_open_network_count",
            "networks_2_4ghz_per_scan": "average_2_4ghz_network_count",
            "networks_5ghz_per_scan": "average_5ghz_network_count",
            "networks_6ghz_per_scan": "average_6ghz_network_count",
            "average_rssi_dbm": "average_rssi_dbm",
            "gateway_latency_ms": "average_latency_ms",
            "gateway_jitter_ms": "average_jitter_ms",
            "gateway_packet_loss_percent": "average_packet_loss_pct",
            "speedtest_download_mbps": "average_speedtest_download_mbps",
            "speedtest_upload_mbps": "average_speedtest_upload_mbps",
            "speedtest_ping_ms": "average_speedtest_ping_ms",
        }[key]
        snapshot[key] = _number(latest.get(source_key))
    return snapshot


def build_discovery_messages(
    device_id: str,
    *,
    discovery_prefix: str = "homeassistant",
) -> list[dict[str, str]]:
    """Build retained, single-component Home Assistant MQTT discovery messages."""
    if not isinstance(device_id, str) or not DEVICE_ID.fullmatch(device_id):
        raise ValueError("device_id must contain 1 to 48 letters, digits, underscores or hyphens")
    if not isinstance(discovery_prefix, str) or not DISCOVERY_PREFIX.fullmatch(discovery_prefix):
        raise ValueError("discovery_prefix must contain 1 to 48 letters, digits, underscores or hyphens")

    state_topic = f"wifi-analyzer-pro/{device_id}/state"
    availability_topic = f"wifi-analyzer-pro/{device_id}/availability"
    device = {
        "identifiers": [f"wifi_analyzer_pro_{device_id}"],
        "name": "WiFi Analyzer Pro",
        "manufacturer": "NetCore Technologies",
        "model": "WiFi Analyzer Pro",
    }
    messages: list[dict[str, str]] = []
    for sensor in SENSORS:
        key = sensor["key"]
        unique_id = f"wifi_analyzer_pro_{device_id}_{key}"
        config: dict[str, Any] = {
            "name": sensor["name"],
            "unique_id": unique_id,
            "state_topic": state_topic,
            "value_template": f"{{{{ value_json.{key} if value_json.{key} is not none else 'unknown' }}}}",
            "availability_topic": availability_topic,
            "payload_available": AVAILABILITY_ONLINE,
            "payload_not_available": AVAILABILITY_OFFLINE,
            "device": device,
            "icon": sensor["icon"],
            "state_class": "measurement",
        }
        if sensor["unit"]:
            config["unit_of_measurement"] = sensor["unit"]
        if sensor["device_class"]:
            config["device_class"] = sensor["device_class"]
        messages.append({
            "topic": f"{discovery_prefix}/sensor/{device_id}_{key}/config",
            "payload": json.dumps(config, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        })

    binary_id = f"wifi_analyzer_pro_{device_id}_telemetry_fresh"
    binary_config = {
        "name": "Telemetry fresh",
        "unique_id": binary_id,
        "state_topic": state_topic,
        "value_template": "{{ 'ON' if value_json.telemetry_fresh else 'OFF' }}",
        "payload_on": "ON",
        "payload_off": "OFF",
        "device_class": "connectivity",
        "availability_topic": availability_topic,
        "payload_available": AVAILABILITY_ONLINE,
        "payload_not_available": AVAILABILITY_OFFLINE,
        "device": device,
        "icon": "mdi:check-network",
    }
    messages.append({
        "topic": f"{discovery_prefix}/binary_sensor/{device_id}_telemetry_fresh/config",
        "payload": json.dumps(binary_config, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
    })
    return messages


__all__ = [
    "AVAILABILITY_OFFLINE",
    "AVAILABILITY_ONLINE",
    "SENSORS",
    "TELEMETRY_FRESHNESS_SECONDS",
    "build_discovery_messages",
    "build_home_assistant_snapshot",
]
