"""Optional Home Assistant MQTT discovery worker for aggregate Wi-Fi telemetry."""
from __future__ import annotations

import os
import re
import signal
import stat
import time
from pathlib import Path
from threading import Event
from typing import Any

if __package__:
    from .homeassistant_mqtt import (
        AVAILABILITY_OFFLINE,
        AVAILABILITY_ONLINE,
        build_discovery_messages,
        build_home_assistant_snapshot,
    )
    from .telemetry_store import WiFiTelemetryStore
else:
    from homeassistant_mqtt import (
        AVAILABILITY_OFFLINE,
        AVAILABILITY_ONLINE,
        build_discovery_messages,
        build_home_assistant_snapshot,
    )
    from telemetry_store import WiFiTelemetryStore

HOST_PATTERN = re.compile(r"^[A-Za-z0-9_.:%-]{1,253}$")
MAX_PASSWORD_FILE_BYTES = 4096


def _read_password_file(path_value: str | None) -> str | None:
    if path_value is None or not path_value.strip():
        return None
    path = Path(path_value).expanduser()
    try:
        descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        raise ValueError("MQTT password file could not be opened safely") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_PASSWORD_FILE_BYTES:
            raise ValueError("MQTT password file must be a regular file no larger than 4096 bytes")
        if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("MQTT password file must not be accessible by group or other users")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            raw = stream.read(MAX_PASSWORD_FILE_BYTES + 1)
        if len(raw) > MAX_PASSWORD_FILE_BYTES:
            raise ValueError("MQTT password file exceeds the 4096-byte limit")
        password = raw.decode("utf-8").rstrip("\r\n")
    except (OSError, UnicodeDecodeError):
        raise ValueError("MQTT password file is unreadable or invalid UTF-8") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not password:
        raise ValueError("MQTT password file must not be empty")
    return password


class HomeAssistantMqttPublisher:
    """Publish retained discovery/state messages with MQTT QoS 1 and broker TLS."""

    def __init__(
        self,
        *,
        host: str,
        device_id: str,
        port: int = 8883,
        username: str | None = None,
        password: str | None = None,
        tls: bool = True,
        ca_cert_file: str | None = None,
        discovery_prefix: str = "homeassistant",
        connect_timeout: float = 15,
        publish_timeout: float = 10,
        client_factory=None,
        mqtt_module=None,
    ):
        if not isinstance(host, str) or not HOST_PATTERN.fullmatch(host) or any(ch in host for ch in "/?#@\\"):
            raise ValueError("mqtt host must be a hostname or IP address, not a URL")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("mqtt port must be an integer from 1 to 65535")
        if not isinstance(tls, bool):
            raise ValueError("mqtt tls must be a boolean")
        if username is not None and (not isinstance(username, str) or not username.strip() or len(username) > 256):
            raise ValueError("mqtt username must contain 1 to 256 characters")
        if password is not None and (not isinstance(password, str) or not password or len(password.encode("utf-8")) > MAX_PASSWORD_FILE_BYTES):
            raise ValueError("mqtt password must contain 1 to 4096 UTF-8 bytes")
        if isinstance(connect_timeout, bool) or not isinstance(connect_timeout, (int, float)) or not 1 <= connect_timeout <= 60:
            raise ValueError("connect_timeout must be from 1 to 60 seconds")
        if isinstance(publish_timeout, bool) or not isinstance(publish_timeout, (int, float)) or not 1 <= publish_timeout <= 60:
            raise ValueError("publish_timeout must be from 1 to 60 seconds")

        self.host = host
        self.device_id = device_id
        self.port = port
        self.username = username.strip() if username else None
        self.password = password
        self.tls = tls
        self.ca_cert_file = ca_cert_file or None
        self.discovery_prefix = discovery_prefix
        self.connect_timeout = float(connect_timeout)
        self.publish_timeout = float(publish_timeout)
        self.state_topic = f"wifi-analyzer-pro/{device_id}/state"
        self.availability_topic = f"wifi-analyzer-pro/{device_id}/availability"
        self.birth_topic = "homeassistant/status"
        self.connected = Event()
        self.discovery_requested = Event()
        self.last_connection_error: str | None = None
        self._mqtt = mqtt_module
        self._client_factory = client_factory
        self.client = None

        # Validate static discovery inputs before any outbound connection.
        self.discovery_messages = build_discovery_messages(
            device_id, discovery_prefix=discovery_prefix,
        )

    def _load_mqtt(self):
        if self._mqtt is None:
            try:
                import paho.mqtt.client as mqtt
            except ImportError as error:
                raise RuntimeError("Install the paho-mqtt runtime dependency to enable Home Assistant integration") from error
            self._mqtt = mqtt
        return self._mqtt

    def start(self) -> None:
        mqtt = self._load_mqtt()
        factory = self._client_factory or mqtt.Client
        self.client = factory(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id=f"wifi-analyzer-pro-{self.device_id}",
            protocol=mqtt.MQTTv311,
        )
        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        self.client.on_message = self._on_message
        self.client.will_set(
            self.availability_topic,
            AVAILABILITY_OFFLINE,
            qos=1,
            retain=True,
        )
        if self.username:
            self.client.username_pw_set(self.username, self.password)
        elif self.password is not None:
            raise ValueError("mqtt password cannot be configured without a username")
        if self.tls:
            self.client.tls_set(ca_certs=self.ca_cert_file)
            self.client.tls_insecure_set(False)
        self.client.reconnect_delay_set(min_delay=1, max_delay=60)
        self.client.connect(self.host, self.port, keepalive=45)
        self.client.loop_start()
        if not self.connected.wait(self.connect_timeout):
            self.client.loop_stop()
            raise TimeoutError("MQTT broker did not complete its TLS/MQTT connection in time")
        if self.last_connection_error:
            self.client.loop_stop()
            raise ConnectionError("MQTT broker rejected the WiFi Analyzer Pro connection")

    def _on_connect(self, client, userdata, flags, reason_code, properties):
        if getattr(reason_code, "is_failure", False):
            self.last_connection_error = "connection_rejected"
            self.connected.clear()
            return
        self.last_connection_error = None
        self.connected.set()
        self.discovery_requested.set()
        client.subscribe(self.birth_topic, qos=1)

    def _on_disconnect(self, client, userdata, disconnect_flags, reason_code, properties):
        self.connected.clear()

    def _on_message(self, client, userdata, message):
        if message.topic != self.birth_topic:
            return
        try:
            payload = message.payload.decode("utf-8").strip().lower()
        except UnicodeDecodeError:
            return
        if payload == AVAILABILITY_ONLINE:
            self.discovery_requested.set()

    def publish(self, topic: str, payload: str, *, retain: bool = True) -> None:
        if not self.connected.is_set() or self.client is None:
            raise ConnectionError("MQTT broker is not connected")
        info = self.client.publish(topic, payload, qos=1, retain=retain)
        mqtt = self._load_mqtt()
        if info.rc != mqtt.MQTT_ERR_SUCCESS:
            raise RuntimeError("MQTT publish was not accepted by the client")
        info.wait_for_publish(timeout=self.publish_timeout)
        if not info.is_published():
            raise TimeoutError("MQTT broker did not acknowledge the retained message")

    def publish_discovery(self) -> int:
        self.publish(self.availability_topic, AVAILABILITY_ONLINE)
        for item in self.discovery_messages:
            self.publish(item["topic"], item["payload"])
        self.discovery_requested.clear()
        return len(self.discovery_messages)

    def publish_snapshot(self, snapshot: dict[str, Any]) -> None:
        import json
        self.publish(self.state_topic, json.dumps(
            snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ))

    def stop(self) -> None:
        if self.client is None:
            return
        try:
            if self.connected.is_set():
                try:
                    self.publish(self.availability_topic, AVAILABILITY_OFFLINE)
                except Exception:
                    pass
        finally:
            try:
                self.client.disconnect()
            finally:
                self.client.loop_stop()
                self.connected.clear()


class HomeAssistantMqttWorker:
    def __init__(
        self,
        *,
        telemetry: WiFiTelemetryStore | None = None,
        site_id: str = "local",
        publisher: HomeAssistantMqttPublisher,
    ):
        self.telemetry = telemetry or WiFiTelemetryStore()
        self.site_id = site_id
        self.publisher = publisher

    def publish_once(self) -> dict:
        if self.publisher.discovery_requested.is_set():
            discovery_count = self.publisher.publish_discovery()
        else:
            discovery_count = 0
        rollups = self.telemetry.history(site_ids=[self.site_id], days=1, limit=1440)
        snapshot = build_home_assistant_snapshot(rollups)
        self.publisher.publish_snapshot(snapshot)
        return {
            "discovery_message_count": discovery_count,
            "telemetry_available": snapshot["telemetry_available"],
            "telemetry_fresh": snapshot["telemetry_fresh"],
            "state_topic": self.publisher.state_topic,
        }


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be true or false")


def main() -> int:
    try:
        host = os.environ.get("WIFI_ANALYZER_HA_MQTT_HOST", "").strip()
        device_id = os.environ.get("WIFI_ANALYZER_HA_DEVICE_ID", "").strip()
        if not host or not device_id:
            raise ValueError("Set WIFI_ANALYZER_HA_MQTT_HOST and WIFI_ANALYZER_HA_DEVICE_ID to enable this worker")
        tls = _env_bool("WIFI_ANALYZER_HA_MQTT_TLS", True)
        port = int(os.environ.get("WIFI_ANALYZER_HA_MQTT_PORT", "8883" if tls else "1883"))
        username = os.environ.get("WIFI_ANALYZER_HA_MQTT_USERNAME") or None
        password = _read_password_file(os.environ.get("WIFI_ANALYZER_HA_MQTT_PASSWORD_FILE"))
        poll_seconds = float(os.environ.get("WIFI_ANALYZER_HA_MQTT_POLL_SECONDS", "60"))
        if not 10 <= poll_seconds <= 3600:
            raise ValueError("WIFI_ANALYZER_HA_MQTT_POLL_SECONDS must be from 10 to 3600")
        publisher = HomeAssistantMqttPublisher(
            host=host,
            device_id=device_id,
            port=port,
            username=username,
            password=password,
            tls=tls,
            ca_cert_file=os.environ.get("WIFI_ANALYZER_HA_MQTT_CA_CERT_FILE"),
            discovery_prefix=os.environ.get("WIFI_ANALYZER_HA_MQTT_DISCOVERY_PREFIX", "homeassistant"),
        )
    except (TypeError, ValueError) as error:
        raise SystemExit(str(error)) from None

    worker = HomeAssistantMqttWorker(
        site_id=os.environ.get("WIFI_ANALYZER_LOCAL_SITE_ID", "local"),
        publisher=publisher,
    )
    stopping = False

    def request_stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    print("WiFi Analyzer Pro Home Assistant MQTT worker starting.")
    try:
        publisher.start()
        while not stopping:
            try:
                result = worker.publish_once()
                print(
                    "Home Assistant telemetry published: "
                    f"available={result['telemetry_available']}, "
                    f"fresh={result['telemetry_fresh']}, "
                    f"discovery_messages={result['discovery_message_count']}."
                )
            except Exception as error:
                # Do not print broker exception text, credentials, or payload contents.
                print(f"Home Assistant MQTT publish failed ({type(error).__name__}).")
            if stopping:
                break
            # Bound retries even if a failed discovery publish leaves its request pending.
            time.sleep(poll_seconds)
    finally:
        publisher.stop()
    print("WiFi Analyzer Pro Home Assistant MQTT worker stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
