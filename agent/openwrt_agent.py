"""Read-only OpenWrt telemetry agent with TLS transport and a bounded durable outbox.

The collector invokes only fixed, read-only ubus/ip/iw commands. It never runs a
shell, copies wireless credentials, or changes router configuration.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import signal
import ssl
import stat
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


AGENT_VERSION = "1.0.0"
ADAPTER_ID = "openwrt"
CAPABILITIES = [
    "system.board",
    "network.interfaces",
    "network.routes",
    "wireless.radios",
    "wireless.associations",
    "inventory.snapshot",
]
MAX_CONFIG_BYTES = 16 * 1024
MAX_COMMAND_OUTPUT_BYTES = 256 * 1024
MAX_SNAPSHOT_BYTES = 512 * 1024
MAX_OUTBOX_BYTES = 768 * 1024
MAX_HTTP_RESPONSE_BYTES = 64 * 1024
AGENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
TOKEN_PATTERN = re.compile(r"^wpa_[A-Za-z0-9_-]{32,128}$")
IFNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")
MAC_PATTERN = re.compile(r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$")
_LOG = logging.getLogger("wifi_analyzer_openwrt_agent")


class AgentError(RuntimeError):
    """Base error for safe, user-displayable agent failures."""


class AgentConfigError(AgentError):
    """Raised for invalid or insecure local agent configuration."""


class AgentTransportError(AgentError):
    """Raised when the authenticated API cannot be reached."""


class CollectorError(AgentError):
    """Raised when a required local telemetry command is unavailable."""

    def __init__(self, message: str, error_code: str = "SCAN_UNAVAILABLE"):
        super().__init__(message)
        self.error_code = error_code


@dataclass(frozen=True)
class AgentConfig:
    agent_id: str
    server_url: str
    token: str = field(repr=False)
    state_dir: Path
    interval_seconds: int = 300
    request_timeout_seconds: int = 10
    allow_insecure_http: bool = False

    @classmethod
    def from_mapping(cls, value: object) -> "AgentConfig":
        if not isinstance(value, dict):
            raise AgentConfigError("Agent configuration must be a JSON object")
        allowed = {
            "agent_id", "server_url", "token", "state_dir",
            "interval_seconds", "request_timeout_seconds", "allow_insecure_http",
        }
        unknown = set(value) - allowed
        if unknown:
            raise AgentConfigError("Agent configuration contains unknown fields")
        agent_id = value.get("agent_id")
        if not isinstance(agent_id, str) or not AGENT_ID_PATTERN.fullmatch(agent_id):
            raise AgentConfigError("agent_id must be a 1 to 64 character identifier")
        server_url = value.get("server_url")
        if not isinstance(server_url, str) or not 1 <= len(server_url) <= 2048:
            raise AgentConfigError("server_url must be a valid HTTP(S) URL")
        if any(ord(char) <= 32 for char in server_url):
            raise AgentConfigError("server_url contains invalid whitespace")
        try:
            parsed = urlsplit(server_url)
        except ValueError as error:
            raise AgentConfigError("server_url must be a valid HTTP(S) URL") from error
        if (
            parsed.scheme not in {"https", "http"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise AgentConfigError("server_url must be an HTTP(S) URL without credentials, query or fragment")
        allow_insecure = value.get("allow_insecure_http", False)
        if not isinstance(allow_insecure, bool):
            raise AgentConfigError("allow_insecure_http must be a boolean")
        if parsed.scheme == "http" and not allow_insecure:
            raise AgentConfigError("HTTP is disabled; use HTTPS or explicitly enable allow_insecure_http on a trusted LAN")
        token = value.get("token")
        if not isinstance(token, str) or not TOKEN_PATTERN.fullmatch(token):
            raise AgentConfigError("token must be an enrolled WiFi Analyzer Pro agent credential")
        state_dir_value = value.get("state_dir", "/var/lib/wifi-analyzer-agent")
        if not isinstance(state_dir_value, str) or not state_dir_value.startswith("/"):
            raise AgentConfigError("state_dir must be an absolute path")
        interval = value.get("interval_seconds", 300)
        timeout = value.get("request_timeout_seconds", 10)
        if isinstance(interval, bool) or not isinstance(interval, int) or not 30 <= interval <= 86400:
            raise AgentConfigError("interval_seconds must be between 30 and 86400")
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 3 <= timeout <= 60:
            raise AgentConfigError("request_timeout_seconds must be between 3 and 60")
        return cls(
            agent_id=agent_id,
            server_url=server_url.rstrip("/"),
            token=token,
            state_dir=Path(state_dir_value),
            interval_seconds=interval,
            request_timeout_seconds=timeout,
            allow_insecure_http=allow_insecure,
        )


def load_config(path: str | os.PathLike) -> AgentConfig:
    config_path = Path(path)
    if config_path.is_symlink():
        raise AgentConfigError("Agent configuration must not be a symbolic link")
    try:
        info = config_path.stat()
    except OSError as error:
        raise AgentConfigError("Agent configuration file could not be read") from error
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CONFIG_BYTES:
        raise AgentConfigError("Agent configuration must be a regular file no larger than 16 KiB")
    if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
        raise AgentConfigError("Agent configuration permissions are too broad; use chmod 600")
    try:
        raw = config_path.read_text(encoding="utf-8")
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AgentConfigError("Agent configuration is not valid UTF-8 JSON") from error
    return AgentConfig.from_mapping(value)


def _decode_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _finite_number(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number != number or number in (float("inf"), float("-inf")):
        return None
    return number


class OpenWrtCollector:
    """Collect a whitelisted OpenWrt snapshot without invoking a shell."""

    def __init__(
        self,
        runner: Callable | None = None,
        command_timeout_seconds: int = 5,
    ):
        self.runner = runner or self._subprocess_runner
        self.command_timeout_seconds = command_timeout_seconds
        self.warnings: list[str] = []

    @staticmethod
    def _subprocess_runner(argv: list[str], timeout: int):
        return subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
            shell=False,
            text=True,
            encoding="utf-8",
            errors="replace",
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"},
        )

    def _run(self, argv: list[str], *, optional: bool = False) -> str | None:
        try:
            result = self.runner(argv, timeout=self.command_timeout_seconds)
        except FileNotFoundError as error:
            if optional:
                self.warnings.append("optional_command_unavailable")
                return None
            raise CollectorError("A required OpenWrt read-only command is unavailable") from error
        except subprocess.TimeoutExpired as error:
            if optional:
                self.warnings.append("optional_command_timeout")
                return None
            raise CollectorError("A required OpenWrt read-only command timed out", "NETWORK_TIMEOUT") from error
        except OSError as error:
            if optional:
                self.warnings.append("optional_command_failed")
                return None
            raise CollectorError("A required OpenWrt read-only command failed") from error
        stdout = _decode_output(getattr(result, "stdout", ""))
        if len(stdout.encode("utf-8")) > MAX_COMMAND_OUTPUT_BYTES:
            if optional:
                self.warnings.append("optional_command_output_too_large")
                return None
            raise CollectorError("A required OpenWrt command exceeded the output limit")
        if getattr(result, "returncode", 1) != 0:
            if optional:
                self.warnings.append("optional_command_failed")
                return None
            raise CollectorError("A required OpenWrt read-only command returned an error")
        return stdout

    def _json_command(self, argv: list[str], *, optional: bool = False) -> object | None:
        output = self._run(argv, optional=optional)
        if output is None:
            return None
        try:
            return json.loads(output)
        except json.JSONDecodeError as error:
            if optional:
                self.warnings.append("optional_command_invalid_json")
                return None
            raise CollectorError("A required OpenWrt command returned invalid JSON") from error

    @staticmethod
    def _board(value: object) -> dict:
        if not isinstance(value, dict):
            raise CollectorError("OpenWrt system board response is not an object")
        release = value.get("release")
        if not isinstance(release, dict):
            release = {}
        return {
            "model": value.get("model"),
            "board_name": value.get("board_name"),
            "hostname": value.get("hostname"),
            "kernel": value.get("kernel"),
            "release": {
                "distribution": release.get("distribution"),
                "version": release.get("version"),
                "revision": release.get("revision"),
                "target": release.get("target"),
            },
        }

    @staticmethod
    def _interfaces(value: object) -> list[dict]:
        if not isinstance(value, dict):
            raise CollectorError("OpenWrt network interface response is not an object", "NETWORK_TIMEOUT")
        entries = value.get("interface", [])
        if not isinstance(entries, list):
            raise CollectorError("OpenWrt network interface list is invalid", "NETWORK_TIMEOUT")
        output = []
        for record in entries[:256]:
            if not isinstance(record, dict):
                continue
            name = record.get("interface") or record.get("device")
            if not isinstance(name, str) or not IFNAME_PATTERN.fullmatch(name):
                continue
            ipv4 = record.get("ipv4-address", [])
            ipv6 = record.get("ipv6-address", [])
            output.append({
                "interface": name,
                "device": record.get("device") if isinstance(record.get("device"), str) else None,
                "proto": record.get("proto") if isinstance(record.get("proto"), str) else None,
                "up": record.get("up") if isinstance(record.get("up"), bool) else None,
                "ipv4-address": [
                    {"address": item.get("address"), "mask": item.get("mask")}
                    for item in ipv4[:32] if isinstance(item, dict)
                ] if isinstance(ipv4, list) else [],
                "ipv6-address": [
                    {"address": item.get("address"), "mask": item.get("mask")}
                    for item in ipv6[:32] if isinstance(item, dict)
                ] if isinstance(ipv6, list) else [],
            })
        return output

    @staticmethod
    def _channel_width(config: dict, info: dict) -> int | None:
        candidate = info.get("channel_width_mhz", info.get("channel_width", info.get("width")))
        numeric = _finite_number(candidate)
        if numeric is not None and numeric in {20, 40, 80, 160, 320}:
            return int(numeric)
        htmode = config.get("htmode")
        if isinstance(htmode, str):
            match = re.search(r"(320|160|80|40|20)$", htmode.upper())
            if match:
                return int(match.group(1))
        return None

    @classmethod
    def _wireless(cls, value: object) -> list[dict]:
        if not isinstance(value, dict):
            raise CollectorError("OpenWrt wireless status response is not an object", "RADIO_UNAVAILABLE")
        output = []
        for radio in value.values():
            if not isinstance(radio, dict):
                continue
            interfaces = radio.get("interfaces", [])
            if not isinstance(interfaces, list):
                continue
            for interface in interfaces[:256]:
                if not isinstance(interface, dict):
                    continue
                config = interface.get("config")
                info = interface.get("iwinfo")
                if not isinstance(config, dict):
                    config = {}
                if not isinstance(info, dict):
                    info = {}
                name = interface.get("ifname") or interface.get("interface")
                if not isinstance(name, str) or not IFNAME_PATTERN.fullmatch(name):
                    continue
                encryption = info.get("encryption")
                if encryption is None:
                    encryption = config.get("encryption")
                if isinstance(encryption, dict):
                    security = encryption.get("description")
                else:
                    security = encryption if isinstance(encryption, str) else None
                output.append({
                    "interface": name,
                    "ssid": info.get("ssid") or config.get("ssid"),
                    "bssid": info.get("bssid") or interface.get("macaddr"),
                    "frequency_mhz": info.get("frequency_mhz", info.get("frequency")),
                    "channel": info.get("channel"),
                    "channel_width_mhz": cls._channel_width(config, info),
                    "signal": info.get("signal"),
                    "noise": info.get("noise"),
                    "txpower": info.get("txpower"),
                    "security": security,
                    "up": interface.get("up") if isinstance(interface.get("up"), bool) else (
                        radio.get("up") if isinstance(radio.get("up"), bool) else None
                    ),
                })
        return output

    @staticmethod
    def _routes(value: object, *, ipv6: bool = False) -> list[dict]:
        if not isinstance(value, list):
            return []
        output = []
        default_target = "::/0" if ipv6 else "0.0.0.0/0"
        for route in value[:2048]:
            if not isinstance(route, dict):
                continue
            target = route.get("dst") or default_target
            if target == "default":
                target = default_target
            if not isinstance(target, str):
                continue
            gateway = route.get("gateway")
            device = route.get("dev")
            metric = route.get("metric")
            if isinstance(gateway, str) and len(gateway) > 64:
                gateway = None
            if not isinstance(device, str) or not IFNAME_PATTERN.fullmatch(device):
                device = None
            if isinstance(metric, bool) or not isinstance(metric, int) or not 0 <= metric <= 65535:
                metric = None
            output.append({
                "target": target,
                "nexthop": gateway,
                "device": device,
                "metric": metric,
            })
        return output

    @staticmethod
    def _parse_stations(output: str) -> list[dict]:
        stations = []
        current = None
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith("Station "):
                if current is not None:
                    stations.append(current)
                match = re.match(r"Station\s+([0-9A-Fa-f:]{17})", stripped)
                if not match or not MAC_PATTERN.fullmatch(match.group(1)):
                    current = None
                    continue
                current = {"mac": match.group(1).upper()}
            elif current is not None:
                if stripped.startswith("signal:"):
                    match = re.search(r"(-?[0-9]+)\s*dBm", stripped)
                    if match:
                        current["signal"] = int(match.group(1))
                elif stripped.startswith("tx bitrate:"):
                    match = re.search(r"([0-9]+(?:\.[0-9]+)?)\s*MBit/s", stripped)
                    if match:
                        current["tx"] = {"rate": float(match.group(1))}
                elif stripped.startswith("rx bitrate:"):
                    match = re.search(r"([0-9]+(?:\.[0-9]+)?)\s*MBit/s", stripped)
                    if match:
                        current["rx"] = {"rate": float(match.group(1))}
        if current is not None:
            stations.append(current)
        return stations[:8192]

    def _associations(self, radios: list[dict]) -> list[dict]:
        result = []
        seen = set()
        for radio in radios:
            interface = radio.get("interface")
            if not isinstance(interface, str) or not IFNAME_PATTERN.fullmatch(interface) or interface in seen:
                continue
            seen.add(interface)
            output = self._run(["iw", "dev", interface, "station", "dump"], optional=True)
            if output is None:
                continue
            stations = self._parse_stations(output)
            if stations:
                result.append({"interface": interface, "stations": stations})
        return result

    def collect(self) -> dict:
        self.warnings = []
        board_raw = self._json_command(["ubus", "call", "system", "board", "{}"])
        interfaces_raw = self._json_command(["ubus", "call", "network.interface", "dump", "{}"], optional=True)
        wireless_raw = self._json_command(["ubus", "call", "network.wireless", "status", "{}"], optional=True)
        if interfaces_raw is None:
            self.warnings.append("network_interfaces_unavailable")
            interfaces = []
        else:
            interfaces = self._interfaces(interfaces_raw)
        if wireless_raw is None:
            self.warnings.append("wireless_status_unavailable")
            radios = []
        else:
            try:
                radios = self._wireless(wireless_raw)
            except CollectorError:
                self.warnings.append("wireless_status_invalid")
                radios = []
        routes4 = self._json_command(["ip", "-j", "route", "show"], optional=True)
        routes6 = self._json_command(["ip", "-6", "-j", "route", "show"], optional=True)
        if routes4 is None:
            self.warnings.append("ipv4_routes_unavailable")
        if routes6 is None:
            self.warnings.append("ipv6_routes_unavailable")
        routes = self._routes(routes4) + self._routes(routes6, ipv6=True)
        associations = self._associations(radios)
        return {
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "board": self._board(board_raw),
            "interfaces": interfaces,
            "wireless": radios,
            "associations": associations,
            "routes": routes,
        }


class DurableOutbox:
    """Keep one bounded pending delivery and atomically replace it on disk."""

    def __init__(self, directory: str | os.PathLike):
        self.directory = Path(directory)
        self.path = self.directory / "pending-snapshot.json"

    def _secure_directory(self) -> None:
        if self.directory.is_symlink():
            raise AgentError("Agent state directory must not be a symbolic link")
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt":
            os.chmod(self.directory, 0o700)

    def load(self) -> dict | None:
        if not self.path.exists():
            return None
        if self.path.is_symlink():
            raise AgentError("Pending delivery path must not be a symbolic link")
        info = self.path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_OUTBOX_BYTES:
            raise AgentError("Pending delivery file is invalid or exceeds the size limit")
        if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
            raise AgentError("Pending delivery permissions are too broad")
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AgentError("Pending delivery file is corrupt; it was left untouched") from error
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("agent_id"), str)
            or not isinstance(value.get("delivery_id"), str)
            or not isinstance(value.get("snapshot"), dict)
        ):
            raise AgentError("Pending delivery file has an invalid envelope")
        try:
            uuid.UUID(value["delivery_id"])
        except ValueError as error:
            raise AgentError("Pending delivery file has an invalid delivery ID") from error
        return value

    def save(self, payload: dict) -> None:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
        if len(encoded) > MAX_OUTBOX_BYTES:
            raise AgentError("Pending delivery exceeds the local outbox size limit")
        self._secure_directory()
        temp_path = self.directory / f".pending-{os.getpid()}-{uuid.uuid4().hex}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temp_path, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, self.path)
            if os.name != "nt":
                os.chmod(self.path, 0o600)
                directory_fd = os.open(self.directory, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        finally:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass

    def clear(self) -> None:
        if self.path.is_symlink():
            raise AgentError("Pending delivery path must not be a symbolic link")
        try:
            self.path.unlink()
        except FileNotFoundError:
            return


class AgentApiClient:
    """Small standard-library HTTP client that never logs the bearer token."""

    def __init__(self, config: AgentConfig, opener: Callable | None = None):
        self.config = config
        self.opener = opener or urlopen

    def post(self, endpoint: str, payload: dict) -> dict:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
        if len(body) > MAX_OUTBOX_BYTES:
            raise AgentTransportError("API request exceeds the agent payload limit")
        url = self.config.server_url.rstrip("/") + endpoint
        request = Request(
            url,
            data=body,
            headers={
                "Authorization": f"Bearer {self.config.token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": f"WiFiAnalyzerOpenWrtAgent/{AGENT_VERSION}",
            },
            method="POST",
        )
        try:
            opener_options = {"timeout": self.config.request_timeout_seconds}
            if url.startswith("https://"):
                opener_options["context"] = ssl.create_default_context()
            response_context = self.opener(request, **opener_options)
            with response_context as response:
                status = getattr(response, "status", 200)
                raw = response.read(MAX_HTTP_RESPONSE_BYTES + 1)
        except HTTPError as error:
            if error.code in {401, 403}:
                raise AgentConfigError("Agent credential was rejected or revoked; re-enrol or rotate it") from error
            raise AgentTransportError(f"API rejected the agent request (HTTP {error.code})") from error
        except (URLError, TimeoutError, OSError) as error:
            raise AgentTransportError("API server is unavailable; the pending delivery was retained") from error
        if status not in {200, 201}:
            raise AgentTransportError(f"API returned unexpected HTTP status {status}")
        if len(raw) > MAX_HTTP_RESPONSE_BYTES:
            raise AgentTransportError("API response exceeded the size limit")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AgentTransportError("API returned invalid JSON") from error
        if not isinstance(value, dict):
            raise AgentTransportError("API response must be a JSON object")
        return value


class OpenWrtAgent:
    def __init__(
        self,
        config: AgentConfig,
        collector: OpenWrtCollector | None = None,
        client: AgentApiClient | None = None,
        outbox: DurableOutbox | None = None,
    ):
        self.config = config
        self.collector = collector or OpenWrtCollector()
        self.client = client or AgentApiClient(config)
        self.outbox = outbox or DurableOutbox(config.state_dir)

    def _heartbeat(self, status: str, error_code: str | None = None) -> dict:
        payload = {
            "agent_id": self.config.agent_id,
            "adapter_id": ADAPTER_ID,
            "agent_version": AGENT_VERSION,
            "status": status,
            "error_code": error_code,
            "capabilities": CAPABILITIES,
        }
        return self.client.post("/api/agents/heartbeat", payload)

    def _flush_pending(self) -> dict | None:
        payload = self.outbox.load()
        if payload is None:
            return None
        if payload["agent_id"] != self.config.agent_id:
            raise AgentError("Pending delivery belongs to a different agent; it was left untouched")
        response = self.client.post("/api/agents/snapshots/batch", payload)
        delivery = response.get("delivery")
        if not isinstance(delivery, dict) or delivery.get("id") is None:
            raise AgentTransportError("API acknowledgement did not contain a delivery record")
        self.outbox.clear()
        return delivery

    @staticmethod
    def _require_snapshot_scope(heartbeat: dict) -> None:
        agent = heartbeat.get("agent") if isinstance(heartbeat, dict) else None
        accepted = agent.get("capabilities", []) if isinstance(agent, dict) else []
        if not isinstance(accepted, list) or "inventory.snapshot" not in accepted:
            raise AgentConfigError("Agent credential is not scoped for inventory.snapshot")

    def run_once(self) -> dict:
        pending = self.outbox.load()
        try:
            heartbeat = self._heartbeat("healthy")
        except AgentTransportError:
            return {"status": "pending" if pending is not None else "offline", "pending": pending is not None}
        self._require_snapshot_scope(heartbeat)

        if pending is not None:
            try:
                heartbeat = self._heartbeat(
                    pending.get("agent_status", "healthy"), pending.get("error_code")
                )
                self._require_snapshot_scope(heartbeat)
                delivery = self._flush_pending()
            except AgentTransportError:
                return {"status": "pending", "pending": True}
            return {"status": "delivered_pending", "pending": False, "delivery": delivery}

        try:
            snapshot = self.collector.collect()
        except CollectorError as error:
            self._heartbeat("degraded", error.error_code)
            return {"status": "degraded", "error_code": error.error_code, "pending": False}

        error_code = None
        if self.collector.warnings:
            if any("wireless" in warning or "optional_command" in warning for warning in self.collector.warnings):
                error_code = "RADIO_UNAVAILABLE"
            elif any("network" in warning or "route" in warning for warning in self.collector.warnings):
                error_code = "NETWORK_TIMEOUT"
            else:
                error_code = "SCAN_UNAVAILABLE"

        payload = {
            "agent_id": self.config.agent_id,
            "delivery_id": str(uuid.uuid4()),
            "snapshot": snapshot,
            "agent_status": "degraded" if error_code else "healthy",
            "error_code": error_code,
        }
        self.outbox.save(payload)
        if error_code is not None:
            try:
                heartbeat = self._heartbeat("degraded", error_code)
                self._require_snapshot_scope(heartbeat)
            except AgentTransportError:
                return {"status": "pending", "pending": True, "warning_count": len(self.collector.warnings)}
        try:
            delivery = self._flush_pending()
        except AgentTransportError:
            return {"status": "pending", "pending": True, "warning_count": len(self.collector.warnings)}
        return {
            "status": "degraded" if error_code else "delivered",
            "pending": False,
            "delivery": delivery,
            "warning_count": len(self.collector.warnings),
        }

    def run_forever(self, stop: Callable[[], bool] | None = None) -> None:
        should_stop = stop or (lambda: False)
        while not should_stop():
            started = time.monotonic()
            try:
                result = self.run_once()
                _LOG.info("agent cycle status=%s pending=%s", result.get("status"), result.get("pending", False))
            except AgentConfigError:
                _LOG.exception("agent configuration or permission error")
            except AgentError as error:
                _LOG.warning("agent cycle unavailable: %s", error)
            elapsed = time.monotonic() - started
            remaining = max(1, self.config.interval_seconds - int(elapsed))
            for _ in range(remaining):
                if should_stop():
                    return
                time.sleep(1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only WiFi Analyzer Pro OpenWrt agent")
    parser.add_argument("command", choices=("run", "run-once", "check-config"))
    parser.add_argument("--config", default="/etc/wifi-analyzer/openwrt-agent.json")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        config = load_config(args.config)
        if args.command == "check-config":
            print("Agent configuration is valid; the bearer token was not displayed.")
            return 0
        agent = OpenWrtAgent(config)
        if args.command == "run-once":
            result = agent.run_once()
            print(json.dumps({key: value for key, value in result.items() if key != "delivery"}, sort_keys=True))
            return 0
        stopped = {"value": False}

        def stop_handler(_signum, _frame):
            stopped["value"] = True

        signal.signal(signal.SIGTERM, stop_handler)
        signal.signal(signal.SIGINT, stop_handler)
        agent.run_forever(lambda: stopped["value"])
        return 0
    except AgentError as error:
        print(f"Agent error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
