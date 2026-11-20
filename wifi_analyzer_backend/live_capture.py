"""Explicit, bounded local packet capture using the system tcpdump/libpcap tool."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

if __package__:
    from .site_history import default_history_path
else:
    from site_history import default_history_path

MAX_DURATION_SECONDS = 60
MAX_PACKETS = 1000
SNAPLEN_BYTES = 256
MAX_CAPTURE_BYTES = 512 * 1024
CAPTURE_RETENTION_SECONDS = 24 * 60 * 60
_INTERFACE = re.compile(r"^(?:[A-Za-z0-9_.:@-]{1,64}|\\\\Device\\\\NPF_\\{[A-Fa-f0-9-]{36}\\})$")
_CAPTURE_ID = re.compile(r"^[a-f0-9]{32}$")

FILTER_PROFILES = {
    "all": None,
    "dns": "port 53",
    "dhcp": "udp port 67 or udp port 68",
    "arp": "arp",
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp or icmp6",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _bounded_integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer between {minimum} and {maximum}")
    return value


class LiveCaptureManager:
    """Manage one explicitly requested tcpdump capture with strict resource bounds."""

    def __init__(self, directory: str | os.PathLike[str] | None = None):
        self.directory = Path(directory).expanduser() if directory is not None else (
            default_history_path().parent / "captures"
        )
        self._lock = threading.RLock()
        self._captures: dict[str, dict[str, Any]] = {}
        self._active_id: str | None = None

    def _ensure_directory(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt":
            try:
                os.chmod(self.directory, 0o700)
            except OSError as error:
                raise RuntimeError("could not secure the capture directory") from error

    @staticmethod
    def _tcpdump_path() -> str | None:
        return shutil.which("tcpdump")

    def list_interfaces(self) -> dict[str, Any]:
        executable = self._tcpdump_path()
        if not executable:
            return {
                "available": False,
                "reason": "tcpdump/libpcap is not installed on this host.",
                "interfaces": [],
                "maximum_duration_seconds": MAX_DURATION_SECONDS,
                "maximum_packets": MAX_PACKETS,
                "maximum_capture_bytes": MAX_CAPTURE_BYTES,
            }
        try:
            result = subprocess.run(
                [executable, "-D"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return {
                "available": False,
                "reason": "The packet-capture interface inventory could not be read.",
                "interfaces": [],
                "maximum_duration_seconds": MAX_DURATION_SECONDS,
                "maximum_packets": MAX_PACKETS,
                "maximum_capture_bytes": MAX_CAPTURE_BYTES,
            }
        if result.returncode != 0:
            return {
                "available": False,
                "reason": "tcpdump could not enumerate capture interfaces; check libpcap and host permissions.",
                "interfaces": [],
                "maximum_duration_seconds": MAX_DURATION_SECONDS,
                "maximum_packets": MAX_PACKETS,
                "maximum_capture_bytes": MAX_CAPTURE_BYTES,
            }

        interfaces = []
        seen = set()
        for line in (result.stdout or "").splitlines():
            match = re.match(r"^\s*\d+\.(\S+)", line)
            if not match:
                continue
            name = match.group(1).strip()
            if not _INTERFACE.fullmatch(name) or name in seen:
                continue
            seen.add(name)
            interfaces.append({"name": name, "description": line.strip()[:160]})
        return {
            "available": bool(interfaces),
            "reason": None if interfaces else "No capture-capable network interfaces were reported by libpcap.",
            "interfaces": interfaces,
            "maximum_duration_seconds": MAX_DURATION_SECONDS,
            "maximum_packets": MAX_PACKETS,
            "maximum_capture_bytes": MAX_CAPTURE_BYTES,
            "snaplen_bytes": SNAPLEN_BYTES,
            "filter_profiles": sorted(FILTER_PROFILES),
        }

    def _prune(self) -> None:
        cutoff = time.time() - CAPTURE_RETENTION_SECONDS
        for path in self.directory.glob("capture-*.pcap"):
            try:
                if path.stat().st_mtime < cutoff:
                    path.unlink(missing_ok=True)
            except OSError:
                continue
        for capture_id, capture in list(self._captures.items()):
            if capture["state"] != "running" and capture["created_epoch"] < cutoff:
                self._captures.pop(capture_id, None)

    @staticmethod
    def _public(capture: dict[str, Any]) -> dict[str, Any]:
        return {
            "capture_id": capture["capture_id"],
            "interface": capture["interface"],
            "filter_profile": capture["filter_profile"],
            "duration_limit_seconds": capture["duration_limit_seconds"],
            "packet_limit": capture["packet_limit"],
            "state": capture["state"],
            "started_at": capture["started_at"],
            "finished_at": capture.get("finished_at"),
            "captured_bytes": capture.get("captured_bytes", 0),
            "error": capture.get("error"),
        }

    def status(self) -> dict[str, Any]:
        with self._lock:
            capture = self._captures.get(self._active_id) if self._active_id else None
            if capture is None and self._captures:
                capture = max(self._captures.values(), key=lambda item: item["created_epoch"])
            return {"capture": self._public(capture) if capture else None}

    def start(
        self,
        *,
        interface: Any,
        duration_seconds: Any = 15,
        packet_limit: Any = 250,
        filter_profile: Any = "all",
    ) -> dict[str, Any]:
        duration = _bounded_integer(duration_seconds, "duration_seconds", 5, MAX_DURATION_SECONDS)
        packets = _bounded_integer(packet_limit, "packet_limit", 1, MAX_PACKETS)
        if not isinstance(filter_profile, str) or filter_profile not in FILTER_PROFILES:
            raise ValueError("filter_profile is not supported")
        if not isinstance(interface, str) or not _INTERFACE.fullmatch(interface):
            raise ValueError("interface is invalid")

        inventory = self.list_interfaces()
        allowed = {item["name"] for item in inventory["interfaces"]}
        if not inventory["available"] or interface not in allowed:
            raise ValueError("interface is not available for packet capture")

        executable = self._tcpdump_path()
        if not executable:
            raise RuntimeError("tcpdump/libpcap is not installed on this host")

        with self._lock:
            current = self._captures.get(self._active_id) if self._active_id else None
            if current and current["state"] == "running":
                raise RuntimeError("a packet capture is already running")
            try:
                self._ensure_directory()
                self._prune()
            except OSError as error:
                raise RuntimeError("could not prepare the private capture directory") from error

            capture_id = uuid.uuid4().hex
            capture_path = self.directory / f"capture-{capture_id}.pcap"
            stderr_path = self.directory / f"capture-{capture_id}.log"
            command = [
                executable, "-nn", "-U", "-i", interface,
                "-s", str(SNAPLEN_BYTES), "-c", str(packets),
                "-w", str(capture_path),
            ]
            bpf = FILTER_PROFILES[filter_profile]
            if bpf:
                command.append(bpf)

            try:
                with stderr_path.open("xb") as stderr:
                    process = subprocess.Popen(
                        command,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=stderr,
                        close_fds=True,
                        start_new_session=(os.name != "nt"),
                    )
                if os.name != "nt":
                    os.chmod(stderr_path, 0o600)
            except (OSError, subprocess.SubprocessError) as error:
                capture_path.unlink(missing_ok=True)
                stderr_path.unlink(missing_ok=True)
                raise RuntimeError("tcpdump could not start; check capture privileges and interface support") from error

            capture = {
                "capture_id": capture_id,
                "interface": interface,
                "filter_profile": filter_profile,
                "duration_limit_seconds": duration,
                "packet_limit": packets,
                "state": "running",
                "started_at": _utc_now(),
                "finished_at": None,
                "captured_bytes": 0,
                "error": None,
                "created_epoch": time.time(),
                "deadline": time.monotonic() + duration,
                "file_path": capture_path,
                "stderr_path": stderr_path,
                "process": process,
                "stop_event": threading.Event(),
                "thread": None,
                "stop_reason": None,
            }
            self._captures[capture_id] = capture
            self._active_id = capture_id
            thread = threading.Thread(
                target=self._monitor,
                args=(capture_id,),
                name=f"wifi-pcap-{capture_id[:8]}",
                daemon=True,
            )
            capture["thread"] = thread
            public_capture = self._public(capture)
            thread.start()
            return public_capture

    def _terminate(self, capture: dict[str, Any], reason: str) -> None:
        capture["stop_reason"] = reason
        try:
            if capture["process"].poll() is None:
                capture["process"].terminate()
        except OSError:
            try:
                capture["process"].kill()
            except OSError:
                pass

    def _monitor(self, capture_id: str) -> None:
        with self._lock:
            capture = self._captures.get(capture_id)
        if capture is None:
            return
        process = capture["process"]
        stop_event = capture["stop_event"]

        while process.poll() is None:
            if stop_event.wait(0.1):
                self._terminate(capture, "operator_stopped")
                break
            if time.monotonic() >= capture["deadline"]:
                self._terminate(capture, "duration_limit")
                break
            try:
                if capture["file_path"].stat().st_size > MAX_CAPTURE_BYTES:
                    self._terminate(capture, "size_limit")
                    break
            except FileNotFoundError:
                pass

        try:
            return_code = process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            return_code = process.wait(timeout=2)
        except Exception:
            return_code = getattr(process, "returncode", None)

        try:
            size = capture["file_path"].stat().st_size
        except OSError:
            size = 0

        stop_reason = capture.get("stop_reason")
        complete = (
            size >= 24
            and size <= MAX_CAPTURE_BYTES
            and (
                return_code == 0
                or stop_reason in {"operator_stopped", "duration_limit"}
            )
        )
        if not complete:
            capture["file_path"].unlink(missing_ok=True)
            if size > MAX_CAPTURE_BYTES:
                error = "Capture exceeded the 512 KiB safety limit and was discarded."
            else:
                error = "tcpdump did not produce a usable capture; check host privileges and interface support."
        else:
            error = None
            if os.name != "nt":
                try:
                    capture["file_path"].chmod(0o600)
                except OSError:
                    error = "Could not secure the completed capture file permissions."
                    complete = False
                    capture["file_path"].unlink(missing_ok=True)

        with self._lock:
            capture["state"] = "completed" if complete else "failed"
            capture["finished_at"] = _utc_now()
            capture["captured_bytes"] = size if complete else 0
            capture["error"] = error
            if self._active_id == capture_id:
                self._active_id = None

    def stop(self, capture_id: Any = None) -> dict[str, Any]:
        with self._lock:
            selected_id = capture_id or self._active_id
            if not isinstance(selected_id, str) or not _CAPTURE_ID.fullmatch(selected_id):
                raise ValueError("capture_id is invalid")
            capture = self._captures.get(selected_id)
            if capture is None:
                raise KeyError("capture not found")
            if capture["state"] == "running":
                capture["stop_event"].set()
                self._terminate(capture, "operator_stopped")
            thread = capture.get("thread")

        if thread and thread is not threading.current_thread():
            thread.join(timeout=5)
        with self._lock:
            return self._public(capture)

    def capture_file(self, capture_id: Any) -> Path | None:
        if not isinstance(capture_id, str) or not _CAPTURE_ID.fullmatch(capture_id):
            return None
        with self._lock:
            capture = self._captures.get(capture_id)
            if not capture or capture["state"] != "completed":
                return None
            path = capture["file_path"]
            try:
                if not path.is_file() or path.stat().st_size > MAX_CAPTURE_BYTES:
                    return None
            except OSError:
                return None
            return path
