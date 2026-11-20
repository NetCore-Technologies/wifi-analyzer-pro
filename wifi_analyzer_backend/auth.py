"""Local password and short-lived bearer-session management.

The password verifier is stored outside the repository with owner-only
permissions. Sessions are process-local and expire after a fixed lifetime.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import tempfile
import threading
import time
from pathlib import Path
from typing import Any


class AuthManager:
    def __init__(self, path: str | None = None, session_ttl_seconds: int = 12 * 60 * 60):
        configured = path or os.environ.get("WIFI_ANALYZER_AUTH_FILE")
        self.path = Path(configured).expanduser() if configured else Path.home() / ".config" / "wifi-analyzer-pro" / "auth.json"
        self.session_ttl_seconds = max(300, int(session_ttl_seconds))
        self._lock = threading.RLock()
        self._sessions: dict[str, float] = {}
        self._failed_login_count = 0
        self._locked_until = 0.0
        self._state: dict[str, Any] | None = None
        self._broken = False
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            self._state = None
            return
        try:
            state = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(state, dict) or state.get("version") != 1:
                raise ValueError("unsupported auth file format")
            salt = bytes.fromhex(state["salt"])
            verifier = bytes.fromhex(state["verifier"])
            if len(salt) != 16 or len(verifier) != 64:
                raise ValueError("invalid verifier material")
            self._state = state
            if os.name != "nt":
                os.chmod(self.path, 0o600)
        except Exception:
            # Never treat a damaged existing auth file as an unconfigured app.
            self._state = None
            self._broken = True

    def configured(self) -> bool:
        return self._state is not None or self._broken

    def _write_state(self, state: dict[str, Any]) -> None:
        parent = self.path.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(parent, 0o700)
        except OSError:
            pass
        fd, temp_name = tempfile.mkstemp(prefix=".auth-", suffix=".tmp", dir=str(parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(state, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temp_name, 0o600)
            os.replace(temp_name, self.path)
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        finally:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass

    @staticmethod
    def _derive(password: str, salt: bytes) -> bytes:
        return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=64)

    def setup(self, password: str) -> str:
        with self._lock:
            if self._broken:
                raise RuntimeError("The existing auth file is unreadable; restore or remove it manually before setup")
            if self.configured():
                raise RuntimeError("Authentication is already configured")
            if not isinstance(password, str) or len(password) < 12:
                raise ValueError("Choose a password with at least 12 characters")
            if len(password) > 1024:
                raise ValueError("Password must be 1024 characters or fewer")
            salt = secrets.token_bytes(16)
            state = {"version": 1, "salt": salt.hex(), "verifier": self._derive(password, salt).hex(), "created_at": int(time.time())}
            self._write_state(state)
            self._state = state
            return self._new_session()

    def login(self, password: str) -> str:
        with self._lock:
            if self._broken:
                raise RuntimeError("The existing auth file is unreadable; restore or remove it manually")
            if not self._state:
                raise RuntimeError("Authentication has not been configured")
            if not isinstance(password, str) or len(password) > 1024:
                raise PermissionError("Invalid password")
            now = time.time()
            if now < self._locked_until:
                raise PermissionError("Too many failed attempts; try again later")
            salt = bytes.fromhex(self._state["salt"])
            supplied = self._derive(password, salt)
            expected = bytes.fromhex(self._state["verifier"])
            if not hmac.compare_digest(supplied, expected):
                self._failed_login_count += 1
                if self._failed_login_count >= 5:
                    self._failed_login_count = 0
                    self._locked_until = now + 300
                    raise PermissionError("Too many failed attempts; sign-in is locked for five minutes")
                raise PermissionError("Invalid password")
            self._failed_login_count = 0
            self._locked_until = 0.0
            return self._new_session()

    def _new_session(self) -> str:
        token = secrets.token_urlsafe(32)
        self._sessions[hashlib.sha256(token.encode()).hexdigest()] = time.time() + self.session_ttl_seconds
        return token

    def validate(self, token: str | None) -> bool:
        # Fail closed until the first-run password has been configured. The
        # status/setup endpoints remain separately reachable for onboarding.
        with self._lock:
            if not self.configured() or not token:
                return False
            key = hashlib.sha256(token.encode()).hexdigest()
            expiry = self._sessions.get(key)
            if expiry is None:
                return False
            if expiry <= time.time():
                self._sessions.pop(key, None)
                return False
            return True

    def logout(self, token: str | None) -> bool:
        with self._lock:
            if not token:
                return False
            key = hashlib.sha256(token.encode()).hexdigest()
            return self._sessions.pop(key, None) is not None

    def status(self, token: str | None = None) -> dict[str, Any]:
        return {"configured": self.configured(), "authenticated": self.validate(token) if self.configured() else False,
                "broken": self._broken, "session_ttl_seconds": self.session_ttl_seconds,
                "storage": "owner-only local auth file"}
