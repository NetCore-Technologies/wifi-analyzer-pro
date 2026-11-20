"""Local human identity, role and short-lived bearer-session management.

The owner account is created during first-run setup. Legacy version-1 single-password
files are migrated in place to a one-owner user directory. Password verifiers and
account metadata are stored atomically with owner-only filesystem permissions.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any

USERNAME = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
ROLES = {"owner", "admin", "network_admin", "analyst", "viewer"}
MAX_USERS = 100

ROLE_PERMISSIONS = {
    "owner": frozenset({
        "users.manage", "agents.manage", "agents.read",
        "reports.manage", "reports.read",
        "sites.manage", "sites.read",
        "diagnostics.run", "diagnostics.read",
    }),
    "admin": frozenset({
        "users.manage", "agents.manage", "agents.read",
        "reports.manage", "reports.read",
        "sites.manage", "sites.read",
        "diagnostics.run", "diagnostics.read",
    }),
    "network_admin": frozenset({
        "agents.manage", "agents.read",
        "reports.manage", "reports.read",
        "sites.manage", "sites.read",
        "diagnostics.run", "diagnostics.read",
    }),
    "analyst": frozenset({
        "agents.read", "reports.read", "sites.read",
        "diagnostics.run", "diagnostics.read",
    }),
    "viewer": frozenset({
        "agents.read", "reports.read", "sites.read",
        "diagnostics.read",
    }),
}


class AuthManager:
    """Local user directory and process-local sessions."""

    def __init__(self, path: str | None = None, session_ttl_seconds: int = 12 * 60 * 60):
        configured = path or os.environ.get("WIFI_ANALYZER_AUTH_FILE")
        self.path = Path(configured).expanduser() if configured else Path.home() / ".config" / "wifi-analyzer-pro" / "auth.json"
        self.session_ttl_seconds = max(300, int(session_ttl_seconds))
        self._lock = threading.RLock()
        self._sessions: dict[str, Any] = {}
        self._failed_login_count = 0
        self._locked_until = 0.0
        self._state: dict[str, Any] | None = None
        self._broken = False
        self._load()

    @staticmethod
    def _normalise_username(value: object) -> str:
        if not isinstance(value, str):
            raise ValueError("Username must contain 3 to 64 letters, numbers, dots, underscores or hyphens")
        username = value.strip().lower()
        if not USERNAME.fullmatch(username):
            raise ValueError("Username must contain 3 to 64 letters, numbers, dots, underscores or hyphens")
        return username

    @staticmethod
    def _validate_password(password: object) -> str:
        if not isinstance(password, str) or len(password) < 12:
            raise ValueError("Choose a password with at least 12 characters")
        if len(password) > 1024:
            raise ValueError("Password must be 1024 characters or fewer")
        return password

    @staticmethod
    def _derive(password: str, salt: bytes) -> bytes:
        return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=64)

    @staticmethod
    def _safe_user(user: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "enabled": user["enabled"],
            "created_at": user["created_at"],
        }

    @staticmethod
    def _make_user(username: str, password: str, role: str) -> dict[str, Any]:
        salt = secrets.token_bytes(16)
        return {
            "id": uuid.uuid4().hex,
            "username": username,
            "role": role,
            "enabled": True,
            "salt": salt.hex(),
            "verifier": AuthManager._derive(password, salt).hex(),
            "created_at": int(time.time()),
        }

    def _validate_v2_state(self, state: dict[str, Any]) -> dict[str, Any]:
        users = state.get("users")
        if not isinstance(users, list) or not 1 <= len(users) <= MAX_USERS:
            raise ValueError("invalid user collection")
        seen_ids: set[str] = set()
        seen_names: set[str] = set()
        owners = 0
        validated = []
        for user in users:
            if not isinstance(user, dict):
                raise ValueError("invalid user record")
            user_id = user.get("id")
            if not isinstance(user_id, str) or not re.fullmatch(r"[a-f0-9]{32}", user_id):
                raise ValueError("invalid user identifier")
            username = self._normalise_username(user.get("username"))
            role = user.get("role")
            enabled = user.get("enabled")
            if role not in ROLES or not isinstance(enabled, bool):
                raise ValueError("invalid user role or state")
            salt = bytes.fromhex(user.get("salt", ""))
            verifier = bytes.fromhex(user.get("verifier", ""))
            if len(salt) != 16 or len(verifier) != 64:
                raise ValueError("invalid verifier material")
            created_at = user.get("created_at")
            if isinstance(created_at, bool) or not isinstance(created_at, int) or created_at < 0:
                raise ValueError("invalid user creation timestamp")
            if user_id in seen_ids or username in seen_names:
                raise ValueError("duplicate user identity")
            seen_ids.add(user_id)
            seen_names.add(username)
            owners += role == "owner"
            validated.append({
                "id": user_id, "username": username, "role": role,
                "enabled": enabled, "salt": salt.hex(),
                "verifier": verifier.hex(), "created_at": created_at,
            })
        if owners != 1:
            raise ValueError("the user directory must contain exactly one owner")
        return {"version": 2, "users": validated, "created_at": int(state.get("created_at", time.time()))}

    def _load(self) -> None:
        if not self.path.exists():
            self._state = None
            return
        try:
            state = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(state, dict):
                raise ValueError("invalid auth file")
            if state.get("version") == 1:
                # Preserve the existing credential as the owner; do not reset or
                # weaken authentication during the single-password migration.
                salt = bytes.fromhex(state["salt"])
                verifier = bytes.fromhex(state["verifier"])
                if len(salt) != 16 or len(verifier) != 64:
                    raise ValueError("invalid legacy verifier material")
                migrated = {
                    "version": 2,
                    "created_at": int(state.get("created_at", time.time())),
                    "users": [{
                        "id": uuid.uuid4().hex,
                        "username": "admin",
                        "role": "owner",
                        "enabled": True,
                        "salt": salt.hex(),
                        "verifier": verifier.hex(),
                        "created_at": int(state.get("created_at", time.time())),
                    }],
                }
                self._write_state(migrated)
                state = migrated
            if state.get("version") != 2:
                raise ValueError("unsupported auth file format")
            self._state = self._validate_v2_state(state)
            if os.name != "nt":
                os.chmod(self.path, 0o600)
        except Exception:
            # A damaged existing credential file never becomes an open setup screen.
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
                json.dump(state, stream, ensure_ascii=True, sort_keys=True)
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

    def _persist(self) -> None:
        if self._state is None:
            raise RuntimeError("Authentication is not configured")
        self._write_state(self._state)

    def _users(self) -> list[dict[str, Any]]:
        return self._state["users"] if self._state else []

    def _find_user(self, username: str) -> dict[str, Any] | None:
        return next((user for user in self._users() if user["username"] == username), None)

    def _find_user_id(self, user_id: str) -> dict[str, Any] | None:
        return next((user for user in self._users() if user["id"] == user_id), None)

    def _new_session(self, user_id: str) -> str:
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode()).hexdigest()
        self._sessions[digest] = {
            "expires_at": time.time() + self.session_ttl_seconds,
            "user_id": user_id,
        }
        return token

    def setup(self, password: str, username: str = "admin") -> str:
        with self._lock:
            if self._broken:
                raise RuntimeError("The existing auth file is unreadable; restore or remove it manually before setup")
            if self.configured():
                raise RuntimeError("Authentication is already configured")
            normalised = self._normalise_username(username)
            valid_password = self._validate_password(password)
            state = {
                "version": 2,
                "created_at": int(time.time()),
                "users": [self._make_user(normalised, valid_password, "owner")],
            }
            self._write_state(state)
            self._state = state
            return self._new_session(state["users"][0]["id"])

    def login(self, password: str, username: str = "admin") -> str:
        with self._lock:
            if self._broken:
                raise RuntimeError("The existing auth file is unreadable; restore or remove it manually")
            if not self._state:
                raise RuntimeError("Authentication has not been configured")
            if not isinstance(password, str) or len(password) > 1024:
                raise PermissionError("Invalid username or password")
            try:
                normalised = self._normalise_username(username)
            except ValueError:
                normalised = ""
            now = time.time()
            if now < self._locked_until:
                raise PermissionError("Too many failed attempts; try again later")
            user = self._find_user(normalised) if normalised else None
            if user is None:
                supplied = self._derive(password, b"\x00" * 16)
                hmac.compare_digest(supplied, b"\x00" * 64)
            else:
                salt = bytes.fromhex(user["salt"])
                supplied = self._derive(password, salt)
                expected = bytes.fromhex(user["verifier"])
                if not hmac.compare_digest(supplied, expected) or not user["enabled"]:
                    user = None
            if user is None:
                self._failed_login_count += 1
                if self._failed_login_count >= 5:
                    self._failed_login_count = 0
                    self._locked_until = now + 300
                    raise PermissionError("Too many failed attempts; sign-in is locked for five minutes")
                raise PermissionError("Invalid username or password")
            self._failed_login_count = 0
            self._locked_until = 0.0
            return self._new_session(user["id"])

    def _session(self, token: str | None) -> tuple[dict[str, Any] | None, str | None]:
        if not token or not self._state:
            return None, None
        key = hashlib.sha256(token.encode()).hexdigest()
        record = self._sessions.get(key)
        if record is None:
            return None, key
        if isinstance(record, (int, float)):
            # Backward-compatible support for in-memory sessions created by v1 tests.
            expiry, user_id = float(record), next((u["id"] for u in self._users() if u["role"] == "owner"), None)
        elif isinstance(record, dict):
            expiry, user_id = record.get("expires_at"), record.get("user_id")
        else:
            self._sessions.pop(key, None)
            return None, key
        if isinstance(expiry, bool) or not isinstance(expiry, (int, float)) or expiry <= time.time():
            self._sessions.pop(key, None)
            return None, key
        user = self._find_user_id(user_id) if isinstance(user_id, str) else None
        if user is None or not user["enabled"]:
            self._sessions.pop(key, None)
            return None, key
        return user, key

    def identity(self, token: str | None) -> dict[str, Any] | None:
        with self._lock:
            user, _ = self._session(token)
            return self._safe_user(user) if user else None

    def validate(self, token: str | None) -> bool:
        with self._lock:
            user, _ = self._session(token)
            return user is not None

    def has_permission(self, token: str | None, permission: str) -> bool:
        if permission not in {
            "users.manage", "agents.manage", "agents.read",
            "reports.manage", "reports.read", "sites.manage", "sites.read",
            "diagnostics.run", "diagnostics.read",
        }:
            return False
        with self._lock:
            user, _ = self._session(token)
            return bool(user and permission in ROLE_PERMISSIONS[user["role"]])

    def list_users(self, actor_token: str | None) -> list[dict[str, Any]]:
        with self._lock:
            actor, _ = self._session(actor_token)
            if not actor or "users.manage" not in ROLE_PERMISSIONS[actor["role"]]:
                raise PermissionError("User-management permission required")
            return [self._safe_user(user) for user in sorted(self._users(), key=lambda item: item["username"])]

    def create_user(self, actor_token: str | None, username: object, password: object, role: object) -> dict[str, Any]:
        with self._lock:
            actor, _ = self._session(actor_token)
            if not actor or "users.manage" not in ROLE_PERMISSIONS[actor["role"]]:
                raise PermissionError("User-management permission required")
            normalised = self._normalise_username(username)
            valid_password = self._validate_password(password)
            if not isinstance(role, str) or role not in {"admin", "network_admin", "analyst", "viewer"}:
                raise ValueError("role must be admin, network_admin, analyst or viewer")
            if actor["role"] != "owner" and role == "admin":
                raise PermissionError("Only the owner can create administrators")
            if len(self._users()) >= MAX_USERS:
                raise ValueError(f"The local directory is limited to {MAX_USERS} users")
            if self._find_user(normalised):
                raise ValueError("A user with that username already exists")
            user = self._make_user(normalised, valid_password, role)
            self._state["users"].append(user)
            try:
                self._persist()
            except Exception:
                self._state["users"].remove(user)
                raise
            return self._safe_user(user)

    def update_user(
        self,
        actor_token: str | None,
        user_id: str,
        *,
        role: object = None,
        enabled: object = None,
        password: object = None,
    ) -> dict[str, Any]:
        with self._lock:
            actor, _ = self._session(actor_token)
            if not actor or "users.manage" not in ROLE_PERMISSIONS[actor["role"]]:
                raise PermissionError("User-management permission required")
            target = self._find_user_id(user_id) if isinstance(user_id, str) else None
            if target is None:
                raise ValueError("User not found")
            if target["role"] == "owner" and not (
                actor["role"] == "owner" and actor["id"] == target["id"]
                and role is None and enabled is None and password is not None
            ):
                raise PermissionError("The workspace owner account cannot be changed here")
            if actor["role"] != "owner" and target["role"] == "admin":
                raise PermissionError("Only the owner can manage administrators")
            updates = {}
            if role is not None:
                if not isinstance(role, str) or role not in {"admin", "network_admin", "analyst", "viewer"}:
                    raise ValueError("role must be admin, network_admin, analyst or viewer")
                if actor["role"] != "owner" and role == "admin":
                    raise PermissionError("Only the owner can assign administrator role")
                updates["role"] = role
            if enabled is not None:
                if not isinstance(enabled, bool):
                    raise ValueError("enabled must be a boolean")
                updates["enabled"] = enabled
            new_salt = None
            if password is not None:
                valid_password = self._validate_password(password)
                new_salt = secrets.token_bytes(16)
                updates["salt"] = new_salt.hex()
                updates["verifier"] = self._derive(valid_password, new_salt).hex()
            if not updates:
                raise ValueError("At least one of role, enabled or password must be supplied")
            original = dict(target)
            target.update(updates)
            try:
                self._persist()
            except Exception:
                target.clear()
                target.update(original)
                raise
            if updates.get("enabled") is False or new_salt is not None:
                for digest, record in list(self._sessions.items()):
                    if isinstance(record, dict) and record.get("user_id") == target["id"]:
                        self._sessions.pop(digest, None)
            return self._safe_user(target)

    def status(self, token: str | None = None) -> dict[str, Any]:
        identity = self.identity(token) if self.configured() else None
        return {
            "configured": self.configured(),
            "authenticated": identity is not None,
            "identity": identity,
            "broken": self._broken,
            "session_ttl_seconds": self.session_ttl_seconds,
            "storage": "owner-only local user directory",
        }

    def logout(self, token: str | None) -> bool:
        with self._lock:
            if not token:
                return False
            key = hashlib.sha256(token.encode()).hexdigest()
            return self._sessions.pop(key, None) is not None
