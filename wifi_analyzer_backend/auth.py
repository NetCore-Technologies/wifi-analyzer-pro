"""Local multi-user password and short-lived bearer-session management.

The auth database is kept outside the repository with owner-only permissions.
Version-1 single-password databases are migrated to a named administrator without
changing the existing password. Session tokens remain process-local and are never
stored in the auth database.
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
from pathlib import Path
from typing import Any


USERNAME = re.compile(r"^[a-z][a-z0-9._-]{1,31}$")
SITE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
ROLES = {"admin", "viewer"}
MAX_USERS = 256
MAX_SITES_PER_USER = 128
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 1024


class AuthManager:
    def __init__(self, path: str | None = None, session_ttl_seconds: int = 12 * 60 * 60):
        configured = path or os.environ.get("WIFI_ANALYZER_AUTH_FILE")
        self.path = (
            Path(configured).expanduser()
            if configured
            else Path.home() / ".config" / "wifi-analyzer-pro" / "auth.json"
        )
        self.session_ttl_seconds = max(300, int(session_ttl_seconds))
        self._lock = threading.RLock()
        self._sessions: dict[str, dict[str, Any]] = {}
        self._failed_login_count = 0
        self._locked_until = 0.0
        self._state: dict[str, Any] | None = None
        self._broken = False
        self._load()

    @staticmethod
    def _username(value: object) -> str:
        if not isinstance(value, str):
            raise ValueError("username must be a string")
        username = value.strip().lower()
        if not USERNAME.fullmatch(username):
            raise ValueError("username must be 2 to 32 lowercase letters, numbers, dots, underscores or hyphens and start with a letter")
        return username

    @staticmethod
    def _password(password: object, *, creating: bool = False) -> str:
        if not isinstance(password, str):
            raise ValueError("password must be a string")
        if len(password) > MAX_PASSWORD_LENGTH:
            raise ValueError(f"Password must be {MAX_PASSWORD_LENGTH} characters or fewer")
        if creating and len(password) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"Choose a password with at least {MIN_PASSWORD_LENGTH} characters")
        return password

    @staticmethod
    def _site_ids(value: object, *, role: str) -> list[str]:
        if role == "admin":
            if value not in (None, ["*"], "*"):
                raise ValueError("administrator accounts always have access to all sites")
            return ["*"]
        if value is None:
            return []
        if not isinstance(value, list) or len(value) > MAX_SITES_PER_USER:
            raise ValueError(f"site_ids must be a list of no more than {MAX_SITES_PER_USER} site identifiers")
        result = []
        for site_id in value:
            if not isinstance(site_id, str) or not SITE_ID.fullmatch(site_id):
                raise ValueError("site_ids contains an invalid site identifier")
            if site_id not in result:
                result.append(site_id)
        return sorted(result)

    @staticmethod
    def _derive(password: str, salt: bytes) -> bytes:
        return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=64)

    @classmethod
    def _new_user_record(
        cls,
        password: str,
        role: str,
        site_ids: object = None,
        *,
        created_at: int | None = None,
    ) -> dict[str, Any]:
        password = cls._password(password, creating=True)
        if role not in ROLES:
            raise ValueError("role must be admin or viewer")
        salt = secrets.token_bytes(16)
        return {
            "salt": salt.hex(),
            "verifier": cls._derive(password, salt).hex(),
            "role": role,
            "site_ids": cls._site_ids(site_ids, role=role),
            "enabled": True,
            "created_at": int(time.time()) if created_at is None else int(created_at),
        }

    @staticmethod
    def _validate_user_record(username: str, record: object) -> dict[str, Any]:
        if not USERNAME.fullmatch(username) or not isinstance(record, dict):
            raise ValueError("invalid auth user record")
        salt = bytes.fromhex(record["salt"])
        verifier = bytes.fromhex(record["verifier"])
        role = record["role"]
        if len(salt) != 16 or len(verifier) != 64 or role not in ROLES:
            raise ValueError("invalid auth verifier or role")
        enabled = record.get("enabled")
        created_at = record.get("created_at")
        if not isinstance(enabled, bool) or isinstance(created_at, bool) or not isinstance(created_at, int):
            raise ValueError("invalid auth user metadata")
        site_ids = AuthManager._site_ids(record.get("site_ids"), role=role)
        if role == "viewer" and record.get("site_ids") == "*":
            raise ValueError("viewer accounts cannot have wildcard site access")
        return {
            "salt": salt.hex(),
            "verifier": verifier.hex(),
            "role": role,
            "site_ids": site_ids,
            "enabled": enabled,
            "created_at": created_at,
        }

    def _load(self) -> None:
        if not self.path.exists():
            self._state = None
            return
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(loaded, dict):
                raise ValueError("auth state must be an object")
            version = loaded.get("version")
            migrated = False
            if version == 1:
                # Preserve the existing single administrator's verifier and password.
                old = self._validate_user_record(
                    "admin",
                    {
                        "salt": loaded["salt"],
                        "verifier": loaded["verifier"],
                        "role": "admin",
                        "site_ids": ["*"],
                        "enabled": True,
                        "created_at": loaded.get("created_at", int(time.time())),
                    },
                )
                state = {
                    "version": 2,
                    "created_at": int(loaded.get("created_at", time.time())),
                    "users": {"admin": old},
                }
                migrated = True
            elif version == 2:
                users = loaded.get("users")
                if not isinstance(users, dict) or not users or len(users) > MAX_USERS:
                    raise ValueError("invalid auth user collection")
                state = {
                    "version": 2,
                    "created_at": int(loaded.get("created_at", time.time())),
                    "users": {
                        self._username(name): self._validate_user_record(self._username(name), record)
                        for name, record in users.items()
                    },
                }
            else:
                raise ValueError("unsupported auth file format")

            if not any(
                record["role"] == "admin" and record["enabled"]
                for record in state["users"].values()
            ):
                raise ValueError("auth database must retain an enabled administrator")
            self._state = state
            if migrated:
                self._write_state(state)
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
                json.dump(state, stream, sort_keys=True, separators=(",", ":"))
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

    def _persist(self, state: dict[str, Any]) -> None:
        self._write_state(state)
        self._state = state

    def setup(self, password: str, username: str = "admin") -> str:
        with self._lock:
            if self._broken:
                raise RuntimeError("The existing auth file is unreadable; restore or remove it manually before setup")
            if self.configured():
                raise RuntimeError("Authentication is already configured")
            username = self._username(username)
            user = self._new_user_record(password, "admin", ["*"])
            state = {
                "version": 2,
                "created_at": int(time.time()),
                "users": {username: user},
            }
            self._persist(state)
            return self._new_session(username)

    def login(self, password: str, username: str = "admin") -> str:
        with self._lock:
            if self._broken:
                raise RuntimeError("The existing auth file is unreadable; restore or remove it manually")
            if not self._state:
                raise RuntimeError("Authentication has not been configured")
            password = self._password(password)
            try:
                username = self._username(username)
            except ValueError:
                username = ""
            now = time.time()
            if now < self._locked_until:
                raise PermissionError("Too many failed attempts; try again later")
            record = self._state["users"].get(username)
            if record is None or not record["enabled"]:
                # Perform a fixed-cost derivation for unknown/disabled usernames.
                self._derive(password, b"wifi-analyzer-dummy-salt")
                self._failed_login_count += 1
                if self._failed_login_count >= 5:
                    self._failed_login_count = 0
                    self._locked_until = now + 300
                    raise PermissionError("Too many failed attempts; sign-in is locked for five minutes")
                raise PermissionError("Invalid username or password")
            salt = bytes.fromhex(record["salt"])
            supplied = self._derive(password, salt)
            expected = bytes.fromhex(record["verifier"])
            if not hmac.compare_digest(supplied, expected):
                self._failed_login_count += 1
                if self._failed_login_count >= 5:
                    self._failed_login_count = 0
                    self._locked_until = now + 300
                    raise PermissionError("Too many failed attempts; sign-in is locked for five minutes")
                raise PermissionError("Invalid username or password")
            self._failed_login_count = 0
            self._locked_until = 0.0
            return self._new_session(username)

    def _new_session(self, username: str) -> str:
        token = secrets.token_urlsafe(32)
        self._sessions[hashlib.sha256(token.encode()).hexdigest()] = {
            "expires_at": time.time() + self.session_ttl_seconds,
            "username": username,
        }
        return token

    def session_info(self, token: str | None) -> dict[str, Any] | None:
        with self._lock:
            if not self.configured() or not token or not self._state:
                return None
            key = hashlib.sha256(token.encode()).hexdigest()
            session = self._sessions.get(key)
            if session is None:
                return None
            if session["expires_at"] <= time.time():
                self._sessions.pop(key, None)
                return None
            record = self._state["users"].get(session["username"])
            if record is None or not record["enabled"]:
                self._sessions.pop(key, None)
                return None
            return {
                "username": session["username"],
                "role": record["role"],
                "site_ids": list(record["site_ids"]),
                "expires_at": int(session["expires_at"]),
            }

    def validate(self, token: str | None) -> bool:
        return self.session_info(token) is not None

    def logout(self, token: str | None) -> bool:
        with self._lock:
            if not token:
                return False
            key = hashlib.sha256(token.encode()).hexdigest()
            return self._sessions.pop(key, None) is not None

    def list_users(self) -> list[dict[str, Any]]:
        with self._lock:
            if not self._state:
                return []
            return [
                {
                    "username": username,
                    "role": record["role"],
                    "site_ids": list(record["site_ids"]),
                    "enabled": record["enabled"],
                    "created_at": record["created_at"],
                    "active_sessions": sum(
                        1 for session in self._sessions.values()
                        if session["username"] == username and session["expires_at"] > time.time()
                    ),
                }
                for username, record in sorted(self._state["users"].items())
            ]

    def create_user(
        self,
        username: str,
        password: str,
        role: str = "viewer",
        site_ids: object = None,
    ) -> dict[str, Any]:
        username = self._username(username)
        if role not in ROLES:
            raise ValueError("role must be admin or viewer")
        record = self._new_user_record(password, role, site_ids)
        with self._lock:
            if not self._state:
                raise RuntimeError("Authentication has not been configured")
            if username in self._state["users"]:
                raise ValueError("username already exists")
            if len(self._state["users"]) >= MAX_USERS:
                raise ValueError(f"At most {MAX_USERS} local users may be configured")
            state = {**self._state, "users": {**self._state["users"], username: record}}
            self._persist(state)
            return next(user for user in self.list_users() if user["username"] == username)

    def update_user(
        self,
        username: str,
        *,
        role: str | None = None,
        site_ids: object = None,
        update_sites: bool = False,
        enabled: bool | None = None,
    ) -> dict[str, Any]:
        username = self._username(username)
        with self._lock:
            if not self._state or username not in self._state["users"]:
                raise KeyError("user not found")
            current = self._state["users"][username]
            new_role = current["role"] if role is None else role
            if new_role not in ROLES:
                raise ValueError("role must be admin or viewer")
            new_sites = (
                self._site_ids(site_ids, role=new_role)
                if update_sites or new_role != current["role"]
                else list(current["site_ids"])
            )
            new_enabled = current["enabled"] if enabled is None else enabled
            if not isinstance(new_enabled, bool):
                raise ValueError("enabled must be a boolean")
            changed = {
                **current,
                "role": new_role,
                "site_ids": new_sites,
                "enabled": new_enabled,
            }
            users = {**self._state["users"], username: changed}
            if not any(
                user["role"] == "admin" and user["enabled"]
                for user in users.values()
            ):
                raise ValueError("at least one enabled administrator must remain")
            state = {**self._state, "users": users}
            self._persist(state)
            if not new_enabled or new_role != current["role"] or new_sites != current["site_ids"]:
                self._revoke_user_sessions(username)
            return next(user for user in self.list_users() if user["username"] == username)

    def reset_password(self, username: str, password: str) -> None:
        username = self._username(username)
        with self._lock:
            if not self._state or username not in self._state["users"]:
                raise KeyError("user not found")
            old = self._state["users"][username]
            fresh = self._new_user_record(
                password,
                old["role"],
                old["site_ids"],
                created_at=old["created_at"],
            )
            fresh["enabled"] = old["enabled"]
            self._persist({**self._state, "users": {**self._state["users"], username: fresh}})
            self._revoke_user_sessions(username)

    def delete_user(self, username: str) -> None:
        username = self._username(username)
        with self._lock:
            if not self._state or username not in self._state["users"]:
                raise KeyError("user not found")
            users = dict(self._state["users"])
            users.pop(username)
            if not any(user["role"] == "admin" and user["enabled"] for user in users.values()):
                raise ValueError("at least one enabled administrator must remain")
            self._persist({**self._state, "users": users})
            self._revoke_user_sessions(username)

    def _revoke_user_sessions(self, username: str) -> None:
        self._sessions = {
            token_hash: session
            for token_hash, session in self._sessions.items()
            if session["username"] != username
        }

    def status(self, token: str | None = None) -> dict[str, Any]:
        info = self.session_info(token)
        return {
            "configured": self.configured(),
            "authenticated": info is not None,
            "broken": self._broken,
            "username": info["username"] if info else None,
            "role": info["role"] if info else None,
            "site_ids": info["site_ids"] if info else [],
            "session_expires_at": info["expires_at"] if info else None,
            "session_ttl_seconds": self.session_ttl_seconds,
            "storage": "owner-only local auth file",
        }
