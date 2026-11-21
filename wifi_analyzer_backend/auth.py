"""Local human identity, role and short-lived bearer-session management.

The owner account is created during first-run setup. Legacy version-1 single-password
files are migrated in place to a one-owner user directory. Password verifiers and
account metadata are stored atomically with owner-only filesystem permissions.
"""
from __future__ import annotations

import base64
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
from urllib.parse import quote
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

USERNAME = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
ROLES = {"owner", "admin", "network_admin", "analyst", "viewer"}
MAX_USERS = 100
MAX_SITE_SCOPE_IDS = 100
MFA_SETUP_TTL_SECONDS = 900
MFA_RECOVERY_CODE_COUNT = 10
SITE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

class MFARequiredError(PermissionError):
    """Raised when a password is valid but a second factor is still required."""


ROLE_PERMISSIONS = {
    "owner": frozenset({
        "users.manage", "agents.manage", "agents.read",
        "reports.manage", "reports.read",
        "webhooks.manage", "webhooks.read",
        "sites.manage", "sites.read",
        "diagnostics.run", "diagnostics.read",
    }),
    "admin": frozenset({
        "users.manage", "agents.manage", "agents.read",
        "reports.manage", "reports.read",
        "webhooks.manage", "webhooks.read",
        "sites.manage", "sites.read",
        "diagnostics.run", "diagnostics.read",
    }),
    "network_admin": frozenset({
        "agents.manage", "agents.read",
        "reports.manage", "reports.read",
        "webhooks.manage", "webhooks.read",
        "sites.manage", "sites.read",
        "diagnostics.run", "diagnostics.read",
    }),
    "analyst": frozenset({
        "agents.read", "reports.read", "webhooks.read", "sites.read",
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
        # Failed-login lockout is scoped to a username. Unknown usernames share
        # one bounded bucket so random names cannot grow the map without limit.
        self._login_failures: dict[str, tuple[int, float]] = {}
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
            "all_sites": user["all_sites"],
            "site_ids": list(user["site_ids"]),
            "mfa_enabled": bool(user.get("mfa_secret_encrypted")),
            "recovery_codes_remaining": len(user.get("mfa_recovery_hashes", [])),
        }

    @staticmethod
    def _make_user(
        username: str, password: str, role: str, *,
        all_sites: bool = True, site_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        salt = secrets.token_bytes(16)
        return {
            "id": uuid.uuid4().hex,
            "username": username,
            "role": role,
            "enabled": True,
            "salt": salt.hex(),
            "verifier": AuthManager._derive(password, salt).hex(),
            "created_at": int(time.time()),
            "all_sites": all_sites,
            "site_ids": list(site_ids or []),
            "mfa_secret_encrypted": None,
            "mfa_pending_secret_encrypted": None,
            "mfa_pending_created_at": None,
            "mfa_recovery_hashes": [],
        }

    @staticmethod
    def _normalise_site_access(all_sites: object, site_ids: object) -> tuple[bool, list[str]]:
        if not isinstance(all_sites, bool):
            raise ValueError("all_sites must be a boolean")
        if not isinstance(site_ids, list) or len(site_ids) > MAX_SITE_SCOPE_IDS:
            raise ValueError(f"site_ids must be a list containing no more than {MAX_SITE_SCOPE_IDS} site identifiers")
        cleaned = []
        for value in site_ids:
            if not isinstance(value, str):
                raise ValueError("each site_id must be a valid 1 to 128 character identifier")
            site_id = value.strip()
            if not SITE_ID.fullmatch(site_id):
                raise ValueError("each site_id must be a valid 1 to 128 character identifier")
            cleaned.append(site_id)
        if len(cleaned) != len(set(cleaned)):
            raise ValueError("site_ids must be unique")
        if all_sites and cleaned:
            raise ValueError("site_ids must be empty when all_sites is enabled")
        return all_sites, sorted(cleaned)

    def _validate_v4_state(self, state: dict[str, Any]) -> dict[str, Any]:
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
            all_sites, site_ids = self._normalise_site_access(
                user.get("all_sites"), user.get("site_ids")
            )
            if role == "owner" and (not all_sites or site_ids):
                raise ValueError("the workspace owner must retain unrestricted site access")
            active_secret = user.get("mfa_secret_encrypted")
            pending_secret = user.get("mfa_pending_secret_encrypted")
            pending_created_at = user.get("mfa_pending_created_at")
            recovery_hashes = user.get("mfa_recovery_hashes", [])
            for label, encrypted in (("active", active_secret), ("pending", pending_secret)):
                if encrypted is not None:
                    if not isinstance(encrypted, str) or not re.fullmatch(r"[A-Za-z0-9_-]{40,512}", encrypted):
                        raise ValueError(f"invalid encrypted {label} MFA secret")
                    decoded = base64.urlsafe_b64decode(encrypted + "=" * (-len(encrypted) % 4))
                    if len(decoded) < 28:
                        raise ValueError(f"invalid encrypted {label} MFA secret")
            if pending_secret is None:
                if pending_created_at is not None:
                    raise ValueError("pending MFA timestamp requires a pending secret")
            elif (
                isinstance(pending_created_at, bool)
                or not isinstance(pending_created_at, int)
                or pending_created_at < 0
            ):
                raise ValueError("invalid pending MFA timestamp")
            if not isinstance(recovery_hashes, list) or len(recovery_hashes) > MFA_RECOVERY_CODE_COUNT:
                raise ValueError("invalid MFA recovery-code collection")
            if any(
                not isinstance(item, str)
                or not re.fullmatch(r"[a-f0-9]{32}:[a-f0-9]{64}", item)
                for item in recovery_hashes
            ):
                raise ValueError("invalid MFA recovery-code verifier")
            if active_secret is None and recovery_hashes:
                raise ValueError("MFA recovery codes require an active MFA secret")
            if user_id in seen_ids or username in seen_names:
                raise ValueError("duplicate user identity")
            seen_ids.add(user_id)
            seen_names.add(username)
            owners += role == "owner"
            validated.append({
                "id": user_id, "username": username, "role": role,
                "enabled": enabled, "salt": salt.hex(),
                "verifier": verifier.hex(), "created_at": created_at,
                "all_sites": all_sites, "site_ids": site_ids,
                "mfa_secret_encrypted": active_secret,
                "mfa_pending_secret_encrypted": pending_secret,
                "mfa_pending_created_at": pending_created_at,
                "mfa_recovery_hashes": list(recovery_hashes),
            })
        if owners != 1:
            raise ValueError("the user directory must contain exactly one owner")
        return {"version": 4, "users": validated, "created_at": int(state.get("created_at", time.time()))}

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
                        "all_sites": True,
                        "site_ids": [],
                    }],
                }
                self._write_state(migrated)
                state = migrated
            if state.get("version") == 2:
                # Existing accounts retain their previous unrestricted access.
                migrated = dict(state)
                migrated["version"] = 3
                migrated["users"] = [
                    {**user, "all_sites": True, "site_ids": []}
                    for user in state.get("users", [])
                ]
                self._write_state(migrated)
                state = migrated
            if state.get("version") == 3:
                # MFA is opt-in. Existing accounts migrate without password resets,
                # role changes, or loss of their prior site access.
                migrated = dict(state)
                migrated["version"] = 4
                migrated["users"] = [
                    {
                        **user,
                        "mfa_secret_encrypted": None,
                        "mfa_pending_secret_encrypted": None,
                        "mfa_pending_created_at": None,
                        "mfa_recovery_hashes": [],
                    }
                    for user in state.get("users", [])
                ]
                self._write_state(migrated)
                state = migrated
            if state.get("version") != 4:
                raise ValueError("unsupported auth file format")
            self._state = self._validate_v4_state(state)
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
                "version": 4,
                "created_at": int(time.time()),
                "users": [self._make_user(normalised, valid_password, "owner", all_sites=True)],
            }
            self._write_state(state)
            self._state = state
            return self._new_session(state["users"][0]["id"])

    @staticmethod
    def _totp_code(secret: str, *, at: float | None = None) -> str:
        moment = time.time() if at is None else at
        key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8), casefold=True)
        counter = int(moment // 30)
        digest = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        value = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
        return f"{value % 1_000_000:06d}"

    @classmethod
    def _verify_totp(cls, secret: str, code: object, *, at: float | None = None) -> bool:
        if not isinstance(code, str) or not re.fullmatch(r"[0-9]{6}", code):
            return False
        moment = time.time() if at is None else at
        counter = int(moment // 30)
        return any(
            hmac.compare_digest(cls._totp_code(secret, at=(counter + offset) * 30), code)
            for offset in (-1, 0, 1)
        )

    @staticmethod
    def _normalise_recovery_code(code: object) -> str:
        if not isinstance(code, str):
            return ""
        value = code.replace("-", "").replace(" ", "").strip().upper()
        return value if re.fullmatch(r"[A-F0-9]{20}", value) else ""

    @classmethod
    def _make_recovery_codes(cls) -> tuple[list[str], list[str]]:
        clear_codes, stored_hashes = [], []
        for _ in range(MFA_RECOVERY_CODE_COUNT):
            raw = secrets.token_hex(10).upper()
            clear_codes.append("-".join(raw[index:index + 4] for index in range(0, 20, 4)))
            salt = secrets.token_bytes(16)
            digest = hashlib.sha256(salt + raw.encode("ascii")).hexdigest()
            stored_hashes.append(f"{salt.hex()}:{digest}")
        return clear_codes, stored_hashes

    @staticmethod
    def _encrypt_mfa_secret(user_id: str, secret: str, key_material: bytes) -> str:
        nonce = secrets.token_bytes(12)
        encrypted = AESGCM(key_material[:32]).encrypt(
            nonce, secret.encode("ascii"), user_id.encode("ascii")
        )
        return base64.urlsafe_b64encode(nonce + encrypted).decode("ascii").rstrip("=")

    @staticmethod
    def _decrypt_mfa_secret(user: dict[str, Any], encrypted: str, key_material: bytes) -> str:
        packed = base64.urlsafe_b64decode(encrypted + "=" * (-len(encrypted) % 4))
        try:
            clear = AESGCM(key_material[:32]).decrypt(
                packed[:12], packed[12:], user["id"].encode("ascii")
            )
        except InvalidTag as error:
            raise RuntimeError("The encrypted MFA secret cannot be verified; restore the account backup") from error
        return clear.decode("ascii")

    @classmethod
    def _recovery_code_index(cls, stored_hashes: list[str], code: object) -> int | None:
        normalised = cls._normalise_recovery_code(code)
        if not normalised:
            return None
        candidate = normalised.encode("ascii")
        matched = None
        for index, stored in enumerate(stored_hashes):
            salt_hex, digest = stored.split(":", 1)
            actual = hashlib.sha256(bytes.fromhex(salt_hex) + candidate).hexdigest()
            if hmac.compare_digest(actual, digest):
                matched = index
        return matched

    def begin_mfa_setup(
        self, token: str | None, password: str, *, now: float | None = None
    ) -> dict[str, str]:
        with self._lock:
            user, _ = self._session(token)
            if not user:
                raise PermissionError("Authentication required")
            if user.get("mfa_secret_encrypted"):
                raise ValueError("Multi-factor authentication is already enabled")
            valid_password = self._validate_password(password)
            material = self._derive(valid_password, bytes.fromhex(user["salt"]))
            if not hmac.compare_digest(material, bytes.fromhex(user["verifier"])):
                raise PermissionError("Password verification failed")
            secret = base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
            original = dict(user)
            user["mfa_pending_secret_encrypted"] = self._encrypt_mfa_secret(user["id"], secret, material)
            user["mfa_pending_created_at"] = int(time.time() if now is None else now)
            try:
                self._persist()
            except Exception:
                user.clear()
                user.update(original)
                raise
            issuer = quote("WiFi Analyzer Pro", safe="")
            label = quote(user["username"], safe="")
            return {
                "secret": secret,
                "otpauth_uri": (
                    f"otpauth://totp/{issuer}:{label}?secret={secret}"
                    f"&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
                ),
                "expires_in_seconds": str(MFA_SETUP_TTL_SECONDS),
            }

    def confirm_mfa_setup(
        self, token: str | None, password: str, code: object, *, now: float | None = None
    ) -> dict[str, Any]:
        with self._lock:
            user, _ = self._session(token)
            if not user:
                raise PermissionError("Authentication required")
            encrypted = user.get("mfa_pending_secret_encrypted")
            created_at = user.get("mfa_pending_created_at")
            moment = time.time() if now is None else now
            if not encrypted or created_at is None:
                raise ValueError("Start MFA setup before confirming it")
            if moment < created_at or moment - created_at > MFA_SETUP_TTL_SECONDS:
                original = dict(user)
                user["mfa_pending_secret_encrypted"] = None
                user["mfa_pending_created_at"] = None
                try:
                    self._persist()
                except Exception:
                    user.clear()
                    user.update(original)
                    raise
                raise ValueError("The MFA setup has expired; start again")
            valid_password = self._validate_password(password)
            material = self._derive(valid_password, bytes.fromhex(user["salt"]))
            if not hmac.compare_digest(material, bytes.fromhex(user["verifier"])):
                raise PermissionError("Password verification failed")
            secret = self._decrypt_mfa_secret(user, encrypted, material)
            if not self._verify_totp(secret, code, at=moment):
                raise PermissionError("The authenticator code is invalid")
            clear_codes, stored_hashes = self._make_recovery_codes()
            original = dict(user)
            user["mfa_secret_encrypted"] = encrypted
            user["mfa_pending_secret_encrypted"] = None
            user["mfa_pending_created_at"] = None
            user["mfa_recovery_hashes"] = stored_hashes
            try:
                self._persist()
            except Exception:
                user.clear()
                user.update(original)
                raise
            return {
                "mfa_enabled": True,
                "recovery_codes": clear_codes,
                "recovery_codes_remaining": len(clear_codes),
            }

    def disable_mfa(
        self, token: str | None, password: str, code: object, *, now: float | None = None
    ) -> dict[str, bool]:
        with self._lock:
            user, _ = self._session(token)
            if not user:
                raise PermissionError("Authentication required")
            encrypted = user.get("mfa_secret_encrypted")
            if not encrypted:
                raise ValueError("Multi-factor authentication is not enabled")
            valid_password = self._validate_password(password)
            material = self._derive(valid_password, bytes.fromhex(user["salt"]))
            if not hmac.compare_digest(material, bytes.fromhex(user["verifier"])):
                raise PermissionError("Password verification failed")
            secret = self._decrypt_mfa_secret(user, encrypted, material)
            valid_code = self._verify_totp(secret, code, at=now)
            recovery_index = None if valid_code else self._recovery_code_index(
                user.get("mfa_recovery_hashes", []), code
            )
            if not valid_code and recovery_index is None:
                raise PermissionError("A valid authenticator or unused recovery code is required")
            original = dict(user)
            user["mfa_secret_encrypted"] = None
            user["mfa_pending_secret_encrypted"] = None
            user["mfa_pending_created_at"] = None
            user["mfa_recovery_hashes"] = []
            try:
                self._persist()
            except Exception:
                user.clear()
                user.update(original)
                raise
            return {"mfa_enabled": False}

    def login(
        self, password: str, username: str = "admin", *, code: object = None, now: float | None = None
    ) -> str:
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
            moment = time.time() if now is None else now
            user = self._find_user(normalised) if normalised else None
            attempt_key = normalised if user is not None else "__unknown__"
            failed_count, locked_until = self._login_failures.get(attempt_key, (0, 0.0))
            if moment < locked_until:
                raise PermissionError("Too many failed attempts; try again later")
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
                failed_count += 1
                if failed_count >= 5:
                    self._login_failures[attempt_key] = (0, moment + 300)
                    raise PermissionError("Too many failed attempts; sign-in is locked for five minutes")
                self._login_failures[attempt_key] = (failed_count, 0.0)
                raise PermissionError("Invalid username or password")
            encrypted = user.get("mfa_secret_encrypted")
            if encrypted:
                if not isinstance(code, str) or not code.strip():
                    raise MFARequiredError("A two-factor authenticator or recovery code is required")
                secret = self._decrypt_mfa_secret(user, encrypted, supplied)
                valid_code = self._verify_totp(secret, code, at=moment)
                recovery_index = None if valid_code else self._recovery_code_index(
                    user.get("mfa_recovery_hashes", []), code
                )
                if not valid_code and recovery_index is None:
                    failed_count += 1
                    if failed_count >= 5:
                        self._login_failures[attempt_key] = (0, moment + 300)
                        raise PermissionError("Too many failed attempts; sign-in is locked for five minutes")
                    self._login_failures[attempt_key] = (failed_count, 0.0)
                    raise PermissionError("Invalid username, password or two-factor code")
                if recovery_index is not None:
                    original_hashes = list(user["mfa_recovery_hashes"])
                    user["mfa_recovery_hashes"] = [
                        item for index, item in enumerate(original_hashes) if index != recovery_index
                    ]
                    try:
                        self._persist()
                    except Exception:
                        user["mfa_recovery_hashes"] = original_hashes
                        raise
            self._login_failures.pop(attempt_key, None)
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

    def site_access(self, token: str | None) -> dict[str, Any] | None:
        with self._lock:
            user, _ = self._session(token)
            if not user:
                return None
            return {"all_sites": user["all_sites"], "site_ids": list(user["site_ids"])}

    def can_access_site(self, token: str | None, site_id: str) -> bool:
        if not isinstance(site_id, str) or not SITE_ID.fullmatch(site_id.strip()):
            return False
        with self._lock:
            user, _ = self._session(token)
            return bool(user and (user["all_sites"] or site_id.strip() in user["site_ids"]))

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

    def create_user(
        self, actor_token: str | None, username: object, password: object, role: object, *,
        all_sites: object = False, site_ids: object = None,
    ) -> dict[str, Any]:
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
            all_sites, site_ids = self._normalise_site_access(
                all_sites, [] if site_ids is None else site_ids
            )
            if not actor["all_sites"]:
                if all_sites or not set(site_ids).issubset(actor["site_ids"]):
                    raise PermissionError("You cannot grant site access outside your own assigned scope")
            if len(self._users()) >= MAX_USERS:
                raise ValueError(f"The local directory is limited to {MAX_USERS} users")
            if self._find_user(normalised):
                raise ValueError("A user with that username already exists")
            user = self._make_user(
                normalised, valid_password, role,
                all_sites=all_sites, site_ids=site_ids,
            )
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
        all_sites: object = None,
        site_ids: object = None,
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
            if all_sites is not None or site_ids is not None:
                next_all_sites = target["all_sites"] if all_sites is None else all_sites
                next_site_ids = target["site_ids"] if site_ids is None else site_ids
                if all_sites is True and site_ids is None:
                    next_site_ids = []
                next_all_sites, next_site_ids = self._normalise_site_access(
                    next_all_sites, next_site_ids
                )
                if not actor["all_sites"]:
                    if next_all_sites or not set(next_site_ids).issubset(actor["site_ids"]):
                        raise PermissionError("You cannot grant site access outside your own assigned scope")
                updates["all_sites"] = next_all_sites
                updates["site_ids"] = next_site_ids
            new_salt = None
            if password is not None:
                valid_password = self._validate_password(password)
                new_salt = secrets.token_bytes(16)
                updates["salt"] = new_salt.hex()
                updates["verifier"] = self._derive(valid_password, new_salt).hex()
                # MFA encryption is password-derived: a password reset clears the
                # second factor and unused recovery codes, requiring fresh enrolment.
                updates["mfa_secret_encrypted"] = None
                updates["mfa_pending_secret_encrypted"] = None
                updates["mfa_pending_created_at"] = None
                updates["mfa_recovery_hashes"] = []
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
