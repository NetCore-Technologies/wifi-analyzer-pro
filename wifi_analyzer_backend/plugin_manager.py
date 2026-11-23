"""Admin-controlled, publisher-signed third-party feature plugin lifecycle.

Plugins are trusted Python code. Signatures establish publisher authenticity and
integrity; they do not sandbox code. Enabled plugins execute in the API process.
"""
from __future__ import annotations

import base64
import hashlib
import importlib
import json
import os
import re
import sqlite3
import stat
import sys
import threading
import types
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

if __package__:
    from .plugin_sdk import (
        FeaturePlugin,
        PluginValidationError,
        manifest_signing_payload,
        source_sha256,
        validate_manifest_shape,
        validate_plugin_payload,
        validate_plugin_result,
    )
else:  # Direct server.py execution from the backend directory.
    from plugin_sdk import (
        FeaturePlugin,
        PluginValidationError,
        manifest_signing_payload,
        source_sha256,
        validate_manifest_shape,
        validate_plugin_payload,
        validate_plugin_result,
    )

MAX_MANIFEST_BYTES = 16 * 1024
MAX_TRUST_FILE_BYTES = 16 * 1024
MAX_TRUSTED_KEYS = 100
MAX_PLUGIN_PACKAGES = 100
PLUGIN_DIRECTORY_NAME = re.compile(r"^[a-z][a-z0-9_-]{1,31}\.[a-z][a-z0-9_-]{1,63}$")
PLUGIN_MODULE_PREFIX = "_wifi_analyzer_external_"


class PluginManagerError(RuntimeError):
    """A bounded plugin lifecycle failure suitable for an authenticated API."""


def _default_plugin_directory() -> Path:
    configured = os.environ.get("WIFI_ANALYZER_PLUGIN_DIR")
    if configured:
        return Path(configured).expanduser()
    data_home = os.environ.get("XDG_DATA_HOME")
    root = Path(data_home).expanduser() if data_home else Path.home() / ".local" / "share"
    return root / "wifi-analyzer-pro" / "plugins"


def _default_state_database() -> Path:
    configured = os.environ.get("WIFI_ANALYZER_PLUGIN_STATE_DB")
    if configured:
        return Path(configured).expanduser()
    state_home = os.environ.get("XDG_STATE_HOME")
    root = Path(state_home).expanduser() if state_home else Path.home() / ".local" / "state"
    return root / "wifi-analyzer-pro" / "plugin-registry.sqlite3"


def _read_regular_file(
    path: Path,
    *,
    maximum_bytes: int,
    owner_only: bool = False,
) -> bytes:
    if path.is_symlink():
        raise PluginManagerError("plugin file must not be a symbolic link")
    try:
        descriptor = os.open(
            str(path),
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError:
        raise PluginManagerError("plugin file could not be opened safely") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum_bytes:
            raise PluginManagerError("plugin file type or size is not permitted")
        if os.name != "nt":
            mode = stat.S_IMODE(info.st_mode)
            if mode & 0o022:
                raise PluginManagerError("plugin file must not be writable by group or other users")
            if owner_only and mode & 0o077:
                raise PluginManagerError("plugin trust file must be accessible only by its owner")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            content = stream.read(maximum_bytes + 1)
        if len(content) > maximum_bytes:
            raise PluginManagerError("plugin file exceeds its configured size limit")
        return content
    except OSError:
        raise PluginManagerError("plugin file could not be read safely") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


class PluginManager:
    """Discover signed packages and manage explicit enable/disable/reload state."""

    def __init__(
        self,
        *,
        plugin_directory: str | os.PathLike[str] | None = None,
        state_database: str | os.PathLike[str] | None = None,
        trust_keys_file: str | os.PathLike[str] | None = None,
        trusted_keys: dict[str, bytes] | None = None,
    ):
        self.plugin_directory = Path(plugin_directory).expanduser() if plugin_directory is not None else _default_plugin_directory()
        self.state_database = Path(state_database).expanduser() if state_database is not None else _default_state_database()
        configured_trust_path = trust_keys_file or os.environ.get("WIFI_ANALYZER_PLUGIN_TRUST_KEYS_FILE", "")
        self.trust_keys_file = Path(configured_trust_path).expanduser() if configured_trust_path else None
        self._trusted_keys_override = dict(trusted_keys) if trusted_keys is not None else None
        self._lock = threading.RLock()
        self._loaded: dict[str, tuple[str, dict[str, Any], types.ModuleType]] = {}
        self._ensure_storage()

    def _ensure_storage(self) -> None:
        plugin_existed = self.plugin_directory.exists()
        self.plugin_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt":
            try:
                if not plugin_existed:
                    os.chmod(self.plugin_directory, 0o700)
            except OSError:
                pass
        if self.plugin_directory.is_symlink() or not self.plugin_directory.is_dir():
            raise PluginManagerError("plugin directory must be a regular non-symbolic-link directory")
        if os.name != "nt" and stat.S_IMODE(self.plugin_directory.stat().st_mode) & 0o022:
            raise PluginManagerError("plugin directory must not be writable by group or other users")

        self.state_database.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt":
            try:
                os.chmod(self.state_database.parent, 0o700)
            except OSError:
                pass
        if self.state_database.is_symlink() or (
            self.state_database.exists() and not self.state_database.is_file()
        ):
            raise PluginManagerError("plugin state database must be a regular non-symbolic-link file")
        with self._connection() as database:
            database.execute("""
                CREATE TABLE IF NOT EXISTS plugin_states (
                    plugin_id TEXT PRIMARY KEY,
                    enabled INTEGER NOT NULL CHECK (enabled IN (0,1)),
                    updated_at TEXT NOT NULL
                )
            """)
            database.execute(
                "CREATE INDEX IF NOT EXISTS idx_plugin_states_enabled "
                "ON plugin_states(enabled, plugin_id)"
            )

    @contextmanager
    def _connection(self):
        self.state_database.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        connection = sqlite3.connect(str(self.state_database), timeout=15)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=15000")
        connection.execute("PRAGMA journal_mode=WAL")
        try:
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
            if os.name != "nt" and self.state_database.exists():
                try:
                    os.chmod(self.state_database, 0o600)
                except OSError:
                    pass

    def _trusted_keys(self) -> dict[str, bytes]:
        if self._trusted_keys_override is not None:
            if not isinstance(self._trusted_keys_override, dict) or len(self._trusted_keys_override) > MAX_TRUSTED_KEYS:
                raise PluginManagerError("plugin trust key override is invalid")
            result = {}
            for key_id, public_key in self._trusted_keys_override.items():
                if (
                    not isinstance(key_id, str)
                    or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}", key_id)
                    or not isinstance(public_key, bytes)
                    or len(public_key) != 32
                ):
                    raise PluginManagerError("plugin trust key override is invalid")
                result[key_id] = public_key
            return result
        if self.trust_keys_file is None:
            return {}
        parent = self.trust_keys_file.parent
        if parent.is_symlink() or not parent.is_dir():
            raise PluginManagerError("plugin trust store directory must be a regular non-symbolic-link directory")
        if os.name != "nt" and stat.S_IMODE(parent.stat().st_mode) & 0o022:
            raise PluginManagerError("plugin trust store directory must not be writable by group or other users")
        try:
            raw = _read_regular_file(
                self.trust_keys_file,
                maximum_bytes=MAX_TRUST_FILE_BYTES,
                owner_only=False,
            )
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise PluginManagerError("plugin trust store is not valid UTF-8 JSON") from None
        if not isinstance(document, dict) or not 1 <= len(document) <= MAX_TRUSTED_KEYS:
            raise PluginManagerError(f"plugin trust store must contain from 1 to {MAX_TRUSTED_KEYS} publisher keys")
        result = {}
        for key_id, encoded in document.items():
            if not isinstance(key_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}", key_id):
                raise PluginManagerError("plugin trust store contains an invalid key identifier")
            if not isinstance(encoded, str) or len(encoded) > 128:
                raise PluginManagerError("plugin trust store contains an invalid public key")
            try:
                raw_key = base64.b64decode(encoded, validate=True)
            except (ValueError, TypeError):
                raise PluginManagerError("plugin trust store public keys must be base64") from None
            if len(raw_key) != 32:
                raise PluginManagerError("Ed25519 publisher public keys must contain 32 bytes")
            result[key_id] = raw_key
        return result

    def _enabled_ids(self) -> set[str]:
        with self._connection() as database:
            rows = database.execute(
                "SELECT plugin_id FROM plugin_states WHERE enabled=1"
            ).fetchall()
        return {row["plugin_id"] for row in rows}

    def _read_plugin(self, plugin_id: str) -> dict[str, Any]:
        if not isinstance(plugin_id, str) or not PLUGIN_DIRECTORY_NAME.fullmatch(plugin_id):
            raise PluginManagerError("plugin_id is invalid")
        directory = self.plugin_directory / plugin_id
        if directory.is_symlink() or not directory.is_dir():
            raise PluginManagerError("plugin directory was not found or is not a regular directory")
        if os.name != "nt" and stat.S_IMODE(directory.stat().st_mode) & 0o022:
            raise PluginManagerError("plugin directory must not be writable by group or other users")
        allowed_entries = {"manifest.json", "plugin.py", "README.md"}
        try:
            entries = {item.name for item in directory.iterdir()}
        except OSError:
            raise PluginManagerError("plugin directory could not be inspected") from None
        if not {"manifest.json", "plugin.py"}.issubset(entries) or entries - allowed_entries:
            raise PluginManagerError("plugin package must contain manifest.json and plugin.py only")
        manifest_path = directory / "manifest.json"
        source_path = directory / "plugin.py"
        try:
            manifest_raw = _read_regular_file(manifest_path, maximum_bytes=MAX_MANIFEST_BYTES)
            source = _read_regular_file(source_path, maximum_bytes=1_048_576)
            manifest = json.loads(manifest_raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise PluginManagerError("plugin manifest is not valid UTF-8 JSON") from None
        try:
            manifest = validate_manifest_shape(manifest)
        except PluginValidationError as error:
            raise PluginManagerError(str(error)) from None
        if manifest["plugin_id"] != plugin_id:
            raise PluginManagerError("plugin folder name does not match the signed plugin_id")
        if manifest["source_sha256"] != source_sha256(source):
            raise PluginManagerError("plugin source digest does not match the signed manifest")

        trusted_keys = self._trusted_keys()
        public_key = trusted_keys.get(manifest["key_id"])
        if public_key is None:
            raise PluginManagerError("plugin publisher key is not present in the local trust store")
        try:
            signature = base64.b64decode(manifest["signature"], validate=True)
            Ed25519PublicKey.from_public_bytes(public_key).verify(
                signature,
                manifest_signing_payload(manifest),
            )
        except (ValueError, InvalidSignature):
            raise PluginManagerError("plugin publisher signature verification failed") from None

        return {
            "plugin_id": manifest["plugin_id"],
            "slug": manifest["slug"],
            "name": manifest["name"],
            "version": manifest["version"],
            "api_version": manifest["api_version"],
            "publisher": manifest["publisher"],
            "key_id": manifest["key_id"],
            "description": manifest["description"],
            "parameters": dict(manifest["parameters"]),
            "permissions": list(manifest["permissions"]),
            "source": source,
            "source_sha256": manifest["source_sha256"],
            "manifest_fingerprint": hashlib.sha256(
                manifest_signing_payload(manifest) + manifest["signature"].encode("ascii")
            ).hexdigest(),
            "directory": directory,
            "manifest": manifest,
        }

    def _discover(self) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
        enabled = self._enabled_ids()
        discovered = []
        rejected = []

        def revoke(plugin_id: str) -> bool:
            was_enabled = plugin_id in enabled
            if was_enabled:
                now = datetime.now(timezone.utc).isoformat(timespec="seconds")
                with self._connection() as database:
                    database.execute(
                        "UPDATE plugin_states SET enabled=0, updated_at=? WHERE plugin_id=?",
                        (now, plugin_id),
                    )
                enabled.discard(plugin_id)
            loaded = self._loaded.pop(plugin_id, None)
            if loaded is not None:
                sys.modules.pop(loaded[2].__name__, None)
            return was_enabled

        try:
            directories = sorted(self.plugin_directory.iterdir(), key=lambda item: item.name)
        except OSError:
            return [], [{"plugin_id": "", "status": "rejected", "error_code": "plugin_directory_unavailable"}]
        package_directories = [
            item for item in directories
            if not item.name.startswith(".") and item.is_dir() and not item.is_symlink()
        ]
        if len(package_directories) > MAX_PLUGIN_PACKAGES:
            for plugin_id in list(enabled):
                revoke(plugin_id)
            return [], [{
                "plugin_id": "",
                "status": "rejected",
                "error_code": "plugin_package_limit_exceeded",
            }]
        for directory in directories:
            if directory.name.startswith("."):
                continue
            if directory.is_symlink() or not directory.is_dir():
                was_enabled = revoke(directory.name)
                rejected.append({
                    "plugin_id": directory.name[:128],
                    "status": "rejected",
                    "error_code": "plugin_entry_is_not_a_regular_directory",
                    "previously_enabled": was_enabled,
                })
                continue
            try:
                item = self._read_plugin(directory.name)
                item["enabled"] = directory.name in enabled
                discovered.append(item)
            except (PluginManagerError, OSError):
                was_enabled = revoke(directory.name)
                rejected.append({
                    "plugin_id": directory.name[:128],
                    "status": "rejected",
                    "error_code": "plugin_validation_failed",
                    "previously_enabled": was_enabled,
                })
        enabled_valid = {
            item["plugin_id"] for item in discovered if item.get("enabled") is True
        }
        for plugin_id, loaded in list(self._loaded.items()):
            if plugin_id not in enabled_valid:
                self._loaded.pop(plugin_id, None)
                sys.modules.pop(loaded[2].__name__, None)
        return discovered, rejected

    @staticmethod
    def _public(item: dict[str, Any], *, enabled: bool) -> dict[str, Any]:
        return {
            "plugin_id": item["plugin_id"],
            "slug": item["slug"],
            "name": item["name"],
            "version": item["version"],
            "api_version": item["api_version"],
            "publisher": item["publisher"],
            "key_id": item["key_id"],
            "description": item["description"],
            "parameters": dict(item["parameters"]),
            "permissions": list(item["permissions"]),
            "enabled": enabled,
            "signature_verified": True,
        }

    def list_plugins(self) -> dict:
        with self._lock:
            discovered, rejected = self._discover()
            plugins = [
                self._public(item, enabled=item["enabled"])
                for item in discovered
            ]
            plugins.extend(rejected)
            return {
                "plugin_count": len(discovered),
                "enabled_count": sum(item["enabled"] for item in discovered),
                "rejected_count": len(rejected),
                "plugins": plugins,
                "execution_model": "trusted_in_process",
            }

    def catalog(self) -> list[dict]:
        with self._lock:
            discovered, _ = self._discover()
            return [
                {
                    "id": "EXT:" + item["plugin_id"],
                    "slug": item["slug"],
                    "name": item["name"],
                    "category": "Third-party",
                    "description": item["description"],
                    "parameters": dict(item["parameters"]),
                    "permissions": list(item["permissions"]),
                    "version": item["version"],
                    "publisher": item["publisher"],
                }
                for item in discovered
                if item["enabled"]
            ]

    def get_feature(self, slug: str) -> dict[str, Any] | None:
        with self._lock:
            for item in self.catalog():
                if item["slug"] == slug:
                    return item
            return None

    def _load(self, item: dict[str, Any]) -> dict[str, Any]:
        module_digest = hashlib.sha256(item["plugin_id"].encode("utf-8")).hexdigest()[:20]
        module_name = PLUGIN_MODULE_PREFIX + module_digest
        old = self._loaded.pop(item["plugin_id"], None)
        if old is not None:
            sys.modules.pop(old[2].__name__, None)
        module = types.ModuleType(module_name)
        module.__file__ = str(item["directory"] / "plugin.py")
        module.__package__ = ""
        sys.modules[module_name] = module
        try:
            code = compile(item["source"], module.__file__, "exec", dont_inherit=True)
            exec(code, module.__dict__)
            exported = getattr(module, "PLUGIN", None)
            if not isinstance(exported, FeaturePlugin):
                # Direct server.py startup and package-mode imports can load
                # the SDK under different module names. Accept the same
                # immutable SDK contract and normalize it to this host class.
                required = ("slug", "name", "description", "parameters", "run")
                if any(not hasattr(exported, attribute) for attribute in required):
                    raise PluginManagerError("plugin.py must export a FeaturePlugin instance named PLUGIN")
                try:
                    exported = FeaturePlugin(
                        slug=exported.slug,
                        name=exported.name,
                        description=exported.description,
                        parameters=exported.parameters,
                        run=exported.run,
                    )
                except (TypeError, AttributeError):
                    raise PluginManagerError("plugin entrypoint does not implement the supported SDK contract") from None
            feature = exported.as_feature(item["manifest"])
        except Exception as error:
            sys.modules.pop(module_name, None)
            if isinstance(error, PluginManagerError):
                raise
            if isinstance(error, PluginValidationError):
                raise PluginManagerError(str(error)) from None
            raise PluginManagerError("plugin entrypoint failed validation or import") from None
        self._loaded[item["plugin_id"]] = (item["manifest_fingerprint"], feature, module)
        return feature

    def enable(self, plugin_id: str) -> dict:
        with self._lock:
            discovered, _ = self._discover()
            item = next((value for value in discovered if value["plugin_id"] == plugin_id), None)
            if item is None:
                raise PluginManagerError("signed plugin package was not found")
            self._load(item)
            now = datetime.now(timezone.utc).isoformat(timespec="seconds")
            with self._connection() as database:
                database.execute("""
                    INSERT INTO plugin_states(plugin_id, enabled, updated_at)
                    VALUES (?, 1, ?)
                    ON CONFLICT(plugin_id) DO UPDATE SET enabled=1, updated_at=excluded.updated_at
                """, (plugin_id, now))
            return self._public(item, enabled=True)

    def disable(self, plugin_id: str) -> dict:
        if not isinstance(plugin_id, str) or not PLUGIN_DIRECTORY_NAME.fullmatch(plugin_id):
            raise PluginManagerError("plugin_id is invalid")
        with self._lock:
            now = datetime.now(timezone.utc).isoformat(timespec="seconds")
            with self._connection() as database:
                database.execute("""
                    INSERT INTO plugin_states(plugin_id, enabled, updated_at)
                    VALUES (?, 0, ?)
                    ON CONFLICT(plugin_id) DO UPDATE SET enabled=0, updated_at=excluded.updated_at
                """, (plugin_id, now))
            loaded = self._loaded.pop(plugin_id, None)
            if loaded is not None:
                sys.modules.pop(loaded[2].__name__, None)
            return {"plugin_id": plugin_id, "enabled": False, "unloaded": loaded is not None}

    def reload(self, plugin_id: str) -> dict:
        with self._lock:
            if plugin_id not in self._enabled_ids():
                raise PluginManagerError("plugin must be enabled before it can be reloaded")
            discovered, _ = self._discover()
            item = next((value for value in discovered if value["plugin_id"] == plugin_id), None)
            if item is None:
                self.disable(plugin_id)
                raise PluginManagerError("enabled plugin no longer passes signature or package verification")
            self._load(item)
            return self._public(item, enabled=True)

    def run(self, slug: str, payload: object = None) -> dict:
        payload = validate_plugin_payload({} if payload is None else payload)
        with self._lock:
            discovered, _ = self._discover()
            item = next((value for value in discovered if value["slug"] == slug and value["enabled"]), None)
            if item is None:
                raise KeyError(f"Unknown or disabled feature: {slug}")
            loaded = self._loaded.get(item["plugin_id"])
            if loaded is None or loaded[0] != item["manifest_fingerprint"]:
                feature = self._load(item)
            else:
                feature = loaded[1]
            try:
                result = feature["run"](payload)
                result = validate_plugin_result(result)
            except PluginValidationError:
                raise
            except Exception:
                # Do not expose third-party exception details to the API response.
                raise PluginManagerError("third-party feature execution failed") from None
            return {
                "feature": feature["id"],
                "slug": slug,
                "result": result,
            }


PLUGIN_MANAGER = PluginManager()

__all__ = [
    "PLUGIN_MANAGER",
    "PluginManager",
    "PluginManagerError",
]
