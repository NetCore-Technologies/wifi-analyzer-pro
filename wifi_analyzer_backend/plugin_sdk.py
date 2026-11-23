"""Developer SDK primitives for signed WiFi Analyzer Pro feature plugins.

Third-party Python plugins are trusted code and execute inside the API process.
The signature verifies publisher identity/integrity; it is not a Python sandbox.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Callable

PLUGIN_API_VERSION = "1.0"
PLUGIN_MANIFEST_SCHEMA = 1
PLUGIN_SOURCE_LIMIT = 1_048_576
PLUGIN_INPUT_LIMIT = 1_048_576
PLUGIN_OUTPUT_LIMIT = 1_048_576

PLUGIN_ID = re.compile(r"^[a-z][a-z0-9_-]{1,31}\.[a-z][a-z0-9_-]{1,63}$")
PLUGIN_SLUG = re.compile(r"^ext_[a-z][a-z0-9_]{1,31}_[a-z][a-z0-9_]{1,63}$")
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
PERMISSIONS = frozenset({
    "diagnostics.read",
    "diagnostics.run",
    "sites.read",
    "agents.read",
    "reports.read",
    "webhooks.read",
})
MANIFEST_FIELDS = frozenset({
    "schema_version",
    "plugin_id",
    "slug",
    "name",
    "version",
    "api_version",
    "publisher",
    "key_id",
    "entrypoint",
    "source_sha256",
    "description",
    "parameters",
    "permissions",
    "signature",
})


class PluginValidationError(ValueError):
    """A plugin package or SDK contract is invalid."""


def canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise PluginValidationError("value must be finite JSON-compatible data") from error


def source_sha256(source: bytes) -> str:
    if not isinstance(source, bytes) or len(source) > PLUGIN_SOURCE_LIMIT:
        raise PluginValidationError("plugin source must be no larger than 1 MiB")
    return hashlib.sha256(source).hexdigest()


def manifest_signing_payload(manifest: dict[str, Any]) -> bytes:
    if not isinstance(manifest, dict):
        raise PluginValidationError("plugin manifest must be an object")
    unsigned = {key: value for key, value in manifest.items() if key != "signature"}
    return canonical_json(unsigned)


def sign_manifest(manifest: dict[str, Any], private_key: object) -> dict[str, Any]:
    """Return a manifest signed using an Ed25519 private-key object.

    The developer keeps the private key outside the plugin package and the
    customer's installation. Only the public key is installed into the trust
    store at the WiFi Analyzer Pro host.
    """
    if not hasattr(private_key, "sign"):
        raise PluginValidationError("private_key must be an Ed25519 signing key")
    result = dict(manifest)
    result.pop("signature", None)
    signature = private_key.sign(manifest_signing_payload(result))
    result["signature"] = base64.b64encode(signature).decode("ascii")
    return result


@dataclass(frozen=True, slots=True)
class FeaturePlugin:
    """SDK object exported by plugin.py as PLUGIN."""

    slug: str
    name: str
    description: str
    parameters: dict[str, Any]
    run: Callable[[dict[str, Any]], dict[str, Any]]

    def as_feature(self, manifest: dict[str, Any]) -> dict[str, Any]:
        if self.slug != manifest["slug"] or self.name != manifest["name"]:
            raise PluginValidationError("plugin entrypoint identity does not match its signed manifest")
        if self.description != manifest["description"] or self.parameters != manifest["parameters"]:
            raise PluginValidationError("plugin entrypoint metadata does not match its signed manifest")
        if not callable(self.run):
            raise PluginValidationError("plugin entrypoint run attribute must be callable")
        return {
            "id": "EXT:" + manifest["plugin_id"],
            "slug": self.slug,
            "name": self.name,
            "category": "Third-party",
            "description": self.description,
            "parameters": dict(self.parameters),
            "permissions": list(manifest["permissions"]),
            "version": manifest["version"],
            "publisher": manifest["publisher"],
            "run": self.run,
        }


def validate_manifest_shape(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != MANIFEST_FIELDS:
        raise PluginValidationError("plugin manifest fields do not match schema version 1")
    if value.get("schema_version") != PLUGIN_MANIFEST_SCHEMA:
        raise PluginValidationError("plugin manifest schema version is unsupported")
    plugin_id = value.get("plugin_id")
    if not isinstance(plugin_id, str) or not PLUGIN_ID.fullmatch(plugin_id):
        raise PluginValidationError("plugin_id must use publisher.plugin identifier syntax")
    publisher, plugin_name = plugin_id.split(".", 1)
    slug = value.get("slug")
    expected_slug = "ext_" + publisher.replace("-", "_") + "_" + plugin_name.replace("-", "_")
    if not isinstance(slug, str) or not PLUGIN_SLUG.fullmatch(slug) or slug != expected_slug:
        raise PluginValidationError("plugin slug must be the deterministic ext_<publisher>_<plugin> identifier")
    name = value.get("name")
    if not isinstance(name, str) or not name.strip() or len(name.strip()) > 120:
        raise PluginValidationError("plugin name must contain 1 to 120 characters")
    version = value.get("version")
    if not isinstance(version, str) or not SEMVER.fullmatch(version):
        raise PluginValidationError("plugin version must use semantic version syntax")
    if value.get("api_version") != PLUGIN_API_VERSION:
        raise PluginValidationError("plugin API version is not compatible with this host")
    if value.get("publisher") != publisher:
        raise PluginValidationError("plugin publisher must match the plugin_id prefix")
    key_id = value.get("key_id")
    if not isinstance(key_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}", key_id):
        raise PluginValidationError("plugin key_id is invalid")
    if value.get("entrypoint") != "plugin.py":
        raise PluginValidationError("only the fixed plugin.py entrypoint is supported")
    source_hash = value.get("source_sha256")
    if not isinstance(source_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", source_hash):
        raise PluginValidationError("source_sha256 must be a lowercase SHA-256 digest")
    description = value.get("description")
    if not isinstance(description, str) or not description.strip() or len(description.strip()) > 500:
        raise PluginValidationError("plugin description must contain 1 to 500 characters")
    parameters = value.get("parameters")
    if not isinstance(parameters, dict) or len(parameters) > 64:
        raise PluginValidationError("plugin parameters must be an object with at most 64 entries")
    canonical_json(parameters)
    permissions = value.get("permissions")
    if (
        not isinstance(permissions, list)
        or len(permissions) > len(PERMISSIONS)
        or any(not isinstance(item, str) or item not in PERMISSIONS for item in permissions)
        or len(permissions) != len(set(permissions))
    ):
        raise PluginValidationError("plugin permissions contain an unsupported or duplicate permission")
    signature = value.get("signature")
    if not isinstance(signature, str) or len(signature) > 256:
        raise PluginValidationError("plugin signature must be a bounded base64 Ed25519 signature")
    try:
        decoded = base64.b64decode(signature, validate=True)
    except (ValueError, TypeError):
        raise PluginValidationError("plugin signature is not valid base64") from None
    if len(decoded) != 64:
        raise PluginValidationError("plugin signature must contain 64 Ed25519 bytes")
    return dict(value)


def validate_plugin_payload(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise PluginValidationError("plugin input must be a JSON object")
    encoded = canonical_json(payload)
    if len(encoded) > PLUGIN_INPUT_LIMIT:
        raise PluginValidationError("plugin input exceeds the 1 MiB limit")
    return payload


def validate_plugin_result(result: object) -> dict[str, Any]:
    if not isinstance(result, dict):
        raise PluginValidationError("plugin result must be a JSON object")
    encoded = canonical_json(result)
    if len(encoded) > PLUGIN_OUTPUT_LIMIT:
        raise PluginValidationError("plugin result exceeds the 1 MiB limit")
    return result


__all__ = [
    "FeaturePlugin",
    "PLUGIN_API_VERSION",
    "PLUGIN_MANIFEST_SCHEMA",
    "PLUGIN_SOURCE_LIMIT",
    "PERMISSIONS",
    "PluginValidationError",
    "canonical_json",
    "manifest_signing_payload",
    "sign_manifest",
    "source_sha256",
    "validate_manifest_shape",
    "validate_plugin_payload",
    "validate_plugin_result",
]
