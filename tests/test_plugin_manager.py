"""Tests for the signed third-party feature plugin SDK and lifecycle manager."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wifi_analyzer_backend.plugin_manager import PluginManager
from wifi_analyzer_backend.plugin_sdk import (
    FeaturePlugin,
    PluginValidationError,
    sign_manifest,
    source_sha256,
    validate_manifest_shape,
)


PLUGIN_ID = "acme.channel_quality"
PLUGIN_SLUG = "ext_acme_channel_quality"
PLUGIN_NAME = "Acme channel quality"


def sample_source() -> bytes:
    return b"""from wifi_analyzer_backend.plugin_sdk import FeaturePlugin

def run(payload):
    networks = payload.get("networks", [])
    if not isinstance(networks, list):
        raise ValueError("networks must be a list")
    return {"network_count": len(networks), "quality": "measured"}

PLUGIN = FeaturePlugin(
    slug="ext_acme_channel_quality",
    name="Acme channel quality",
    description="Score a supplied Wi-Fi network observation set.",
    parameters={"networks": "network[]"},
    run=run,
)
"""


class PluginManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.plugin_dir = root / "plugins"
        self.plugin_dir.mkdir(mode=0o700)
        self.state_path = root / "plugin-state.sqlite3"
        self.private_key = Ed25519PrivateKey.generate()
        public_key = self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self.manager = PluginManager(
            plugin_directory=self.plugin_dir,
            state_database=self.state_path,
            trusted_keys={"acme-release-2026": public_key},
        )
        self.install_package()

    def manifest(self, *, source: bytes | None = None, **overrides):
        source = source if source is not None else sample_source()
        value = {
            "schema_version": 1,
            "plugin_id": PLUGIN_ID,
            "slug": PLUGIN_SLUG,
            "name": PLUGIN_NAME,
            "version": "1.0.0",
            "api_version": "1.0",
            "publisher": "acme",
            "key_id": "acme-release-2026",
            "entrypoint": "plugin.py",
            "source_sha256": source_sha256(source),
            "description": "Score a supplied Wi-Fi network observation set.",
            "parameters": {"networks": "network[]"},
            "permissions": ["diagnostics.read"],
        }
        value.update(overrides)
        return sign_manifest(value, self.private_key)

    def install_package(self, *, source: bytes | None = None, manifest_overrides=None):
        source = source if source is not None else sample_source()
        directory = self.plugin_dir / PLUGIN_ID
        directory.mkdir(mode=0o700, exist_ok=True)
        manifest = self.manifest(
            source=source,
            **(manifest_overrides or {}),
        )
        (directory / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, sort_keys=True),
            encoding="utf-8",
        )
        (directory / "plugin.py").write_bytes(source)
        if os.name != "nt":
            os.chmod(directory, 0o700)
            os.chmod(directory / "manifest.json", 0o600)
            os.chmod(directory / "plugin.py", 0o600)
        return directory

    def test_signed_package_is_discovered_but_disabled_by_default(self):
        listing = self.manager.list_plugins()
        self.assertEqual(listing["plugin_count"], 1)
        self.assertEqual(listing["enabled_count"], 0)
        self.assertEqual(listing["rejected_count"], 0)
        plugin = listing["plugins"][0]
        self.assertEqual(plugin["plugin_id"], PLUGIN_ID)
        self.assertFalse(plugin["enabled"])
        self.assertTrue(plugin["signature_verified"])
        self.assertEqual(self.manager.catalog(), [])
        with self.assertRaisesRegex(KeyError, "Unknown or disabled"):
            self.manager.run(PLUGIN_SLUG, {"networks": []})

    def test_enable_execute_reload_disable_and_reenable_lifecycle(self):
        enabled = self.manager.enable(PLUGIN_ID)
        self.assertTrue(enabled["enabled"])
        feature = self.manager.catalog()[0]
        self.assertEqual(feature["slug"], PLUGIN_SLUG)
        self.assertEqual(feature["id"], "EXT:" + PLUGIN_ID)
        result = self.manager.run(PLUGIN_SLUG, {"networks": [{"rssi": -52}]})
        self.assertEqual(result, {
            "feature": "EXT:" + PLUGIN_ID,
            "slug": PLUGIN_SLUG,
            "result": {"network_count": 1, "quality": "measured"},
        })

        reloaded = self.manager.reload(PLUGIN_ID)
        self.assertEqual(reloaded["version"], "1.0.0")
        self.assertEqual(self.manager.run(PLUGIN_SLUG, {"networks": []})["result"]["network_count"], 0)

        disabled = self.manager.disable(PLUGIN_ID)
        self.assertFalse(disabled["enabled"])
        self.assertTrue(disabled["unloaded"])
        self.assertEqual(self.manager.catalog(), [])
        with self.assertRaisesRegex(KeyError, "Unknown or disabled"):
            self.manager.run(PLUGIN_SLUG, {"networks": []})

        self.assertTrue(self.manager.enable(PLUGIN_ID)["enabled"])
        self.assertEqual(self.manager.run(PLUGIN_SLUG, {"networks": []})["result"]["quality"], "measured")

    def test_tampered_source_is_rejected_after_manifest_was_signed(self):
        self.manager.enable(PLUGIN_ID)
        source_path = self.plugin_dir / PLUGIN_ID / "plugin.py"
        source_path.write_bytes(source_path.read_bytes() + b"\n# modified after signing\n")
        listing = self.manager.list_plugins()
        self.assertEqual(listing["plugin_count"], 0)
        self.assertEqual(listing["rejected_count"], 1)
        self.assertEqual(listing["plugins"][0]["error_code"], "plugin_validation_failed")
        with self.assertRaisesRegex(KeyError, "Unknown or disabled"):
            self.manager.run(PLUGIN_SLUG, {"networks": []})

    def test_integrity_failure_revokes_enabled_state_until_admin_reenables(self):
        self.manager.enable(PLUGIN_ID)
        source_path = self.plugin_dir / PLUGIN_ID / "plugin.py"
        original_source = source_path.read_bytes()
        source_path.write_bytes(original_source + b"\\n# tampered\\n")
        rejected = self.manager.list_plugins()
        self.assertEqual(rejected["plugins"][0]["status"], "rejected")
        self.assertTrue(rejected["plugins"][0]["previously_enabled"])
        self.assertEqual(rejected["enabled_count"], 0)

        source_path.write_bytes(original_source)
        self.assertEqual(self.manager.catalog(), [])
        self.assertTrue(self.manager.enable(PLUGIN_ID)["enabled"])
        self.assertEqual(len(self.manager.catalog()), 1)

    def test_untrusted_publisher_signature_is_rejected(self):
        other_key = Ed25519PrivateKey.generate()
        source = sample_source()
        manifest = self.manifest(source=source)
        # Keep the valid manifest shape and source digest but sign it with an
        # unrelated key, then replace the installed signed document.
        unsigned = {key: value for key, value in manifest.items() if key != "signature"}
        manifest["signature"] = base64.b64encode(other_key.sign(
            json.dumps(unsigned, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        )).decode("ascii")
        (self.plugin_dir / PLUGIN_ID / "manifest.json").write_text(
            json.dumps(manifest), encoding="utf-8",
        )
        listing = self.manager.list_plugins()
        self.assertEqual(listing["plugin_count"], 0)
        self.assertEqual(listing["rejected_count"], 1)

    def test_incompatible_api_version_and_unknown_permissions_are_rejected(self):
        with self.assertRaisesRegex(PluginValidationError, "API version"):
            validate_manifest_shape(self.manifest(api_version="2.0"))
        with self.assertRaisesRegex(PluginValidationError, "permissions"):
            validate_manifest_shape(self.manifest(permissions=["diagnostics.read", "root.access"]))

    def test_disabled_plugins_do_not_appear_in_the_feature_catalog(self):
        self.assertEqual(self.manager.catalog(), [])
        self.manager.enable(PLUGIN_ID)
        self.assertEqual(len(self.manager.catalog()), 1)
        self.manager.disable(PLUGIN_ID)
        self.assertEqual(self.manager.catalog(), [])

    def test_execution_input_and_output_are_bounded_json_objects(self):
        self.manager.enable(PLUGIN_ID)
        with self.assertRaisesRegex(PluginValidationError, "JSON object"):
            self.manager.run(PLUGIN_SLUG, ["not", "an", "object"])
        with self.assertRaisesRegex(PluginValidationError, "1 MiB"):
            self.manager.run(PLUGIN_SLUG, {"value": "x" * (1024 * 1024 + 1)})

    @unittest.skipIf(os.name == "nt", "POSIX plugin package permission assertions")
    def test_plugin_package_rejects_group_or_world_writable_code(self):
        source = self.plugin_dir / PLUGIN_ID / "plugin.py"
        os.chmod(source, stat.S_IRUSR | stat.S_IWUSR | stat.S_IWGRP)
        listing = self.manager.list_plugins()
        self.assertEqual(listing["plugin_count"], 0)
        self.assertEqual(listing["rejected_count"], 1)


if __name__ == "__main__":
    unittest.main()
