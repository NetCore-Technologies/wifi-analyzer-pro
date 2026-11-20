"""Regression checks for standalone packaging of dynamically loaded plugins."""
from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class FrozenPackagingConfigTests(unittest.TestCase):
    def test_all_pyinstaller_builds_collect_feature_plugin_submodules(self):
        release_workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        arm64_script = (ROOT / "wifi_analyzer_backend" / "build_arm64_binary.sh").read_text(encoding="utf-8")

        self.assertIn("--collect-submodules feature_plugins", release_workflow)
        self.assertIn("--collect-submodules feature_plugins", arm64_script)

    def test_release_smoke_test_executes_dynamic_feature_plugins(self):
        release_workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        self.assertIn("Smoke test bundled feature plugins", release_workflow)
        self.assertIn("router_webhook_subscription_router", release_workflow)
        self.assertIn("router_scheduled_report_delivery_package", release_workflow)
        self.assertIn("pcap_capture_analyzer", release_workflow)


if __name__ == "__main__":
    unittest.main()
