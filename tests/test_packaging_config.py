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

    def test_arm64_builder_runs_the_frozen_plugin_smoke_test_on_an_isolated_port(self):
        arm64_script = (ROOT / "wifi_analyzer_backend" / "build_arm64_binary.sh").read_text(encoding="utf-8")
        smoke_helper = (ROOT / "wifi_analyzer_backend" / "smoke_test_frozen_features.py").read_text(encoding="utf-8")

        self.assertIn('SMOKE_PORT="$(.venv/bin/python', arm64_script)
        self.assertIn("WIFI_ANALYZER_PORT=", arm64_script)
        self.assertIn("WIFI_ANALYZER_AUTH_FILE=", arm64_script)
        self.assertIn("WIFI_ANALYZER_HISTORY_DB=", arm64_script)
        self.assertIn('rm -rf "$SMOKE_DIR"', arm64_script)
        self.assertIn("smoke_test_frozen_features.py", arm64_script)
        self.assertIn("WIFI_ANALYZER_SMOKE_URL", smoke_helper)

    def test_release_smoke_test_executes_dynamic_feature_plugins_while_server_is_running(self):
        release_workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        smoke_helper = (ROOT / "wifi_analyzer_backend" / "smoke_test_frozen_features.py").read_text(encoding="utf-8")

        self.assertEqual(release_workflow.count("smoke_test_frozen_features.py"), 3)
        self.assertIn("router_webhook_subscription_router", smoke_helper)
        self.assertIn("router_scheduled_report_delivery_package", smoke_helper)
        self.assertIn("pcap_capture_analyzer", smoke_helper)
        self.assertIn('result.get("feature") != "F191"', smoke_helper)


if __name__ == "__main__":
    unittest.main()
