"""Regression checks for standalone packaging of dynamically loaded plugins."""
from __future__ import annotations

import os
import subprocess
import sys
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
        syntax = subprocess.run(
            ["bash", "-n", str(ROOT / "wifi_analyzer_backend" / "build_arm64_binary.sh")],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)

    def test_live_capture_can_be_imported_by_direct_server_execution(self):
        environment = os.environ.copy()
        backend_path = str(ROOT / "wifi_analyzer_backend")
        current_path = environment.get("PYTHONPATH", "")
        environment["PYTHONPATH"] = backend_path + (os.pathsep + current_path if current_path else "")
        result = subprocess.run(
            [sys.executable, "-c", "import live_capture; assert live_capture.LiveCaptureManager"],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rate_limiter_can_be_imported_by_direct_server_execution(self):
        environment = os.environ.copy()
        backend_path = str(ROOT / "wifi_analyzer_backend")
        current_path = environment.get("PYTHONPATH", "")
        environment["PYTHONPATH"] = backend_path + (os.pathsep + current_path if current_path else "")
        result = subprocess.run(
            [sys.executable, "-c", "import rate_limit; assert rate_limit.TokenBucketRateLimiter"],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_webhook_dispatch_worker_can_be_imported_by_direct_execution(self):
        environment = os.environ.copy()
        backend_path = str(ROOT / "wifi_analyzer_backend")
        current_path = environment.get("PYTHONPATH", "")
        environment["PYTHONPATH"] = backend_path + (os.pathsep + current_path if current_path else "")
        result = subprocess.run(
            [sys.executable, "-c", "import webhook_dispatch_worker; assert webhook_dispatch_worker.WebhookDispatchWorker"],
            cwd=ROOT, env=environment, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_webhook_subscription_store_imports_in_direct_execution_runtime(self):
        environment = os.environ.copy()
        backend_path = str(ROOT / "wifi_analyzer_backend")
        current_path = environment.get("PYTHONPATH", "")
        environment["PYTHONPATH"] = backend_path + (os.pathsep + current_path if current_path else "")
        result = subprocess.run(
            [sys.executable, "-c", "import webhook_subscription_store; assert webhook_subscription_store.WebhookSubscriptionStore"],
            cwd=ROOT, env=environment, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_docker_runtime_copies_signed_audit_checkpoint_support(self):
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn(
            "COPY --chown=10001:10001 wifi_analyzer_backend/audit_checkpoint.py ./audit_checkpoint.py",
            dockerfile,
        )
        self.assertIn(
            "COPY --chown=10001:10001 wifi_analyzer_backend/live_capture.py ./live_capture.py",
            dockerfile,
        )
        self.assertIn(
            "COPY --chown=10001:10001 wifi_analyzer_backend/rate_limit.py ./rate_limit.py",
            dockerfile,
        )
        self.assertIn(
            "COPY --chown=10001:10001 wifi_analyzer_backend/webhook_delivery_store.py ./webhook_delivery_store.py",
            dockerfile,
        )
        self.assertIn(
            "COPY --chown=10001:10001 wifi_analyzer_backend/webhook_dispatch_worker.py ./webhook_dispatch_worker.py",
            dockerfile,
        )
        self.assertIn(
            "COPY --chown=10001:10001 wifi_analyzer_backend/webhook_subscription_store.py ./webhook_subscription_store.py",
            dockerfile,
        )

    def test_release_smoke_test_executes_dynamic_feature_plugins_while_server_is_running(self):
        release_workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        smoke_helper = (ROOT / "wifi_analyzer_backend" / "smoke_test_frozen_features.py").read_text(encoding="utf-8")

        self.assertEqual(release_workflow.count("smoke_test_frozen_features.py"), 3)
        self.assertIn("router_webhook_subscription_router", smoke_helper)
        self.assertIn("router_scheduled_report_delivery_package", smoke_helper)
        self.assertIn("pcap_capture_analyzer", smoke_helper)
        self.assertIn("router_webhook_delivery_orchestrator", smoke_helper)
        self.assertIn('result.get("feature") != "F191"', smoke_helper)
        self.assertIn('webhook.get("feature") != "F192"', smoke_helper)


if __name__ == "__main__":
    unittest.main()
