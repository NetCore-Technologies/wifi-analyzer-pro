"""Regression checks for hardened Compose and systemd deployment assets."""
from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class DeploymentConfigTests(unittest.TestCase):
    def test_compose_binds_loopback_by_default_and_persists_shared_state(self):
        compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
        self.assertIn("WIFI_ANALYZER_BIND_ADDRESS:-127.0.0.1", compose)
        self.assertIn("read_only: true", compose)
        self.assertIn("cap_drop:", compose)
        self.assertIn("- ALL", compose)
        self.assertIn("no-new-privileges:true", compose)
        self.assertIn("config:/home/wifi-analyzer/.config", compose)
        self.assertIn("state:/home/wifi-analyzer/.local/state", compose)
        self.assertIn("profiles:", compose)
        self.assertIn("webhook-dispatcher", compose)

    def test_systemd_units_share_state_and_drop_privileges(self):
        paths = [
            "wifi-analyzer-pro.service",
            "wifi-analyzer-webhook-dispatcher.service",
            "wifi-analyzer-report-worker.service",
        ]
        for filename in paths:
            content = (ROOT / "deploy" / "systemd" / filename).read_text(encoding="utf-8")
            with self.subTest(filename=filename):
                self.assertIn("User=wifi-analyzer", content)
                self.assertIn("Group=wifi-analyzer", content)
                self.assertIn("StateDirectory=wifi-analyzer-pro", content)
                self.assertIn("UMask=0077", content)
                self.assertIn("NoNewPrivileges=true", content)
                self.assertIn("ProtectSystem=strict", content)
                self.assertIn("CapabilityBoundingSet=", content)
                self.assertIn("ReadWritePaths=/var/lib/wifi-analyzer-pro", content)

    def test_deployment_guide_covers_backup_rollback_and_secret_separation(self):
        guide = (ROOT / "deploy" / "README.md").read_text(encoding="utf-8")
        self.assertIn("State, backup and restore", guide)
        self.assertIn("Upgrade and rollback", guide)
        self.assertIn("report-worker.env", guide)
        self.assertIn("NFS/SMB", guide)
        self.assertIn("public internet", guide)

    def test_report_and_webhook_workers_have_separate_service_units(self):
        report = (ROOT / "deploy" / "systemd" / "wifi-analyzer-report-worker.service").read_text(encoding="utf-8")
        webhook = (ROOT / "deploy" / "systemd" / "wifi-analyzer-webhook-dispatcher.service").read_text(encoding="utf-8")
        self.assertIn("EnvironmentFile=/etc/wifi-analyzer-pro/report-worker.env", report)
        self.assertIn("webhook_dispatch_worker", webhook)
        self.assertNotIn("SIGNING_SECRET", webhook)


if __name__ == "__main__":
    unittest.main()
