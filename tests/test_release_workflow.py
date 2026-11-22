"""Regression checks for the tagged-release build and frozen-binary smoke path."""
from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RELEASE_WORKFLOW = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
FROZEN_SMOKE = (ROOT / "wifi_analyzer_backend" / "smoke_test_frozen_features.py").read_text(encoding="utf-8")
README = (ROOT / "README.md").read_text(encoding="utf-8")


def _step(name: str) -> str:
    marker = f"      - name: {name}\n"
    start = RELEASE_WORKFLOW.find(marker)
    if start < 0:
        raise AssertionError(f"release workflow step not found: {name}")
    end = RELEASE_WORKFLOW.find("\n      - name:", start + len(marker))
    return RELEASE_WORKFLOW[start:] if end < 0 else RELEASE_WORKFLOW[start:end]


class ReleaseWorkflowTests(unittest.TestCase):
    def test_linux_frozen_smoke_uses_path_relative_to_backend_working_directory(self):
        step = _step("Smoke test standalone server (Linux)")
        self.assertIn("cd wifi_analyzer_backend", step)
        self.assertIn("python smoke_test_frozen_features.py", step)
        self.assertNotIn("python wifi_analyzer_backend/smoke_test_frozen_features.py", step)

    def test_all_platforms_execute_the_frozen_feature_smoke(self):
        for platform in ("Linux", "macOS", "Windows"):
            with self.subTest(platform=platform):
                self.assertIn(
                    "smoke_test_frozen_features.py",
                    _step(f"Smoke test standalone server ({platform})"),
                )

    def test_frozen_smoke_requires_the_entire_current_rf_and_client_feature_wave(self):
        self.assertIn("MINIMUM_FEATURE_COUNT = 208", FROZEN_SMOKE)
        for slug in (
            "multi_ap_channel_reuse_planner",
            "rf_survey_evidence_normalizer",
            "floorplan_rf_survey_analyzer",
            "rf_survey_report_comparator",
            "rf_survey_acceptance_auditor",
            "radio_regulatory_evidence_validator",
            "radio_capability_regulatory_channel_planner",
            "rf_change_approval_packet",
            "client_roam_transaction_analyzer",
            "client_experience_slo_evaluator",
            "client_experience_slo_window_comparator",
        ):
            with self.subTest(feature=slug):
                self.assertIn(f'"{slug}"', FROZEN_SMOKE)

    def test_frozen_smoke_executes_floorplan_rf_analysis_not_only_catalogue_listing(self):
        self.assertIn('"/api/features/floorplan_rf_survey_analyzer"', FROZEN_SMOKE)
        self.assertIn('floorplan_survey.get("feature") != "F203"', FROZEN_SMOKE)
        self.assertIn('"accepted_measurement_count") != 4', FROZEN_SMOKE)

    def test_windows_release_includes_a_license_bearing_portable_bundle(self):
        step = _step("Package Windows EXE, MSI, PowerShell and batch launchers")
        for required in (
            "Copy-Item 'README.md' $stage",
            "Copy-Item 'LICENSE' $stage",
            "wifi-analyzer-pro-$env:VERSION-windows-x64.zip",
            "wifi-analyzer-pro.bat",
            "wifi-analyzer-pro.ps1",
        ):
            with self.subTest(required=required):
                self.assertIn(required, step)
        self.assertIn("| Windows x64 | EXE, MSI, portable ZIP", README)

    def test_release_checksums_cover_assets_created_by_each_platform(self):
        checksum = _step("Generate platform SHA-256 manifest")
        self.assertIn("SHA256SUMS-${TARGET}.txt", checksum)
        self.assertIn("SHA256SUMS-windows-x64.txt", checksum)
        self.assertIn("Generate master SHA256SUMS", RELEASE_WORKFLOW)
        self.assertIn("Attest release asset provenance", RELEASE_WORKFLOW)

    def test_release_artifact_actions_use_compatible_v7_upload_and_v8_download(self):
        self.assertIn("uses: actions/upload-artifact@v7", RELEASE_WORKFLOW)
        self.assertIn("uses: actions/download-artifact@v8", RELEASE_WORKFLOW)
        self.assertNotIn("uses: actions/download-artifact@v4", RELEASE_WORKFLOW)

    def test_release_tag_must_match_application_version(self):
        self.assertIn("Verify release tag matches application version", RELEASE_WORKFLOW)
        self.assertIn("JSON.parse(require('fs').readFileSync('package.json')).version", RELEASE_WORKFLOW)
        self.assertIn('test "$expected" = "$actual"', RELEASE_WORKFLOW)


if __name__ == "__main__":
    unittest.main()
