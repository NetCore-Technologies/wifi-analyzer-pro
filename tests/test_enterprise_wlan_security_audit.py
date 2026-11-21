"""Tests for the evidence-aware enterprise WLAN security posture audit."""
import unittest

from wifi_analyzer_backend.feature_plugins.feature_194_enterprise_wlan_security_audit import run


def corporate_profile(**overrides):
    profile = {
        "profile_id": "hq-corporate",
        "site_id": "hq",
        "purpose": "corporate",
        "enabled": True,
        "security_mode": "WPA3-Enterprise",
        "ieee8021x_enabled": True,
        "pmf": "required",
        "eap_methods": ["EAP-TLS"],
        "validate_server_certificate": True,
        "client_certificate_required": True,
        "radius_servers": [
            {"server_id": "radius-a", "address": "192.0.2.10", "auth_port": 1812, "shared_secret_configured": True},
            {"server_id": "radius-b", "address": "192.0.2.11", "auth_port": 1812, "shared_secret_configured": True},
        ],
        "wps_enabled": False,
    }
    profile.update(overrides)
    return profile


def guest_profile(**overrides):
    profile = {
        "profile_id": "hq-guest",
        "site_id": "hq",
        "purpose": "guest",
        "enabled": True,
        "security_mode": "WPA3-Personal",
        "pmf": "required",
        "vlan_id": 300,
        "client_isolation": True,
        "firewall_isolation": True,
        "wps_enabled": False,
    }
    profile.update(overrides)
    return profile


class EnterpriseWlanSecurityAuditTests(unittest.TestCase):
    def test_compliant_corporate_and_guest_profiles_have_no_findings(self):
        result = run({"profiles": [corporate_profile(), guest_profile()]})
        self.assertEqual(result["feature"], "F194")
        self.assertEqual(result["status"], "audited")
        self.assertEqual(result["summary"]["profile_count"], 2)
        self.assertEqual(result["summary"]["compliant_profile_count"], 2)
        self.assertEqual(result["summary"]["finding_count"], 0)
        self.assertEqual(result["summary"]["compliance_pct"], 100.0)

    def test_missing_controls_are_evidence_gaps_not_assumed_disabled(self):
        result = run({"profiles": [{"profile_id": "unknown-office", "site_id": "hq", "purpose": "corporate"}]})
        codes = {item["code"] for item in result["findings"]}
        states = {item["evidence_state"] for item in result["findings"]}
        self.assertEqual(result["profiles"][0]["status"], "evidence_incomplete")
        self.assertIn("SECURITY_MODE_UNKNOWN", codes)
        self.assertIn("PMF_EVIDENCE_MISSING", codes)
        self.assertNotIn("CORPORATE_REQUIRES_ENTERPRISE_AUTH", codes)
        self.assertEqual(states, {"missing"})
        self.assertEqual(result["summary"]["violation_count"], 0)
        self.assertGreater(result["summary"]["evidence_gap_count"], 0)
        self.assertIsNone(result["summary"]["compliance_pct"])
        self.assertIsNone(result["summary"]["observed_risk_score"])
        self.assertIsNone(result["profiles"][0]["observed_risk_score"])

    def test_explicitly_empty_radius_inventory_is_a_confirmed_violation(self):
        result = run({"profiles": [corporate_profile(radius_servers=[])]})
        finding = next(item for item in result["findings"] if item["code"] == "RADIUS_SERVERS_MISSING")
        self.assertEqual(finding["evidence_state"], "violation")
        self.assertEqual(finding["severity"], "critical")

    def test_profiles_with_both_known_violations_and_missing_evidence_have_unknown_risk(self):
        result = run({"profiles": [corporate_profile(
            security_mode="WPA2-Personal",
            pmf=None,
        )]})
        profile = result["profiles"][0]
        self.assertEqual(profile["status"], "non_compliant")
        self.assertGreater(profile["violation_count"], 0)
        self.assertGreater(profile["evidence_gap_count"], 0)
        self.assertIsNone(profile["observed_risk_score"])
        self.assertEqual(result["summary"]["evidence_incomplete_profile_count"], 1)
        self.assertIsNone(result["summary"]["observed_risk_score"])

    def test_corporate_personal_security_is_a_critical_policy_violation(self):
        result = run({"profiles": [corporate_profile(
            security_mode="WPA2-Personal",
            radius_servers=[],
            eap_methods=[],
        )]})
        finding = next(item for item in result["findings"] if item["code"] == "CORPORATE_REQUIRES_ENTERPRISE_AUTH")
        self.assertEqual(finding["severity"], "critical")
        self.assertEqual(finding["evidence_state"], "violation")
        self.assertEqual(result["profiles"][0]["status"], "non_compliant")

    def test_corporate_minimum_eap_and_radius_redundancy_policy_is_enforced(self):
        profile = corporate_profile(
            security_mode="WPA2-Enterprise",
            eap_methods=["PEAP-MSCHAPv2"],
            radius_servers=[{"server_id": "only-radius", "address": "radius1.example.net", "shared_secret_configured": True}],
        )
        result = run({
            "policy": {"minimum_corporate_security": "WPA3-Enterprise"},
            "profiles": [profile],
        })
        codes = {item["code"] for item in result["findings"]}
        self.assertIn("CORPORATE_SECURITY_BELOW_POLICY", codes)
        self.assertIn("EAP_METHOD_NOT_ALLOWED", codes)
        self.assertIn("RADIUS_REDUNDANCY_INSUFFICIENT", codes)

    def test_custom_eap_allowlist_can_approve_peap_explicitly(self):
        profile = corporate_profile(eap_methods=["PEAP-MSCHAPv2"], client_certificate_required=False)
        result = run({
            "policy": {
                "minimum_corporate_security": "WPA2-Enterprise",
                "allowed_eap_methods": ["PEAP-MSCHAPv2"],
            },
            "profiles": [profile],
        })
        self.assertEqual(result["summary"]["compliant_profile_count"], 1)
        self.assertEqual(result["summary"]["finding_count"], 0)

    def test_certificate_validation_and_eap_tls_client_certificate_are_checked(self):
        result = run({"profiles": [corporate_profile(
            validate_server_certificate=False,
            client_certificate_required=False,
        )]})
        codes = {item["code"] for item in result["findings"]}
        self.assertIn("RADIUS_SERVER_CERT_VALIDATION_DISABLED", codes)
        self.assertIn("EAP_TLS_CLIENT_CERT_NOT_REQUIRED", codes)

    def test_radius_shared_secret_missing_or_unconfigured_is_not_silently_accepted(self):
        result = run({"profiles": [corporate_profile(radius_servers=[
            {"server_id": "radius-a", "address": "192.0.2.10", "shared_secret_configured": False},
            {"server_id": "radius-b", "address": "192.0.2.11"},
        ])]})
        codes = {item["code"] for item in result["findings"]}
        self.assertIn("RADIUS_SHARED_SECRET_NOT_CONFIGURED", codes)
        self.assertIn("RADIUS_SECRET_EVIDENCE_MISSING", codes)

    def test_missing_radius_secret_state_is_an_evidence_gap_not_a_violation(self):
        result = run({"profiles": [corporate_profile(radius_servers=[
            {"server_id": "radius-a", "address": "192.0.2.10", "shared_secret_configured": None},
        ])]})
        finding = next(item for item in result["findings"] if item["code"] == "RADIUS_SECRET_EVIDENCE_MISSING")
        self.assertEqual(finding["evidence_state"], "missing")
        self.assertNotIn("RADIUS_SHARED_SECRET_NOT_CONFIGURED", {
            item["code"] for item in result["findings"]
        })
        self.assertIsNone(result["profiles"][0]["observed_risk_score"])

    def test_duplicate_radius_addresses_do_not_count_as_redundancy(self):
        result = run({"profiles": [corporate_profile(radius_servers=[
            {"server_id": "radius-a", "address": "192.0.2.10", "shared_secret_configured": True},
            {"server_id": "radius-b", "address": "192.0.2.10", "shared_secret_configured": True},
        ])]})
        self.assertEqual(result["profiles"][0]["radius_server_count"], 1)
        self.assertIn("RADIUS_REDUNDANCY_INSUFFICIENT", {item["code"] for item in result["findings"]})

    def test_guest_open_portal_and_isolation_controls_are_enforced(self):
        result = run({"profiles": [guest_profile(
            security_mode="open",
            captive_portal_enabled=False,
            vlan_id=None,
            client_isolation=False,
            firewall_isolation=False,
            pmf="optional",
            wps_enabled=True,
        )]})
        codes = {item["code"] for item in result["findings"]}
        self.assertIn("GUEST_OPEN_WITHOUT_CAPTIVE_PORTAL", codes)
        self.assertIn("GUEST_VLAN_EVIDENCE_MISSING", codes)
        self.assertIn("GUEST_CLIENT_ISOLATION_DISABLED", codes)
        self.assertIn("GUEST_FIREWALL_ISOLATION_DISABLED", codes)
        self.assertIn("PMF_NOT_REQUIRED", codes)
        self.assertIn("WPS_ENABLED", codes)

    def test_iot_and_management_networks_are_segmented_and_restricted(self):
        iot = {
            "profile_id": "hq-iot",
            "site_id": "hq",
            "purpose": "iot",
            "enabled": True,
            "security_mode": "WPA3-Personal",
            "pmf": "required",
            "wps_enabled": False,
            "vlan_id": 400,
            "client_isolation": False,
            "firewall_isolation": False,
        }
        management = corporate_profile(
            profile_id="hq-management",
            purpose="management",
            management_access_restricted=False,
        )
        result = run({"profiles": [iot, management]})
        codes = {item["code"] for item in result["findings"]}
        self.assertIn("IOT_CLIENT_ISOLATION_DISABLED", codes)
        self.assertIn("IOT_FIREWALL_ISOLATION_DISABLED", codes)
        self.assertIn("MANAGEMENT_ACCESS_EXPOSED", codes)

    def test_sensitive_profile_fields_and_radius_addresses_are_never_returned(self):
        profile = corporate_profile(
            ssid="private-office-wlan-ssid",
            shared_secret="never-return-this",
        )
        profile["radius_servers"][0]["shared_secret"] = "radius-secret-never-return-this"
        result = run({"profiles": [profile]})
        rendered = str(result)
        for secret in ("private-office-wlan-ssid", "192.0.2.10", "radius-secret-never-return-this", "never-return-this"):
            self.assertNotIn(secret, rendered)
        self.assertNotIn('"shared_secret"', rendered)
        self.assertNotIn('"address"', rendered)

    def test_disabled_profiles_are_recorded_but_not_audited(self):
        result = run({"profiles": [corporate_profile(enabled=False, security_mode="open", wps_enabled=True)]})
        self.assertEqual(result["profiles"][0]["status"], "disabled")
        self.assertEqual(result["profiles"][0]["finding_count"], 0)
        self.assertEqual(result["summary"]["disabled_profile_count"], 1)
        self.assertEqual(result["summary"]["finding_count"], 0)

    def test_empty_inventory_has_no_fabricated_compliance_score(self):
        result = run({"profiles": []})
        self.assertEqual(result["status"], "empty")
        self.assertIsNone(result["summary"]["compliance_pct"])
        self.assertIsNone(result["summary"]["observed_risk_score"])

    def test_duplicate_profile_ids_and_invalid_values_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "profile_id values must be unique"):
            run({"profiles": [{"profile_id": "same"}, {"profile_id": "same"}]})
        with self.assertRaisesRegex(ValueError, "pmf must be one of"):
            run({"profiles": [{"profile_id": "bad-pmf", "pmf": "sometimes"}]})
        with self.assertRaisesRegex(ValueError, "valid IP address or DNS hostname"):
            run({"profiles": [corporate_profile(radius_servers=[
                {"address": "bad host name", "shared_secret_configured": True},
                {"address": "radius2.example.net", "shared_secret_configured": True},
            ])]})

    def test_policy_and_inventory_limits_are_bounded(self):
        with self.assertRaisesRegex(ValueError, "allowed_eap_methods"):
            run({"policy": {"allowed_eap_methods": []}, "profiles": []})
        with self.assertRaisesRegex(ValueError, "minimum_radius_servers"):
            run({"policy": {"minimum_radius_servers": 0}, "profiles": []})
        too_many = [{"profile_id": f"profile-{index}"} for index in range(1025)]
        with self.assertRaisesRegex(ValueError, "no more than 1024"):
            run({"profiles": too_many})


if __name__ == "__main__":
    unittest.main()
