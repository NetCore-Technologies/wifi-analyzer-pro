"""Tests for vendor-issued installation licences and offline verification."""
import base64
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wifi_analyzer_backend.billing import PLAN_CATALOG
from wifi_analyzer_backend.license import (
    LICENSE_SCHEMA,
    LicenseVerificationError,
    VendorLicenseStore,
    create_signed_license,
    verify_license_token,
)


INSTALLATION_ID = "a" * 32
NOW = 1_800_000_000


class VendorLicenseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.private_key = Ed25519PrivateKey.generate()
        self.public_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.public_keys = {"test-key": self.public_bytes}
        self.clock = [float(NOW)]
        self.store = VendorLicenseStore(
            self.root / "vendor-license.json",
            public_keys=self.public_keys,
            clock=lambda: self.clock[0],
        )

    def tearDown(self):
        self.temp.cleanup()

    def claims(self, **overrides):
        result = {
            "schema": LICENSE_SCHEMA,
            "key_id": "test-key",
            "license_id": "lic_customer12345678",
            "installation_id": INSTALLATION_ID,
            "plan_id": "business",
            "issued_at": NOW - 60,
            "expires_at": NOW + 30 * 24 * 60 * 60,
            "limits": dict(PLAN_CATALOG["business"]["limits"]),
        }
        result.update(overrides)
        return result

    def token(self, **overrides):
        return create_signed_license(self.claims(**overrides), self.private_key)

    def test_valid_license_grants_signed_plan_entitlements_to_bound_installation(self):
        result = verify_license_token(
            self.token(),
            public_keys=self.public_keys,
            expected_installation_id=INSTALLATION_ID,
            now=NOW,
        )
        self.assertTrue(result["valid"])
        self.assertTrue(result["active"])
        self.assertFalse(result["grace_period"])
        self.assertEqual(result["plan_id"], "business")
        self.assertEqual(result["limits"], PLAN_CATALOG["business"]["limits"])

    def test_license_is_bound_to_one_installation(self):
        with self.assertRaisesRegex(LicenseVerificationError, "different installation"):
            verify_license_token(
                self.token(),
                public_keys=self.public_keys,
                expected_installation_id="b" * 32,
                now=NOW,
            )

    def test_payload_tampering_wrong_key_and_unknown_key_are_rejected(self):
        token = self.token()
        payload_segment, signature_segment = token.split(".")
        raw = base64.urlsafe_b64decode(payload_segment + "=" * (-len(payload_segment) % 4))
        claims = json.loads(raw)
        claims["plan_id"] = "enterprise"
        altered = base64.urlsafe_b64encode(
            json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
        ).decode().rstrip("=") + "." + signature_segment
        with self.assertRaises(LicenseVerificationError):
            verify_license_token(
                altered, public_keys=self.public_keys,
                expected_installation_id=INSTALLATION_ID, now=NOW,
            )
        with self.assertRaises(LicenseVerificationError):
            verify_license_token(
                token, public_keys={"other-key": self.public_bytes},
                expected_installation_id=INSTALLATION_ID, now=NOW,
            )

    def test_invalid_plan_limits_schema_and_time_claims_are_rejected(self):
        for overrides in (
            {"plan_id": "super-enterprise"},
            {"limits": {"users": 100000}},
            {"issued_at": NOW + 3600},
            {"expires_at": NOW - 61},
            {"expires_at": NOW + 20 * 365 * 24 * 60 * 60},
            {"license_id": "bad-id"},
            {"installation_id": "not-an-install"},
        ):
            with self.subTest(overrides=overrides):
                with self.assertRaises(LicenseVerificationError):
                    verify_license_token(
                        self.token(**overrides),
                        public_keys=self.public_keys,
                        expected_installation_id=INSTALLATION_ID,
                        now=NOW,
                    )

    def test_expired_license_has_a_bounded_offline_grace_period(self):
        expiry = NOW - 60 * 60
        result = verify_license_token(
            self.token(issued_at=NOW - 7 * 24 * 60 * 60, expires_at=expiry),
            public_keys=self.public_keys,
            expected_installation_id=INSTALLATION_ID,
            now=NOW,
        )
        self.assertTrue(result["active"])
        self.assertTrue(result["grace_period"])
        with self.assertRaisesRegex(LicenseVerificationError, "expired"):
            verify_license_token(
                self.token(issued_at=NOW - 7 * 24 * 60 * 60, expires_at=expiry),
                public_keys=self.public_keys,
                expected_installation_id=INSTALLATION_ID,
                now=expiry + 72 * 60 * 60 + 1,
            )

    def test_activation_persists_verified_token_and_status_survives_restart(self):
        token = self.token()
        result = self.store.activate(token, INSTALLATION_ID)
        self.assertEqual(result["plan_id"], "business")
        self.assertEqual(self.store.status(INSTALLATION_ID)["license_id"], "lic_customer12345678")
        restarted = VendorLicenseStore(
            self.root / "vendor-license.json",
            public_keys=self.public_keys,
            clock=lambda: self.clock[0],
        )
        self.assertEqual(restarted.status(INSTALLATION_ID)["plan_id"], "business")
        self.assertTrue(restarted.status(INSTALLATION_ID)["active"])

    def test_activation_refuses_wrong_installation_without_replacing_existing_license(self):
        original = self.token()
        self.store.activate(original, INSTALLATION_ID)
        with self.assertRaises(LicenseVerificationError):
            self.store.activate(self.token(installation_id="b" * 32), INSTALLATION_ID)
        self.assertEqual(self.store.status(INSTALLATION_ID)["plan_id"], "business")

    def test_license_file_is_private_and_deactivation_removes_it(self):
        self.store.activate(self.token(), INSTALLATION_ID)
        self.assertTrue(self.store.path.exists())
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(self.store.path.stat().st_mode), 0o600)
        self.assertTrue(self.store.deactivate())
        self.assertFalse(self.store.path.exists())
        self.assertFalse(self.store.status(INSTALLATION_ID)["installed"])

    def test_vendor_signed_offline_grace_claim_overrides_generic_default(self):
        token = self.token(
            issued_at=NOW - 7 * 24 * 60 * 60,
            expires_at=NOW - 60,
            offline_grace_seconds=6 * 60 * 60,
        )
        with self.assertRaisesRegex(LicenseVerificationError, "expired"):
            verify_license_token(
                token, public_keys=self.public_keys,
                expected_installation_id=INSTALLATION_ID,
                now=NOW - 60 + 6 * 60 * 60 + 1,
            )

    def test_refresh_credentials_are_private_and_validate_fixed_https_origin(self):
        self.store.configure_service(
            service_url="https://licenses.example.com",
            checkout_session_id="cs_test_123456789",
            activation_secret="a" * 48,
            license_id="lic_customer12345678",
        )
        credentials = self.store.refresh_credentials()
        self.assertEqual(credentials["service_url"], "https://licenses.example.com")
        self.assertEqual(credentials["activation_secret"], "a" * 48)
        self.assertTrue(self.store.renewal_configured())
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(self.store.refresh_path.stat().st_mode), 0o600)
        with self.assertRaises(ValueError):
            self.store.configure_service(
                service_url="http://127.0.0.1:1999",
                checkout_session_id="cs_test_123456789",
                activation_secret="a" * 48,
                license_id="lic_customer12345678",
            )

    def test_deactivation_removes_refresh_credentials_as_well_as_token(self):
        self.store.configure_service(
            service_url="https://licenses.example.com",
            checkout_session_id="cs_test_123456789",
            activation_secret="a" * 48,
            license_id="lic_customer12345678",
        )
        self.store.activate(self.token(), INSTALLATION_ID)
        self.assertTrue(self.store.deactivate())
        self.assertIsNone(self.store.refresh_credentials())

    def test_missing_public_key_configuration_fails_closed(self):
        store = VendorLicenseStore(
            self.root / "unconfigured.json",
            public_keys={},
            clock=lambda: self.clock[0],
        )
        self.assertFalse(store.status(INSTALLATION_ID)["configured"])
        with self.assertRaisesRegex(LicenseVerificationError, "not configured"):
            store.activate(self.token(), INSTALLATION_ID)

    def test_malformed_stored_token_fails_closed(self):
        self.store.path.write_text("not.a.valid.token", encoding="ascii")
        status = self.store.status(INSTALLATION_ID)
        self.assertFalse(status["active"])
        self.assertEqual(status["plan_id"], "free")
        self.assertIn("format", status["error"])


if __name__ == "__main__":
    unittest.main()
