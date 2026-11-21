"""Vendor control-plane tests for checkout, Stripe events and licence issuance."""
import hashlib
import hmac
import io
import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wifi_analyzer_backend.billing import PLAN_CATALOG
from wifi_analyzer_backend.license import verify_license_token
from wifi_analyzer_backend.licensing_service import (
    LicenseNotReady,
    LicenseServiceConflict,
    VendorLicenseService,
    vendor_public_key_text,
)


NOW = 1_800_000_000.0
INSTALLATION = "a" * 32
STRIPE_SECRET = "sk_test_vendor1234567890"
STRIPE_WEBHOOK_SECRET = "whsec_vendor_test_secret"


class VendorLicenseServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.now = [NOW]
        self.private_key = Ed25519PrivateKey.generate()
        self.price_plans = {
            "price_vendorpro1234": "pro",
            "price_vendorbusiness1234": "business",
            "price_vendorenterprise1234": "enterprise",
        }
        self.checkout_requests = []

        def opener(request, timeout):
            self.checkout_requests.append((request, timeout))
            return io.BytesIO(json.dumps({
                "id": "cs_test_123456789",
                "url": "https://checkout.stripe.com/c/pay/cs_test_123456789",
            }).encode())

        self.service = VendorLicenseService(
            str(Path(self.temp.name) / "vendor.sqlite3"),
            stripe_secret_key=STRIPE_SECRET,
            stripe_webhook_secret=STRIPE_WEBHOOK_SECRET,
            public_url="https://licenses.example.com",
            price_plans=self.price_plans,
            signing_private_key=self.private_key,
            key_id="test-key",
            clock=lambda: self.now[0],
            stripe_opener=opener,
        )

    def tearDown(self):
        self.temp.cleanup()

    def checkout(self, plan="business"):
        return self.service.create_checkout(
            installation_id=INSTALLATION,
            plan_id=plan,
            customer_email="customer@example.com",
        )

    def event(self, event_id, event_type, obj, *, created=None):
        return {
            "id": event_id,
            "type": event_type,
            "created": int(self.now[0] if created is None else created),
            "data": {"object": obj},
        }

    def checkout_completed(self, checkout):
        return self.event(
            "evt_checkout1234",
            "checkout.session.completed",
            {
                "id": checkout["checkout_session_id"],
                "mode": "subscription",
                "payment_status": "paid",
                "customer": "cus_vendor1234",
                "subscription": "sub_vendor1234",
                "client_reference_id": INSTALLATION,
                "metadata": {
                    "license_id": checkout["license_id"],
                    "installation_id": INSTALLATION,
                    "plan_id": "business",
                },
            },
        )

    def subscription_event(self, checkout, event_id, status="active", price="price_vendorbusiness1234", created=None):
        return self.event(
            event_id,
            "customer.subscription.updated",
            {
                "id": "sub_vendor1234",
                "customer": "cus_vendor1234",
                "status": status,
                "current_period_end": int(self.now[0] + 30 * 24 * 60 * 60),
                "cancel_at_period_end": False,
                "metadata": {
                    "license_id": checkout["license_id"],
                    "installation_id": INSTALLATION,
                    "plan_id": "business",
                },
                "items": {"data": [{"price": {"id": price}}]},
            },
            created=created,
        )

    def test_vendor_checkout_uses_vendor_price_and_private_secret_server_side(self):
        checkout = self.checkout()
        request, timeout = self.checkout_requests[0]
        fields = parse_qs(request.data.decode())
        self.assertEqual(request.full_url, "https://api.stripe.com/v1/checkout/sessions")
        self.assertEqual(request.get_header("Authorization"), f"Bearer {STRIPE_SECRET}")
        self.assertEqual(fields["line_items[0][price]"], ["price_vendorbusiness1234"])
        self.assertEqual(fields["metadata[license_id]"], [checkout["license_id"]])
        self.assertEqual(fields["metadata[installation_id]"], [INSTALLATION])
        self.assertEqual(fields["subscription_data[metadata][license_id]"], [checkout["license_id"]])
        self.assertTrue(checkout["checkout_url"].startswith("https://checkout.stripe.com/"))
        self.assertEqual(timeout, 12)
        self.assertEqual(len(checkout["activation_secret"]), 43)

    def test_invalid_plan_installation_and_email_are_rejected(self):
        with self.assertRaises(ValueError):
            self.service.create_checkout(installation_id=INSTALLATION, plan_id="free")
        with self.assertRaises(ValueError):
            self.service.create_checkout(installation_id="bad-install", plan_id="pro")
        with self.assertRaises(ValueError):
            self.service.create_checkout(
                installation_id=INSTALLATION, plan_id="pro", customer_email="not-an-email",
            )

    def test_active_vendor_subscription_prevents_second_checkout(self):
        checkout = self.checkout()
        self.service.process_event(self.checkout_completed(checkout))
        self.service.process_event(self.subscription_event(checkout, "evt_active1234"))
        with self.assertRaises(LicenseServiceConflict):
            self.checkout("pro")

    def test_checkout_and_subscription_webhooks_issue_installation_bound_token(self):
        checkout = self.checkout()
        self.service.process_event(self.checkout_completed(checkout))
        self.service.process_event(self.subscription_event(checkout, "evt_active1234"))
        issued = self.service.claim_license(
            installation_id=INSTALLATION,
            checkout_session_id=checkout["checkout_session_id"],
            activation_secret=checkout["activation_secret"],
        )
        public = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        verified = verify_license_token(
            issued["license_token"],
            public_keys={"test-key": public},
            expected_installation_id=INSTALLATION,
            now=self.now[0],
        )
        self.assertEqual(verified["plan_id"], "business")
        self.assertEqual(verified["offline_grace_seconds"], 6 * 60 * 60)
        self.assertEqual(issued["license_id"], checkout["license_id"])

    def test_claim_before_payment_confirmation_and_wrong_activation_secret_fail(self):
        checkout = self.checkout()
        with self.assertRaises(LicenseNotReady):
            self.service.claim_license(
                installation_id=INSTALLATION,
                checkout_session_id=checkout["checkout_session_id"],
                activation_secret=checkout["activation_secret"],
            )
        self.service.process_event(self.checkout_completed(checkout))
        self.service.process_event(self.subscription_event(checkout, "evt_active1234"))
        with self.assertRaisesRegex(Exception, "credential is invalid"):
            self.service.claim_license(
                installation_id=INSTALLATION,
                checkout_session_id=checkout["checkout_session_id"],
                activation_secret="wrong-secret-value-that-is-long-enough",
            )

    def test_refresh_renews_same_license_and_checks_subscription_state(self):
        checkout = self.checkout()
        self.service.process_event(self.checkout_completed(checkout))
        self.service.process_event(self.subscription_event(checkout, "evt_active1234"))
        first = self.service.claim_license(
            installation_id=INSTALLATION,
            checkout_session_id=checkout["checkout_session_id"],
            activation_secret=checkout["activation_secret"],
        )
        self.now[0] += 3600
        second = self.service.refresh_license(
            installation_id=INSTALLATION,
            license_id=checkout["license_id"],
            activation_secret=checkout["activation_secret"],
        )
        self.assertEqual(second["license_id"], first["license_id"])
        self.assertGreater(second["expires_at"], first["expires_at"])
        with self.assertRaises(LicenseNotReady):
            self.service.refresh_license(
                installation_id="b" * 32,
                license_id=checkout["license_id"],
                activation_secret=checkout["activation_secret"],
            )

    def test_past_due_grace_is_bounded_and_does_not_reset_on_repeated_events(self):
        checkout = self.checkout()
        self.service.process_event(self.checkout_completed(checkout))
        first = self.subscription_event(checkout, "evt_pastdue1234", status="past_due")
        self.service.process_event(first)
        self.now[0] += 24 * 60 * 60
        repeated = self.subscription_event(checkout, "evt_pastdue5678", status="past_due")
        self.service.process_event(repeated)
        self.assertTrue(self.service.refresh_license(
            installation_id=INSTALLATION,
            license_id=checkout["license_id"],
            activation_secret=checkout["activation_secret"],
        )["license_token"])
        self.now[0] += 49 * 60 * 60
        with self.assertRaises(LicenseNotReady):
            self.service.refresh_license(
                installation_id=INSTALLATION,
                license_id=checkout["license_id"],
                activation_secret=checkout["activation_secret"],
            )

    def test_cancelled_or_unpaid_subscription_revokes_product_access(self):
        checkout = self.checkout()
        self.service.process_event(self.checkout_completed(checkout))
        self.service.process_event(self.subscription_event(checkout, "evt_active1234"))
        cancelled = self.subscription_event(checkout, "evt_cancel1234", status="canceled")
        cancelled["type"] = "customer.subscription.deleted"
        self.service.process_event(cancelled)
        with self.assertRaises(LicenseNotReady):
            self.service.refresh_license(
                installation_id=INSTALLATION,
                license_id=checkout["license_id"],
                activation_secret=checkout["activation_secret"],
            )

    def test_duplicate_and_out_of_order_events_cannot_restore_cancelled_plan(self):
        checkout = self.checkout()
        self.service.process_event(self.checkout_completed(checkout))
        active = self.subscription_event(checkout, "evt_active1234", created=NOW + 10)
        self.service.process_event(active)
        duplicate = self.service.process_event(active)
        self.assertTrue(duplicate["duplicate"])
        cancelled = self.subscription_event(checkout, "evt_cancel1234", status="canceled", created=NOW + 20)
        cancelled["type"] = "customer.subscription.deleted"
        self.service.process_event(cancelled)
        stale = self.subscription_event(checkout, "evt_stale1234", status="active", created=NOW + 15)
        result = self.service.process_event(stale)
        self.assertTrue(result["stale"])
        with self.assertRaises(LicenseNotReady):
            self.service.refresh_license(
                installation_id=INSTALLATION,
                license_id=checkout["license_id"],
                activation_secret=checkout["activation_secret"],
            )

    def test_signed_stripe_webhook_is_verified_and_replay_protected(self):
        checkout = self.checkout()
        event = self.checkout_completed(checkout)
        raw = json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
        timestamp = int(self.now[0])
        signature = hmac.new(
            STRIPE_WEBHOOK_SECRET.encode(),
            str(timestamp).encode() + b"." + raw,
            hashlib.sha256,
        ).hexdigest()
        result = self.service.receive_webhook(raw, f"t={timestamp},v1={signature}")
        self.assertFalse(result["duplicate"])
        duplicate = self.service.receive_webhook(raw, f"t={timestamp},v1={signature}")
        self.assertTrue(duplicate["duplicate"])
        with self.assertRaises(Exception):
            self.service.receive_webhook(raw, f"t={timestamp},v1={'0' * 64}")

    def test_public_key_exposes_only_verification_key_not_private_material(self):
        result = self.service.public_key()
        self.assertEqual(result["key_id"], "test-key")
        self.assertEqual(len(result["public_key"]), 44)
        self.assertNotIn("private", json.dumps(result))

    def test_activation_secret_is_stored_as_a_hash_not_plaintext(self):
        checkout = self.checkout()
        with sqlite3.connect(self.service.path) as connection:
            stored = connection.execute(
                "SELECT activation_secret_hash FROM vendor_licenses WHERE license_id=?",
                (checkout["license_id"],),
            ).fetchone()[0]
        self.assertEqual(stored, hashlib.sha256(checkout["activation_secret"].encode()).hexdigest())
        self.assertNotEqual(stored, checkout["activation_secret"])


if __name__ == "__main__":
    unittest.main()
