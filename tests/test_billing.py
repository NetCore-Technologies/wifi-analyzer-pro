"""Tests for Stripe signature verification, subscription state and quota enforcement."""
import hashlib
import hmac
import io
import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs

from wifi_analyzer_backend.billing import (
    PLAN_CATALOG,
    StripeApiError,
    StripeSignatureError,
    WorkspaceBillingStore,
    create_billing_portal_session,
    create_checkout_session,
    verify_stripe_signature,
)


SECRET = "whsec_test_signing_secret"


def make_event(event_id, event_type, obj):
    return {
        "id": event_id,
        "type": event_type,
        "data": {"object": obj},
    }


def signed_payload(event, *, timestamp=1_800_000_000, secret=SECRET):
    payload = json.dumps(event, separators=(",", ":"), sort_keys=True).encode()
    signed = str(timestamp).encode() + b"." + payload
    signature = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return payload, f"t={timestamp},v1={signature}"


class StripeSignatureTests(unittest.TestCase):
    def test_valid_timestamped_signature_is_verified_before_json_is_returned(self):
        event = make_event("evt_123456", "customer.subscription.updated", {"id": "sub_123456"})
        payload, header = signed_payload(event)
        result = verify_stripe_signature(payload, header, SECRET, now=1_800_000_001)
        self.assertEqual(result, event)

    def test_multiple_v1_signatures_are_supported_without_weakening_verification(self):
        event = make_event("evt_123456", "ignored", {})
        payload, header = signed_payload(event)
        _, valid = header.split(",")
        result = verify_stripe_signature(payload, f"t=1800000000,v1={'0' * 64},{valid}", SECRET, now=1_800_000_000)
        self.assertEqual(result["id"], "evt_123456")

    def test_wrong_secret_tampered_body_and_stale_timestamp_are_rejected(self):
        event = make_event("evt_123456", "ignored", {})
        payload, header = signed_payload(event)
        with self.assertRaises(StripeSignatureError):
            verify_stripe_signature(payload, header, "whsec_wrong_secret_value", now=1_800_000_000)
        with self.assertRaises(StripeSignatureError):
            verify_stripe_signature(payload + b" ", header, SECRET, now=1_800_000_000)
        with self.assertRaises(StripeSignatureError):
            verify_stripe_signature(payload, header, SECRET, now=1_800_001_000)

    def test_malformed_headers_missing_configuration_and_oversized_payload_fail_closed(self):
        with self.assertRaises(StripeSignatureError):
            verify_stripe_signature(b"{}", "v1=bad", SECRET, now=1_800_000_000)
        with self.assertRaises(StripeSignatureError):
            verify_stripe_signature(b"{}", "t=1,v1=" + "0" * 64, "", now=1)
        with self.assertRaises(StripeSignatureError):
            verify_stripe_signature(b"x" * (256 * 1024 + 1), "t=1,v1=" + "0" * 64, SECRET, now=1)

    def test_signed_non_json_and_non_object_payloads_are_rejected(self):
        payload = b"[]"
        timestamp = 1_800_000_000
        digest = hmac.new(SECRET.encode(), str(timestamp).encode() + b"." + payload, hashlib.sha256).hexdigest()
        with self.assertRaises(StripeSignatureError):
            verify_stripe_signature(payload, f"t={timestamp},v1={digest}", SECRET, now=timestamp)


class BillingStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.temp.name) / "billing.sqlite3")
        self.now = [1_800_000_000.0]
        self.store = WorkspaceBillingStore(self.path, clock=lambda: self.now[0])
        self.price_plans = {"price_pro1234": "pro", "price_business1234": "business"}

    def tearDown(self):
        self.temp.cleanup()

    def subscription_event(self, event_id, *, status="active", price="price_pro1234", workspace_id=None, period_end=None):
        instance_id = workspace_id if workspace_id is not None else self.store.instance_id()
        return make_event(
            event_id,
            "customer.subscription.updated",
            {
                "id": "sub_123456",
                "customer": "cus_123456",
                "status": status,
                "current_period_end": period_end or self.now[0] + 3600,
                "cancel_at_period_end": False,
                "metadata": {"workspace_id": instance_id},
                "items": {"data": [{"price": {"id": price}}]},
            },
        )

    def test_new_installation_starts_on_free_with_explicit_quotas(self):
        status = self.store.status()
        self.assertEqual(status["plan_id"], "free")
        self.assertFalse(status["active"])
        self.assertEqual(status["limits"], PLAN_CATALOG["free"]["limits"])
        self.assertEqual(self.store.capacity("agents", 0)["allowed"], True)
        denied = self.store.capacity("agents", 1)
        self.assertFalse(denied["allowed"])
        self.assertEqual(denied["limit"], 1)

    def test_free_monthly_diagnostic_allowance_is_atomic_and_resets_at_utc_month(self):
        for expected_used in range(1, 101):
            result = self.store.consume_monthly_feature_run()
            self.assertTrue(result["allowed"])
            self.assertEqual(result["used"], expected_used)
        blocked = self.store.consume_monthly_feature_run()
        self.assertFalse(blocked["allowed"])
        self.assertEqual(blocked["used"], 100)
        self.assertEqual(self.store.status()["monthly_usage"]["feature_runs"], 100)

        self.now[0] += 31 * 24 * 60 * 60
        reset = self.store.consume_monthly_feature_run()
        self.assertTrue(reset["allowed"])
        self.assertEqual(reset["used"], 1)

    def test_site_quota_is_present_on_each_plan(self):
        self.assertEqual(self.store.status()["limits"]["sites"], 1)
        self.assertEqual(self.store.capacity("sites", 0)["allowed"], True)
        self.assertFalse(self.store.capacity("sites", 1)["allowed"])

    def test_installation_identifier_is_stable_across_store_restarts(self):
        first = self.store.instance_id()
        restarted = WorkspaceBillingStore(self.path, clock=lambda: self.now[0])
        self.assertEqual(restarted.instance_id(), first)

    def test_active_subscription_unlocks_exact_plan_quotas(self):
        self.store.process_stripe_event(self.subscription_event("evt_123456"), price_plans=self.price_plans)
        status = self.store.status()
        self.assertTrue(status["active"])
        self.assertEqual(status["plan_id"], "pro")
        self.assertEqual(status["limits"]["agents"], 5)
        self.assertTrue(self.store.capacity("agents", 4)["allowed"])
        self.assertFalse(self.store.capacity("agents", 5)["allowed"])

    def test_duplicate_events_are_idempotent_and_do_not_extend_subscription(self):
        event = self.subscription_event("evt_123456")
        self.assertTrue(self.store.process_stripe_event(event, price_plans=self.price_plans))
        self.now[0] += 100
        self.assertFalse(self.store.process_stripe_event(event, price_plans=self.price_plans))
        self.assertEqual(self.store.status()["webhook_events_retained"], 1)
        self.assertEqual(
            self.store.status()["current_period_end"],
            "2027-01-15T09:00:00+00:00",
        )

    def test_subscription_from_another_workspace_is_ignored(self):
        other = self.subscription_event("evt_123456", workspace_id="f" * 32)
        self.store.process_stripe_event(other, price_plans=self.price_plans)
        self.assertEqual(self.store.status()["plan_id"], "free")
        self.assertIsNone(self.store.stripe_customer_id())

    def test_unknown_price_never_grants_a_paid_plan(self):
        event = self.subscription_event("evt_123456", price="price_unknown1234")
        self.store.process_stripe_event(event, price_plans=self.price_plans)
        self.assertEqual(self.store.status()["plan_id"], "free")
        self.assertFalse(self.store.status()["active"])

    def test_past_due_subscription_has_a_bounded_grace_period(self):
        event = self.subscription_event("evt_123456", status="past_due")
        self.store.process_stripe_event(event, price_plans=self.price_plans)
        self.assertTrue(self.store.status()["active"])
        self.assertTrue(self.store.status()["grace_period"])
        self.now[0] += 72 * 60 * 60 + 1
        self.assertFalse(self.store.status()["active"])
        self.assertEqual(self.store.status()["plan_id"], "free")

    def test_repeated_past_due_updates_do_not_extend_original_grace_period(self):
        first = self.subscription_event("evt_firstpastdue", status="past_due")
        first["created"] = int(self.now[0])
        self.store.process_stripe_event(first, price_plans=self.price_plans)
        original_end = self.store.status()["grace_period_ends_at"]

        self.now[0] += 24 * 60 * 60
        second = self.subscription_event("evt_secondpastdue", status="past_due")
        second["created"] = int(self.now[0])
        self.store.process_stripe_event(second, price_plans=self.price_plans)

        self.assertEqual(self.store.status()["grace_period_ends_at"], original_end)

    def test_out_of_order_subscription_events_cannot_restore_cancelled_access(self):
        active = self.subscription_event("evt_orderactive", status="active")
        active["created"] = int(self.now[0])
        self.store.process_stripe_event(active, price_plans=self.price_plans)

        cancelled = self.subscription_event("evt_ordercancel", status="canceled")
        cancelled["type"] = "customer.subscription.deleted"
        cancelled["created"] = int(self.now[0]) + 10
        self.store.process_stripe_event(cancelled, price_plans=self.price_plans)

        stale_active = self.subscription_event("evt_orderstale", status="active")
        stale_active["created"] = int(self.now[0]) + 5
        self.store.process_stripe_event(stale_active, price_plans=self.price_plans)

        self.assertFalse(self.store.status()["active"])
        self.assertEqual(self.store.status()["plan_id"], "free")
        self.assertEqual(self.store.status()["subscription_status"], "canceled")

    def test_expired_and_unpaid_subscriptions_revert_to_free(self):
        expired = self.subscription_event("evt_123456", period_end=self.now[0] - 1)
        self.store.process_stripe_event(expired, price_plans=self.price_plans)
        self.assertEqual(self.store.status()["plan_id"], "free")

        store = WorkspaceBillingStore(str(Path(self.temp.name) / "other.sqlite3"), clock=lambda: self.now[0])
        event = make_event(
            "evt_654321", "customer.subscription.updated",
            {
                "id": "sub_123456", "customer": "cus_123456", "status": "unpaid",
                "current_period_end": self.now[0] + 3600,
                "metadata": {"workspace_id": store.instance_id()},
                "items": {"data": [{"price": {"id": "price_pro1234"}}]},
            },
        )
        store.process_stripe_event(event, price_plans=self.price_plans)
        self.assertEqual(store.status()["plan_id"], "free")

    def test_cancelled_subscription_does_not_retain_paid_access(self):
        event = self.subscription_event("evt_123456", status="canceled")
        event["type"] = "customer.subscription.deleted"
        self.store.process_stripe_event(event, price_plans=self.price_plans)
        self.assertEqual(self.store.status()["plan_id"], "free")
        self.assertFalse(self.store.status()["active"])


class StripeCheckoutTests(unittest.TestCase):
    def setUp(self):
        self.requests = []

    def opener(self, request, timeout):
        self.requests.append((request, timeout))
        return io.BytesIO(json.dumps({
            "id": "cs_test_123456",
            "url": "https://checkout.stripe.com/c/pay/cs_test_123456",
        }).encode())

    def test_checkout_uses_server_price_and_workspace_metadata(self):
        result = create_checkout_session(
            secret_key="sk_test_1234567890",
            price_id="price_pro1234",
            instance_id="a" * 32,
            public_url="https://analyzer.example.com",
            opener=self.opener,
        )
        self.assertEqual(result["checkout_session_id"], "cs_test_123456")
        request, timeout = self.requests[0]
        self.assertEqual(request.full_url, "https://api.stripe.com/v1/checkout/sessions")
        self.assertEqual(request.get_header("Authorization"), "Bearer sk_test_1234567890")
        fields = parse_qs(request.data.decode())
        self.assertEqual(fields["line_items[0][price]"], ["price_pro1234"])
        self.assertEqual(fields["metadata[workspace_id]"], ["a" * 32])
        self.assertEqual(fields["subscription_data[metadata][workspace_id]"], ["a" * 32])
        self.assertEqual(timeout, 12)

    def test_checkout_rejects_untrusted_price_ids_and_non_https_public_origins(self):
        for kwargs in (
            {"price_id": "not-a-price"},
            {"public_url": "http://0.0.0.0:199"},
            {"public_url": "https://user:pass@example.com"},
            {"public_url": "https://example.com/path"},
        ):
            params = {
                "secret_key": "sk_test_1234567890",
                "price_id": "price_pro1234",
                "instance_id": "a" * 32,
                "public_url": "https://analyzer.example.com",
                "opener": self.opener,
            }
            params.update(kwargs)
            with self.assertRaises(ValueError):
                create_checkout_session(**params)

    def test_invalid_stripe_api_response_is_not_trusted(self):
        def bad_opener(request, timeout):
            return io.BytesIO(b'{"url":"https://evil.example.test/checkout"}')
        with self.assertRaises(StripeApiError):
            create_checkout_session(
                secret_key="sk_test_1234567890",
                price_id="price_pro1234",
                instance_id="a" * 32,
                public_url="https://analyzer.example.com",
                opener=bad_opener,
            )

    def test_billing_portal_uses_only_the_stored_customer_and_validated_return_url(self):
        def portal_opener(request, timeout):
            self.requests.append((request, timeout))
            return io.BytesIO(b'{"url":"https://billing.stripe.com/p/session_123456"}')
        result = create_billing_portal_session(
            secret_key="sk_test_1234567890",
            customer_id="cus_123456",
            public_url="https://analyzer.example.com",
            opener=portal_opener,
        )
        fields = parse_qs(self.requests[0][0].data.decode())
        self.assertEqual(fields["customer"], ["cus_123456"])
        self.assertEqual(fields["return_url"], ["https://analyzer.example.com/?billing=return"])
        self.assertEqual(result["url"], "https://billing.stripe.com/p/session_123456")


if __name__ == "__main__":
    unittest.main()
