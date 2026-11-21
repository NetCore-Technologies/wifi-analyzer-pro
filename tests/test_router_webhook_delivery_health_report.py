"""Tests for F193 metadata-only webhook delivery health reporting."""
from __future__ import annotations

import unittest

from wifi_analyzer_backend.feature_plugins.feature_193_router_webhook_delivery_health_report import run


NOW = "2026-11-21T10:00:00Z"


def delivery(
    delivery_id=1,
    *,
    subscription_id="office-alerts",
    site_ids=None,
    status="pending",
    attempts=0,
    response_status=None,
    last_error_code=None,
    delivered_at=None,
    created_at="2026-11-21T09:00:00Z",
):
    return {
        "id": delivery_id,
        "subscription_id": subscription_id,
        "event_count": 3,
        "site_ids": ["office"] if site_ids is None else site_ids,
        "has_unscoped_events": False,
        "status": status,
        "attempts": attempts,
        "max_attempts": 6,
        "last_error_code": last_error_code,
        "response_status": response_status,
        "created_at": created_at,
        "updated_at": delivered_at or NOW,
        "delivered_at": delivered_at,
    }


class WebhookDeliveryHealthReportTests(unittest.TestCase):
    def test_empty_window_is_explicit_and_does_not_invent_rates(self):
        result = run({"now": NOW, "window_days": 7, "deliveries": []})
        self.assertEqual(result["feature"], "F193")
        self.assertEqual(result["summary"]["total_deliveries"], 0)
        self.assertIsNone(result["summary"]["success_rate_pct"])
        self.assertEqual(result["by_site"], [])
        self.assertTrue(result["recommendations"])

    def test_summarises_delivery_success_retry_latency_and_failure_codes(self):
        records = [
            delivery(1, status="delivered", attempts=2, response_status=204,
                     delivered_at="2026-11-21T09:00:04Z"),
            delivery(2, site_ids=["branch"], subscription_id="branch-alerts",
                     status="dead_letter", attempts=6, last_error_code="delivery_http_error"),
            delivery(3, status="retry_wait", attempts=3, last_error_code="delivery_timeout"),
            delivery(4, status="pending", attempts=0),
        ]
        result = run({"now": NOW, "window_days": 7, "deliveries": records})
        summary = result["summary"]
        self.assertEqual(summary["total_deliveries"], 4)
        self.assertEqual(summary["total_events"], 12)
        self.assertEqual(summary["counts_by_status"]["delivered"], 1)
        self.assertEqual(summary["counts_by_status"]["dead_letter"], 1)
        self.assertEqual(summary["success_rate_pct"], 50.0)
        self.assertEqual(summary["retry_delivery_count"], 3)
        self.assertEqual(summary["average_delivery_latency_seconds"], 4.0)
        self.assertEqual(summary["response_statuses"], {"204": 1})
        self.assertEqual(result["failure_codes"], [
            {"code": "delivery_http_error", "count": 1},
            {"code": "delivery_timeout", "count": 1},
        ])
        self.assertEqual({item["site_id"] for item in result["by_site"]}, {"office", "branch"})
        self.assertNotIn("body", str(result))
        self.assertNotIn("headers", str(result))
        self.assertNotIn("endpoint", str(result))

    def test_per_subscription_aggregation_and_event_counts(self):
        records = [
            delivery(1, subscription_id="office-alerts", status="delivered",
                     delivered_at="2026-11-21T09:00:02Z", response_status=200),
            delivery(2, subscription_id="office-alerts", status="dead_letter",
                     attempts=6, last_error_code="delivery_http_error"),
            delivery(3, subscription_id="branch-alerts", site_ids=["branch"], status="pending"),
        ]
        result = run({"now": NOW, "window_days": 7, "deliveries": records})
        office = next(item for item in result["by_subscription"] if item["subscription_id"] == "office-alerts")
        self.assertEqual(office["delivery_count"], 2)
        self.assertEqual(office["event_count"], 6)
        self.assertEqual(office["delivered_count"], 1)
        self.assertEqual(office["dead_letter_count"], 1)

    def test_rejects_invalid_status_timestamps_and_limits(self):
        invalid = delivery(status="unknown")
        with self.assertRaisesRegex(ValueError, "status"):
            run({"now": NOW, "window_days": 7, "deliveries": [invalid]})
        invalid = delivery(created_at="2026-11-21T09:00:00")
        with self.assertRaisesRegex(ValueError, "timezone"):
            run({"now": NOW, "window_days": 7, "deliveries": [invalid]})
        with self.assertRaises(ValueError):
            run({"now": NOW, "window_days": 91, "deliveries": []})
        with self.assertRaises(ValueError):
            run({"now": NOW, "window_days": 7, "deliveries": [delivery()] * 5001})


if __name__ == "__main__":
    unittest.main()
