"""Tests for short-lived live-stream tickets and bounded site-scoped fan-out."""
from __future__ import annotations

import json
import queue
import unittest
from unittest.mock import patch

from wifi_analyzer_backend.live_stream import (
    LiveStreamCapacityError,
    LiveStreamHub,
    MAX_QUEUED_EVENTS_PER_CLIENT,
)


class LiveStreamHubTests(unittest.TestCase):
    def setUp(self):
        self.hub = LiveStreamHub(ticket_ttl_seconds=10, max_tickets=4, max_connections=3, max_connections_per_user=2)

    def ticket(self, *, user="user-1", token="session-secret", sites=None, now=100.0):
        return self.hub.issue_ticket(
            user_id=user,
            session_token=token,
            site_ids=sites or ["office"],
            now=now,
        )

    def test_ticket_is_random_short_lived_and_consumed_exactly_once(self):
        created = self.ticket()
        self.assertEqual(created["expires_in_seconds"], 10)
        self.assertEqual(created["site_ids"], ["office"])
        self.assertEqual(created["websocket_url"], "/ws/live")
        self.assertTrue(created["websocket_protocol"].startswith("wfa-ticket."))
        self.assertNotIn("session-secret", created["websocket_protocol"])
        self.assertIsNotNone(self.hub.consume_ticket(created["ticket"], now=109.9))
        self.assertIsNone(self.hub.consume_ticket(created["ticket"], now=109.9))

    def test_expired_ticket_cannot_be_consumed(self):
        created = self.ticket()
        self.assertIsNone(self.hub.consume_ticket(created["ticket"], now=110.0))
        self.assertEqual(self.hub.ticket_count, 0)

    def test_site_scope_is_enforced_for_live_event_fanout(self):
        office = self.ticket(user="office-user", sites=["office"])
        branch = self.ticket(user="branch-user", sites=["branch"])
        _, office_client = self.hub.register(self.hub.consume_ticket(office["ticket"], now=100.0))
        _, branch_client = self.hub.register(self.hub.consume_ticket(branch["ticket"], now=100.0))

        sent = self.hub.publish("scan.updated", "office", {"network_count": 7})
        self.assertEqual(sent["queued_count"], 1)
        self.assertEqual(sent["slow_consumer_count"], 0)
        event = json.loads(office_client.events.get_nowait())
        self.assertEqual(event["type"], "scan.updated")
        self.assertEqual(event["site_id"], "office")
        self.assertEqual(event["data"]["network_count"], 7)
        self.assertTrue(branch_client.events.empty())

    def test_ticket_rejects_invalid_or_duplicate_sites_and_non_session_credentials(self):
        with self.assertRaisesRegex(ValueError, "session token"):
            self.hub.issue_ticket(user_id="u", session_token="", site_ids=["office"])
        with self.assertRaisesRegex(ValueError, "unique"):
            self.hub.issue_ticket(user_id="u", session_token="secret", site_ids=["office", "office"])
        with self.assertRaisesRegex(ValueError, "valid"):
            self.hub.issue_ticket(user_id="u", session_token="secret", site_ids=["office/../branch"])
        with self.assertRaisesRegex(ValueError, "no more than"):
            self.hub.issue_ticket(
                user_id="u", session_token="secret",
                site_ids=[f"site-{index}" for index in range(101)],
            )

    def test_connection_capacity_and_per_user_limits_are_enforced(self):
        first = self.ticket(user="user-1")
        second = self.ticket(user="user-1", sites=["office"])
        third = self.ticket(user="user-1", sites=["branch"])
        self.hub.register(self.hub.consume_ticket(first["ticket"], now=100.0))
        self.hub.register(self.hub.consume_ticket(second["ticket"], now=100.0))
        with self.assertRaisesRegex(LiveStreamCapacityError, "user"):
            self.hub.register(self.hub.consume_ticket(third["ticket"], now=100.0))
        self.assertEqual(self.hub.connection_count, 2)

    def test_slow_consumer_is_closed_instead_of_building_an_unbounded_queue(self):
        created = self.ticket()
        _, client = self.hub.register(self.hub.consume_ticket(created["ticket"], now=100.0))
        for index in range(MAX_QUEUED_EVENTS_PER_CLIENT):
            result = self.hub.publish("scan.updated", "office", {"index": index})
            self.assertEqual(result["queued_count"], 1)
        overflow = self.hub.publish("scan.updated", "office", {"overflow": True})
        self.assertEqual(overflow["slow_consumer_count"], 1)
        self.assertTrue(client.closed.is_set())
        self.assertEqual(client.events.qsize(), MAX_QUEUED_EVENTS_PER_CLIENT)

    def test_event_payload_must_be_finite_json_and_bounded(self):
        with self.assertRaisesRegex(ValueError, "finite JSON"):
            self.hub.publish("scan.updated", "office", {"value": float("nan")})
        with self.assertRaisesRegex(ValueError, "exceeds"):
            self.hub.publish("scan.updated", "office", {"payload": "x" * 20_000})
        with self.assertRaisesRegex(ValueError, "event_type"):
            self.hub.publish("BAD EVENT", "office", {})

    def test_unregister_and_close_all_signal_client_threads(self):
        one = self.ticket(user="one")
        two = self.ticket(user="two")
        id_one, client_one = self.hub.register(self.hub.consume_ticket(one["ticket"], now=100.0))
        _, client_two = self.hub.register(self.hub.consume_ticket(two["ticket"], now=100.0))
        self.hub.unregister(id_one)
        self.assertTrue(client_one.closed.is_set())
        self.assertFalse(client_two.closed.is_set())
        self.hub.close_all()
        self.assertTrue(client_two.closed.is_set())
        self.assertEqual(self.hub.connection_count, 0)
        self.assertEqual(self.hub.ticket_count, 0)


if __name__ == "__main__":
    unittest.main()
