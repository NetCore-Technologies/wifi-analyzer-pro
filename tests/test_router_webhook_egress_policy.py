"""Tests for webhook egress allowlists, DNS pinning and TLS evidence."""
from __future__ import annotations

import unittest

from wifi_analyzer_backend.feature_plugins.feature_187_router_webhook_egress_policy_verifier import run


NOW = "2026-11-20T10:00:00Z"


def valid_payload():
    return {
        "endpoint": "https://hooks.example.net/router/events",
        "allowed_hosts": ["hooks.example.net"],
        "resolution_at": "2026-11-20T09:59:55Z",
        "connected_at": NOW,
        "resolved_addresses": ["1.1.1.1", "2606:4700:4700::1111"],
        "peer_ip": "1.1.1.1",
        "connected_port": 443,
        "tls_version": "TLSv1.3",
        "tls_verified": True,
        "hostname_verified": True,
        "redirect_location": None,
    }


class RouterWebhookEgressPolicyVerifierTests(unittest.TestCase):
    def test_approves_public_pinned_peer_with_recent_dns_and_verified_tls(self):
        result = run(valid_payload())
        self.assertEqual(result["status"], "approved")
        self.assertTrue(result["approved"])
        self.assertEqual(result["hostname"], "hooks.example.net")
        self.assertEqual(result["connected_peer_ip"], "1.1.1.1")
        self.assertEqual(result["connection_policy"]["connect_to_exact_peer_ip"], "1.1.1.1")
        self.assertEqual(result["connection_policy"]["tls_server_name"], "hooks.example.net")
        self.assertFalse(result["connection_policy"]["follow_redirects"])
        self.assertEqual(result["reasons"], [])

    def test_approves_public_ipv6_peer_and_keeps_original_hostname_for_tls(self):
        payload = valid_payload()
        payload["peer_ip"] = "2606:4700:4700::1111"
        payload["connected_port"] = 443
        result = run(payload)
        self.assertTrue(result["approved"])
        self.assertEqual(result["connected_peer_ip"], "2606:4700:4700::1111")
        self.assertEqual(result["connection_policy"]["tls_server_name"], "hooks.example.net")

    def test_blocks_private_loopback_link_local_reserved_and_multicast_dns_answers(self):
        for address in (
            "10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1",
            "169.254.1.1", "0.0.0.0", "224.0.0.1", "100.64.0.1",
            "::1", "fc00::1", "fe80::1", "ff02::1", "2001:db8::1",
        ):
            with self.subTest(address=address):
                payload = valid_payload()
                payload["resolved_addresses"] = [address]
                payload["peer_ip"] = address
                result = run(payload)
                self.assertFalse(result["approved"])
                self.assertIn("connected_peer_is_not_public", result["reasons"])
                self.assertTrue(any(reason.startswith("non_public_dns_address:") for reason in result["reasons"]))

    def test_blocks_peer_ip_not_present_in_resolver_answer(self):
        payload = valid_payload()
        payload["peer_ip"] = "8.8.8.8"
        result = run(payload)
        self.assertFalse(result["approved"])
        self.assertIn("connected_peer_not_in_resolved_address_set", result["reasons"])

    def test_blocks_stale_or_future_dns_resolution_evidence(self):
        stale = valid_payload()
        stale["resolution_at"] = "2026-11-20T09:58:00Z"
        result = run(stale)
        self.assertFalse(result["approved"])
        self.assertIn("dns_resolution_too_old", result["reasons"])
        future = valid_payload()
        future["resolution_at"] = "2026-11-20T10:00:05Z"
        result = run(future)
        self.assertFalse(result["approved"])
        self.assertIn("connection_time_precedes_dns_resolution", result["reasons"])

    def test_blocks_unverified_tls_hostname_or_redirect(self):
        for change, expected in (
            ({"tls_verified": False}, "tls_certificate_verification_failed"),
            ({"hostname_verified": False}, "tls_hostname_verification_failed"),
            ({"redirect_location": "https://other.example.net/steal"}, "redirect_refused"),
            ({"connected_port": 8443}, "connected_port_is_not_443"),
        ):
            with self.subTest(change=change):
                payload = {**valid_payload(), **change}
                result = run(payload)
                self.assertFalse(result["approved"])
                self.assertIn(expected, result["reasons"])

    def test_uses_exact_dns_host_allowlist_and_normalizes_idna(self):
        with self.assertRaisesRegex(ValueError, "exact host allowlist"):
            payload = valid_payload()
            payload["endpoint"] = "https://hooks.example.net.attacker.test/events"
            run(payload)
        with self.assertRaisesRegex(ValueError, "exact host allowlist"):
            payload = valid_payload()
            payload["endpoint"] = "https://other.example.net/events"
            run(payload)
        idna = valid_payload()
        idna["endpoint"] = "https://xn--bcher-kva.example/events"
        idna["allowed_hosts"] = ["bücher.example"]
        result = run(idna)
        self.assertTrue(result["approved"])
        self.assertEqual(result["hostname"], "xn--bcher-kva.example")

    def test_rejects_non_https_credentials_queries_fragments_and_ip_literal_endpoints(self):
        for endpoint, message in (
            ("http://hooks.example.net/events", "HTTPS"),
            ("https://user@hooks.example.net/events", "embedded credentials"),
            ("https://hooks.example.net/events?x=1", "query string"),
            ("https://hooks.example.net/events#fragment", "query string or fragment"),
            ("https://127.0.0.1/events", "DNS hostname"),
            ("https://hooks.example.net:8443/events", "port 443"),
        ):
            with self.subTest(endpoint=endpoint), self.assertRaisesRegex(ValueError, message):
                run({**valid_payload(), "endpoint": endpoint})

    def test_rejects_duplicate_or_invalid_resolver_records(self):
        payload = valid_payload()
        payload["resolved_addresses"] = ["1.1.1.1", "1.1.1.1"]
        with self.assertRaisesRegex(ValueError, "must not contain duplicates"):
            run(payload)
        payload = valid_payload()
        payload["resolved_addresses"] = ["not-an-ip"]
        with self.assertRaisesRegex(ValueError, "valid IP address"):
            run(payload)

    def test_rejects_bad_timestamp_tls_fields_ports_and_limits(self):
        for change, message in (
            ({"resolution_at": "2026-11-20T09:00:00"}, "timezone offset"),
            ({"tls_version": "SSLv3"}, "TLSv1.2 or TLSv1.3"),
            ({"tls_verified": "yes"}, "must be booleans"),
            ({"connected_port": 0}, "connected_port"),
            ({"max_dns_age_seconds": 61}, "from 1 to 60"),
            ({"resolved_addresses": []}, "from 1 to 32"),
        ):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, message):
                run({**valid_payload(), **change})

    def test_rejects_oversized_or_non_finite_input(self):
        with self.assertRaisesRegex(ValueError, "finite values"):
            run({**valid_payload(), "metadata": float("nan")})
        with self.assertRaisesRegex(ValueError, "byte input limit"):
            run({**valid_payload(), "metadata": "x" * (64 * 1024)})


if __name__ == "__main__":
    unittest.main()
