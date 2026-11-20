"""Verify webhook egress evidence before a dispatcher accepts a delivery connection.

This feature makes no network requests. A dispatcher must resolve DNS, connect to the exact
validated peer IP, verify TLS using the original DNS hostname, and refuse redirects.
"""
from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

MAX_INPUT_BYTES = 64 * 1024
MAX_ADDRESSES = 32
MAX_HOSTS = 50
MAX_DNS_AGE_SECONDS = 60
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _timestamp(value: object, field: str):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone offset")
    return parsed.astimezone(timezone.utc)


def _hostname(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ValueError(f"{field} must be a DNS hostname")
    candidate = value.rstrip(".").lower()
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise ValueError(f"{field} must be a valid IDNA DNS hostname") from error
    if not candidate or len(candidate) > 253 or "." not in candidate:
        raise ValueError(f"{field} must be a fully-qualified DNS hostname")
    if any(not HOST_LABEL.fullmatch(label) for label in candidate.split(".")):
        raise ValueError(f"{field} is not a valid DNS hostname")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return candidate
    raise ValueError(f"{field} must be a DNS hostname, not an IP literal")


def _ip(value: object, field: str):
    if not isinstance(value, str) or not value or len(value) > 64 or "%" in value:
        raise ValueError(f"{field} must be an unscoped IP address")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise ValueError(f"{field} must be a valid IP address") from error
    return address


def _endpoint(value: object, allowed_hosts: set[str]) -> tuple[str, str]:
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError("endpoint must be an HTTPS URL of at most 2048 characters")
    if any(ord(char) < 32 or ord(char) == 127 or char == "\\" for char in value):
        raise ValueError("endpoint contains invalid control characters or backslashes")
    if "?" in value or "#" in value:
        raise ValueError("endpoint must not contain a query string or fragment")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise ValueError("endpoint must be a valid HTTPS URL") from error
    if parsed.scheme.lower() != "https" or not parsed.netloc or hostname is None:
        raise ValueError("endpoint must use HTTPS and contain a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("endpoint must not contain embedded credentials")
    if port not in (None, 443):
        raise ValueError("endpoint must use HTTPS port 443")
    host = _hostname(hostname, "endpoint.hostname")
    if host not in allowed_hosts:
        raise ValueError("endpoint hostname is not present in the exact host allowlist")
    path = parsed.path or "/"
    if not path.startswith("/") or path.startswith("//"):
        raise ValueError("endpoint path must be absolute")
    return host, f"https://{host}{path}"


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    try:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError("egress verification input must contain JSON-compatible finite values") from error
    if len(encoded) > MAX_INPUT_BYTES:
        raise ValueError(f"egress verification input exceeds the {MAX_INPUT_BYTES}-byte input limit")

    allowed_raw = payload.get("allowed_hosts")
    if not isinstance(allowed_raw, list) or not 1 <= len(allowed_raw) <= MAX_HOSTS:
        raise ValueError(f"allowed_hosts must contain from 1 to {MAX_HOSTS} DNS hostnames")
    allowed_hosts = [_hostname(item, f"allowed_hosts[{index}]") for index, item in enumerate(allowed_raw)]
    if len(allowed_hosts) != len(set(allowed_hosts)):
        raise ValueError("allowed_hosts entries must be unique")
    host, endpoint = _endpoint(payload.get("endpoint"), set(allowed_hosts))

    resolution_at = _timestamp(payload.get("resolution_at"), "resolution_at")
    connected_at = _timestamp(payload.get("connected_at"), "connected_at")
    max_dns_age = payload.get("max_dns_age_seconds", 15)
    if isinstance(max_dns_age, bool) or not isinstance(max_dns_age, int) or not 1 <= max_dns_age <= MAX_DNS_AGE_SECONDS:
        raise ValueError(f"max_dns_age_seconds must be an integer from 1 to {MAX_DNS_AGE_SECONDS}")
    age = (connected_at - resolution_at).total_seconds()

    resolved_raw = payload.get("resolved_addresses")
    if not isinstance(resolved_raw, list) or not 1 <= len(resolved_raw) <= MAX_ADDRESSES:
        raise ValueError(f"resolved_addresses must contain from 1 to {MAX_ADDRESSES} IP addresses")
    resolved = [_ip(item, f"resolved_addresses[{index}]") for index, item in enumerate(resolved_raw)]
    normalized_resolved = [str(item) for item in resolved]
    if len(normalized_resolved) != len(set(normalized_resolved)):
        raise ValueError("resolved_addresses must not contain duplicates")
    peer = _ip(payload.get("peer_ip"), "peer_ip")

    connected_port = payload.get("connected_port")
    if isinstance(connected_port, bool) or not isinstance(connected_port, int) or not 1 <= connected_port <= 65535:
        raise ValueError("connected_port must be an integer from 1 to 65535")
    tls_version = payload.get("tls_version")
    if not isinstance(tls_version, str) or tls_version not in {"TLSv1.2", "TLSv1.3"}:
        raise ValueError("tls_version must be TLSv1.2 or TLSv1.3")
    tls_verified = payload.get("tls_verified")
    hostname_verified = payload.get("hostname_verified")
    if not isinstance(tls_verified, bool) or not isinstance(hostname_verified, bool):
        raise ValueError("tls_verified and hostname_verified must be booleans")
    redirect_location = payload.get("redirect_location")
    if redirect_location is not None and (
        not isinstance(redirect_location, str) or len(redirect_location) > 2048
    ):
        raise ValueError("redirect_location must be null or a bounded string")

    reasons = []
    if age < 0:
        reasons.append("connection_time_precedes_dns_resolution")
    elif age > max_dns_age:
        reasons.append("dns_resolution_too_old")
    for address in resolved:
        effective = address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) else address
        if not effective.is_global or effective.is_multicast or effective.is_reserved:
            reasons.append(f"non_public_dns_address:{address}")
    if peer not in resolved:
        reasons.append("connected_peer_not_in_resolved_address_set")
    effective_peer = peer.ipv4_mapped if isinstance(peer, ipaddress.IPv6Address) else peer
    if not effective_peer.is_global or effective_peer.is_multicast or effective_peer.is_reserved:
        reasons.append("connected_peer_is_not_public")
    if connected_port != 443:
        reasons.append("connected_port_is_not_443")
    if not tls_verified:
        reasons.append("tls_certificate_verification_failed")
    if not hostname_verified:
        reasons.append("tls_hostname_verification_failed")
    if redirect_location is not None:
        reasons.append("redirect_refused")

    approved = not reasons
    return {
        "status": "approved" if approved else "blocked",
        "approved": approved,
        "endpoint": endpoint,
        "hostname": host,
        "connected_peer_ip": str(peer),
        "connected_port": connected_port,
        "tls_version": tls_version,
        "dns_resolution_age_seconds": round(age, 3),
        "resolved_addresses": sorted(normalized_resolved),
        "reasons": sorted(set(reasons)),
        "connection_policy": {
            "connect_to_exact_peer_ip": str(peer) if approved else None,
            "tls_server_name": host if approved else None,
            "follow_redirects": False,
            "required_tls_versions": ["TLSv1.2", "TLSv1.3"],
        },
        "note": (
            "This is an evidence verifier, not a network client. A dispatcher must independently enforce the "
            "returned pin by connecting to the exact peer IP while retaining the DNS hostname for TLS SNI and "
            "certificate validation. Re-resolve and revalidate on every attempt; never follow redirects."
        ),
    }


FEATURE = {
    "id": "F187",
    "slug": "router_webhook_egress_policy_verifier",
    "name": "Webhook egress and DNS-pinning policy verifier",
    "category": "Router operations",
    "description": (
        "Validate allow-listed HTTPS webhook connection evidence, reject non-public or stale DNS answers, "
        "verify the connected peer IP is pinned to the resolved set, require TLS verification and refuse redirects."
    ),
    "parameters": {
        "endpoint": "HTTPS endpoint on an exact allow-listed DNS hostname",
        "allowed_hosts": "1 to 50 fully-qualified DNS hostnames",
        "resolution_at": "timezone-aware timestamp when DNS was resolved",
        "connected_at": "timezone-aware timestamp when the socket connection was established",
        "resolved_addresses": "1 to 32 IP addresses returned by the trusted resolver",
        "peer_ip": "actual connected socket peer address",
        "connected_port": "actual destination port",
        "tls_version": "TLSv1.2 or TLSv1.3",
        "tls_verified": "whether certificate-chain verification passed",
        "hostname_verified": "whether SAN/hostname validation passed",
        "redirect_location": "must be null; redirects are refused",
    },
    "run": run,
}
