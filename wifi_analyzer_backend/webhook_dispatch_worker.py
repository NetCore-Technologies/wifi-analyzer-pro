"""Opt-in worker for durable multi-subscription signed webhook delivery."""
from __future__ import annotations

import json
import os
import signal
import socket
import ssl
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit

if __package__:
    from .feature_plugins.feature_187_router_webhook_egress_policy_verifier import (
        run as verify_egress,
        _endpoint as validate_endpoint,
    )
    from .report_worker import (
        MAX_REQUEST_BYTES,
        MAX_RESPONSE_BYTES,
        _DeliveryFailure,
        _PinnedHTTPSConnection,
        _normalise_resolver_result,
        _resolve_public_addresses,
    )
    from .webhook_delivery_store import (
        WebhookDeliveryNotFoundError,
        WebhookDeliveryStore,
    )
else:  # Direct execution in the minimal runtime image.
    from feature_plugins.feature_187_router_webhook_egress_policy_verifier import (
        run as verify_egress,
        _endpoint as validate_endpoint,
    )
    from report_worker import (
        MAX_REQUEST_BYTES,
        MAX_RESPONSE_BYTES,
        _DeliveryFailure,
        _PinnedHTTPSConnection,
        _normalise_resolver_result,
        _resolve_public_addresses,
    )
    from webhook_delivery_store import (
        WebhookDeliveryNotFoundError,
        WebhookDeliveryStore,
    )


MAX_WORKER_BATCH = 20
SIGNED_HEADER_NAMES = {
    "Content-Type", "X-WiFiAnalyzer-Key-Id", "X-WiFiAnalyzer-Timestamp",
    "X-WiFiAnalyzer-Signature", "Idempotency-Key",
}


def _timestamp(value, field: str) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError(f"{field} must be a timezone-aware timestamp") from error
    else:
        raise ValueError(f"{field} must be a timezone-aware timestamp")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone offset")
    return parsed.astimezone(timezone.utc)


class WebhookDispatchWorker:
    """Claim durable prepared envelopes and transmit them over freshly pinned TLS sockets."""

    def __init__(
        self,
        store: WebhookDeliveryStore | None = None,
        worker_id: str | None = None,
        *,
        timeout_seconds: float = 8,
        lease_seconds: int = 120,
        resolver=None,
        connection_factory=None,
        clock=None,
    ):
        self.store = store or WebhookDeliveryStore()
        self.worker_id = worker_id or f"webhook-worker-{uuid.uuid4().hex[:10]}"
        if not isinstance(self.worker_id, str) or not self.worker_id or len(self.worker_id) > 64:
            raise ValueError("worker_id must be a non-empty identifier of at most 64 characters")
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or not 1 <= timeout_seconds <= 30:
            raise ValueError("timeout_seconds must be from 1 to 30")
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int) or not 15 <= lease_seconds <= 3600:
            raise ValueError("lease_seconds must be from 15 to 3600")
        self.timeout_seconds = float(timeout_seconds)
        self.lease_seconds = lease_seconds
        self.resolver = resolver or _resolve_public_addresses
        self.connection_factory = connection_factory or _PinnedHTTPSConnection
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def _now(self) -> datetime:
        return _timestamp(self.clock(), "worker clock")

    @staticmethod
    def _validate_envelope(job: dict) -> tuple[str, str, dict, str]:
        try:
            host, endpoint = validate_endpoint(job.get("endpoint"), set(job.get("allowed_hosts", [])))
        except (TypeError, ValueError):
            raise _DeliveryFailure("delivery_endpoint_invalid") from None
        if endpoint != job["endpoint"]:
            raise _DeliveryFailure("delivery_endpoint_invalid")
        headers = job.get("headers")
        if not isinstance(headers, dict) or set(headers) != SIGNED_HEADER_NAMES:
            raise _DeliveryFailure("delivery_envelope_invalid")
        if headers.get("Content-Type") != "application/json":
            raise _DeliveryFailure("delivery_envelope_invalid")
        key_id = headers.get("X-WiFiAnalyzer-Key-Id")
        timestamp = headers.get("X-WiFiAnalyzer-Timestamp")
        signature = headers.get("X-WiFiAnalyzer-Signature")
        idempotency_key = headers.get("Idempotency-Key")
        if not isinstance(key_id, str) or not key_id or any(c in key_id for c in "\r\n"):
            raise _DeliveryFailure("delivery_envelope_invalid")
        if not isinstance(timestamp, str) or not timestamp.isdigit() or len(timestamp) > 12:
            raise _DeliveryFailure("delivery_envelope_invalid")
        if not isinstance(signature, str) or not __import__("re").fullmatch(r"v1=[0-9a-f]{64}", signature):
            raise _DeliveryFailure("delivery_envelope_invalid")
        if idempotency_key != job.get("batch_id"):
            raise _DeliveryFailure("delivery_envelope_invalid")
        body = job.get("body")
        if not isinstance(body, str) or not body or len(body.encode("utf-8")) > MAX_REQUEST_BYTES:
            raise _DeliveryFailure("delivery_request_too_large")
        try:
            decoded = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise _DeliveryFailure("delivery_envelope_invalid") from None
        if (
            not isinstance(decoded, dict)
            or decoded.get("schema_version") != "1.0"
            or decoded.get("batch_id") != job.get("batch_id")
            or decoded.get("key_id") != key_id
            or not isinstance(decoded.get("events"), list)
            or len(decoded["events"]) != job.get("event_count")
        ):
            raise _DeliveryFailure("delivery_envelope_invalid")
        return host, endpoint, headers, body

    def _fail(self, job: dict, code: str) -> dict:
        try:
            failed = self.store.fail(
                job["id"], job["lease_id"], code, now=self._now(),
            )
            return {
                "delivery_id": job["id"],
                "subscription_id": job["subscription_id"],
                "batch_id": job["batch_id"],
                "status": failed["status"],
                "error_code": code,
            }
        except WebhookDeliveryNotFoundError:
            return {
                "delivery_id": job["id"],
                "subscription_id": job["subscription_id"],
                "batch_id": job["batch_id"],
                "status": "lease_lost",
            }

    def _deliver(self, claimed: dict) -> dict:
        connection = None
        delivery_id = claimed["id"]
        try:
            lease_id = claimed["lease_id"]
            job = self.store.get_leased_job(delivery_id, lease_id, now=self._now())
            if job is None:
                return {"delivery_id": delivery_id, "status": "lease_lost"}
            host, endpoint, headers, body = self._validate_envelope(job)

            resolution_at = self._now()
            try:
                resolved = _normalise_resolver_result(self.resolver(host))
            except _DeliveryFailure:
                raise
            except (OSError, socket.gaierror, TimeoutError):
                raise _DeliveryFailure("dns_resolution_failed") from None

            last_error = None
            for address in resolved:
                try:
                    connection = self.connection_factory(host, address, self.timeout_seconds)
                    break
                except ssl.SSLError as error:
                    last_error = error
                except (OSError, TimeoutError) as error:
                    last_error = error
            if connection is None:
                code = "delivery_tls_failed" if isinstance(last_error, ssl.SSLError) else "delivery_connection_failed"
                raise _DeliveryFailure(code)

            evidence = {
                "endpoint": endpoint,
                "allowed_hosts": job["allowed_hosts"],
                "resolution_at": resolution_at.isoformat(),
                "connected_at": self._now().isoformat(),
                "resolved_addresses": resolved,
                "peer_ip": getattr(connection, "peer_ip", None),
                "connected_port": getattr(connection, "connected_port", None),
                "tls_version": getattr(connection, "tls_version", None),
                "tls_verified": getattr(connection, "tls_verified", False),
                "hostname_verified": getattr(connection, "hostname_verified", False),
                "redirect_location": None,
            }
            try:
                verified = verify_egress(evidence)
            except (TypeError, ValueError):
                raise _DeliveryFailure("egress_policy_blocked") from None
            if not verified.get("approved"):
                raise _DeliveryFailure("egress_policy_blocked")

            # Confirm the lease is still ours after DNS/TLS setup and immediately before I/O.
            self.store.renew_lease(
                delivery_id, lease_id, now=self._now(), lease_seconds=self.lease_seconds,
            )
            response = connection.post(
                endpoint, headers, body, max_response_bytes=MAX_RESPONSE_BYTES,
            )
            status = response.get("status")
            response_size = response.get("response_bytes")
            if isinstance(response_size, bool) or not isinstance(response_size, int) or not 0 <= response_size <= MAX_RESPONSE_BYTES:
                raise _DeliveryFailure("delivery_response_too_large")
            if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
                raise _DeliveryFailure("delivery_transport_error")
            if response.get("redirected") or 300 <= status < 400:
                raise _DeliveryFailure("redirect_refused")
            if not 200 <= status < 300:
                raise _DeliveryFailure("delivery_http_error")
            completed = self.store.complete(
                delivery_id, lease_id, http_status=status, now=self._now(),
            )
            return {
                "delivery_id": delivery_id,
                "subscription_id": job["subscription_id"],
                "batch_id": job["batch_id"],
                "status": completed["status"],
                "http_status": status,
                "event_count": job["event_count"],
            }
        except _DeliveryFailure as error:
            return self._fail(claimed, error.code)
        except WebhookDeliveryNotFoundError:
            return {"delivery_id": delivery_id, "status": "lease_lost"}
        except (OSError, socket.gaierror, TimeoutError):
            return self._fail(claimed, "delivery_timeout")
        except ssl.SSLError:
            return self._fail(claimed, "delivery_tls_failed")
        except Exception:
            # Never persist endpoint, headers, payloads, secret-like exception strings or socket details.
            return self._fail(claimed, "delivery_transport_error")
        finally:
            if connection is not None:
                connection.close()

    def run_once(self, *, now=None, max_jobs: int = 5) -> dict:
        if isinstance(max_jobs, bool) or not isinstance(max_jobs, int) or not 1 <= max_jobs <= MAX_WORKER_BATCH:
            raise ValueError(f"max_jobs must be from 1 to {MAX_WORKER_BATCH}")
        moment = _timestamp(now, "now") if now is not None else self._now()
        claim = self.store.claim_due(
            self.worker_id, now=moment, lease_seconds=self.lease_seconds, limit=max_jobs,
        )
        results = [self._deliver(job) for job in claim["jobs"]]
        delivered = sum(item["status"] == "delivered" for item in results)
        failed = sum(item["status"] in {"retry_wait", "dead_letter", "lease_lost"} for item in results)
        return {
            "worker_id": self.worker_id,
            "claimed_count": claim["claimed_count"],
            "processed_count": len(results),
            "delivered_count": delivered,
            "failed_count": failed,
            "deliveries": results,
        }


def main() -> int:
    try:
        poll_seconds = float(os.environ.get("WIFI_ANALYZER_WEBHOOK_WORKER_POLL_SECONDS", "5"))
        timeout_seconds = float(os.environ.get("WIFI_ANALYZER_WEBHOOK_WORKER_TIMEOUT_SECONDS", "8"))
        lease_seconds = int(os.environ.get("WIFI_ANALYZER_WEBHOOK_WORKER_LEASE_SECONDS", "120"))
        max_jobs = int(os.environ.get("WIFI_ANALYZER_WEBHOOK_WORKER_BATCH_SIZE", "5"))
    except ValueError as error:
        raise SystemExit("Webhook worker numeric configuration is invalid") from error
    if not 1 <= poll_seconds <= 300:
        raise SystemExit("Webhook worker poll interval must be from 1 to 300 seconds")
    if not 1 <= max_jobs <= MAX_WORKER_BATCH:
        raise SystemExit(f"Webhook worker batch size must be from 1 to {MAX_WORKER_BATCH}")
    worker = WebhookDispatchWorker(
        worker_id=os.environ.get("WIFI_ANALYZER_WEBHOOK_WORKER_ID") or None,
        timeout_seconds=timeout_seconds,
        lease_seconds=lease_seconds,
    )
    stopping = False

    def request_stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    print(f"WiFi Analyzer Pro webhook dispatch worker started ({worker.worker_id}).")
    while not stopping:
        try:
            result = worker.run_once(max_jobs=max_jobs)
            if result["claimed_count"]:
                print(
                    f"Webhook worker processed {result['processed_count']} delivery(s): "
                    f"{result['delivered_count']} delivered, {result['failed_count']} failed."
                )
            else:
                time.sleep(poll_seconds)
        except Exception:
            print("Webhook worker cycle failed; inspect protected configuration and service logs.")
            time.sleep(poll_seconds)
    print("WiFi Analyzer Pro webhook worker stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
