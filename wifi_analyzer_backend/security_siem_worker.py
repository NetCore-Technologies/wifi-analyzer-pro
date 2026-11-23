"""Opt-in, pinned-TLS sender for hash-chained security audit events."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import signal
import stat
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

if __package__:
    from .audit_store import SecurityAuditStore
    from .report_worker import (
        MAX_RESPONSE_BYTES,
        _DeliveryFailure,
        _PinnedHTTPSConnection,
        _resolve_public_addresses,
        _validate_webhook,
    )
    from .security_siem_store import (
        MAX_DELIVERY_BATCH,
        MAX_INGEST_BATCH,
        SecuritySiemStore,
        SiemDeliveryNotFoundError,
        SiemQueueFullError,
    )
    from .feature_plugins.feature_187_router_webhook_egress_policy_verifier import run as verify_egress
else:  # Direct execution from the installed backend directory.
    from audit_store import SecurityAuditStore
    from report_worker import (
        MAX_RESPONSE_BYTES,
        _DeliveryFailure,
        _PinnedHTTPSConnection,
        _resolve_public_addresses,
        _validate_webhook,
    )
    from security_siem_store import (
        MAX_DELIVERY_BATCH,
        MAX_INGEST_BATCH,
        SecuritySiemStore,
        SiemDeliveryNotFoundError,
        SiemQueueFullError,
    )
    from feature_plugins.feature_187_router_webhook_egress_policy_verifier import run as verify_egress

WORKER_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
MAX_SECRET_BYTES = 4096
MAX_REQUEST_BYTES = 1024 * 1024


def _read_secret_file(path_value: str | None) -> str:
    if not isinstance(path_value, str) or not path_value.strip():
        raise ValueError("A protected SIEM signing-secret file is required")
    path = Path(path_value).expanduser()
    if path.is_symlink():
        raise ValueError("SIEM signing-secret file must not be a symbolic link")
    try:
        descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        raise ValueError("SIEM signing-secret file could not be opened safely") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SECRET_BYTES:
            raise ValueError("SIEM signing-secret file must be regular and no larger than 4096 bytes")
        if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("SIEM signing-secret file must not be accessible by group or other users")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            raw = stream.read(MAX_SECRET_BYTES + 1)
        if len(raw) > MAX_SECRET_BYTES:
            raise ValueError("SIEM signing-secret file exceeds 4096 bytes")
        secret = raw.decode("utf-8").rstrip("\r\n")
    except (OSError, UnicodeDecodeError):
        raise ValueError("SIEM signing-secret file is unreadable or invalid UTF-8") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(secret.encode("utf-8")) < 32:
        raise ValueError("SIEM signing secret must contain at least 32 UTF-8 bytes")
    return secret


def _sign_event(secret: str, key_id: str, timestamp: str, event_id: str, body: str) -> dict[str, str]:
    message = "\n".join((key_id, timestamp, event_id, body)).encode("utf-8")
    digest = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return {
        "X-WiFiAnalyzer-Key-Id": key_id,
        "X-WiFiAnalyzer-Timestamp": timestamp,
        "X-WiFiAnalyzer-Signature": "sha256=" + digest,
        "Idempotency-Key": event_id,
    }


class SecuritySiemWorker:
    """At-least-once audit event delivery over DNS-pinned, certificate-verified HTTPS."""

    def __init__(
        self,
        *,
        audit_store: SecurityAuditStore | None = None,
        store: SecuritySiemStore | None = None,
        worker_id: str | None = None,
        timeout_seconds: float = 8,
        lease_seconds: int = 120,
        resolver=None,
        connection_factory=None,
        clock=None,
    ):
        self.audit_store = audit_store or SecurityAuditStore()
        self.store = store or SecuritySiemStore()
        self.worker_id = worker_id or ("siem-exporter-" + uuid.uuid4().hex[:12])
        if not WORKER_ID_PATTERN.fullmatch(self.worker_id):
            raise ValueError("worker_id must be a 1 to 64 character identifier")
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
        value = self.clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("worker clock must return a timezone-aware datetime")
        return value.astimezone(timezone.utc)

    def _fail(self, job: dict, code: str) -> dict:
        try:
            result = self.store.fail(
                job["id"], job["lease_id"], code, now=self._now(),
            )
            return {
                "source_id": job["source_id"],
                "event_id": job["event_id"],
                "status": result["status"],
                "error_code": code,
            }
        except SiemDeliveryNotFoundError:
            return {
                "source_id": job["source_id"],
                "event_id": job["event_id"],
                "status": "lease_lost",
            }

    def _deliver(self, claimed: dict, webhook: dict) -> dict:
        connection = None
        try:
            job = self.store.get_leased(claimed["id"], claimed["lease_id"], now=self._now())
            if job is None:
                return {
                    "source_id": claimed["source_id"],
                    "event_id": claimed["event_id"],
                    "status": "lease_lost",
                }

            host = urlsplit(webhook["endpoint"]).hostname
            resolution_at = self._now()
            try:
                resolved = self.resolver(host)
            except _DeliveryFailure:
                raise
            except Exception:
                raise _DeliveryFailure("dns_resolution_failed") from None

            last_error = None
            for address in resolved:
                try:
                    connection = self.connection_factory(host, address, self.timeout_seconds)
                    break
                except Exception as error:
                    last_error = error
            if connection is None:
                import ssl
                raise _DeliveryFailure(
                    "delivery_tls_failed" if isinstance(last_error, ssl.SSLError)
                    else "delivery_connection_failed"
                )

            connected_at = self._now()
            evidence = {
                "endpoint": webhook["endpoint"],
                "allowed_hosts": webhook["allowed_hosts"],
                "resolution_at": resolution_at.isoformat(),
                "connected_at": connected_at.isoformat(),
                "resolved_addresses": resolved,
                "peer_ip": getattr(connection, "peer_ip", None),
                "connected_port": getattr(connection, "connected_port", None),
                "tls_version": getattr(connection, "tls_version", None),
                "tls_verified": getattr(connection, "tls_verified", False),
                "hostname_verified": getattr(connection, "hostname_verified", False),
                "redirect_location": None,
            }
            if not verify_egress(evidence).get("approved"):
                raise _DeliveryFailure("egress_policy_blocked")

            self.store.renew_lease(
                job["id"], job["lease_id"], now=self._now(),
                lease_seconds=self.lease_seconds,
            )
            body = json.dumps(
                job["payload"],
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
            if len(body.encode("utf-8")) > MAX_REQUEST_BYTES:
                raise _DeliveryFailure("delivery_request_too_large")
            timestamp = self._now().isoformat(timespec="seconds")
            headers = _sign_event(
                webhook["signing_secret"],
                webhook["key_id"],
                timestamp,
                job["event_id"],
                body,
            )
            response = connection.post(
                webhook["endpoint"],
                headers,
                body,
                max_response_bytes=MAX_RESPONSE_BYTES,
            )
            status = response.get("status")
            response_bytes = response.get("response_bytes")
            if (
                isinstance(status, bool)
                or not isinstance(status, int)
                or not 100 <= status <= 599
                or isinstance(response_bytes, bool)
                or not isinstance(response_bytes, int)
                or not 0 <= response_bytes <= MAX_RESPONSE_BYTES
            ):
                raise _DeliveryFailure("delivery_transport_error")
            if response.get("redirected") or 300 <= status < 400:
                raise _DeliveryFailure("redirect_refused")
            if not 200 <= status < 300:
                raise _DeliveryFailure("delivery_http_error")

            completed = self.store.complete(
                job["id"], job["lease_id"], http_status=status, now=self._now(),
            )
            return {
                "source_id": completed["source_id"],
                "event_id": completed["event_id"],
                "status": "delivered",
                "http_status": status,
            }
        except _DeliveryFailure as error:
            return self._fail(claimed, error.code)
        except SiemDeliveryNotFoundError:
            return {
                "source_id": claimed["source_id"],
                "event_id": claimed["event_id"],
                "status": "lease_lost",
            }
        except (TimeoutError, OSError):
            return self._fail(claimed, "delivery_transport_error")
        except Exception:
            # Never surface endpoint response bodies, exception strings or secret material.
            return self._fail(claimed, "delivery_worker_error")
        finally:
            if connection is not None:
                connection.close()

    def run_once(
        self,
        webhook: dict,
        *,
        max_events: int = 100,
        max_jobs: int = 5,
        now: object = None,
    ) -> dict:
        safe_webhook = _validate_webhook(webhook)
        if isinstance(max_events, bool) or not isinstance(max_events, int) or not 1 <= max_events <= MAX_INGEST_BATCH:
            raise ValueError(f"max_events must be from 1 to {MAX_INGEST_BATCH}")
        if isinstance(max_jobs, bool) or not isinstance(max_jobs, int) or not 1 <= max_jobs <= MAX_DELIVERY_BATCH:
            raise ValueError(f"max_jobs must be from 1 to {MAX_DELIVERY_BATCH}")
        moment = self._now() if now is None else _timestamp(now, "now")

        cursor = self.store.cursor_id()
        source_events = self.audit_store.list_events_after(after_id=cursor, limit=max_events)
        queue_full = False
        try:
            ingest = self.store.ingest(source_events, now=moment)
        except SiemQueueFullError:
            ingest = {
                "ingested_count": 0,
                "duplicate_count": 0,
                "source_cursor_id": cursor,
                "queue_full": True,
            }
            queue_full = True

        self.store.prune(now=moment)
        claimed = self.store.claim_due(
            self.worker_id,
            now=moment,
            lease_seconds=self.lease_seconds,
            limit=max_jobs,
        )
        jobs = [self._deliver(item, safe_webhook) for item in claimed["jobs"]]
        delivered = sum(item["status"] == "delivered" for item in jobs)
        failed = sum(item["status"] in {"retry_wait", "dead_letter", "lease_lost"} for item in jobs)
        return {
            "worker_id": self.worker_id,
            "source_event_count": len(source_events),
            "ingested_count": ingest["ingested_count"],
            "duplicate_count": ingest["duplicate_count"],
            "queue_full": queue_full,
            "claimed_count": claimed["claimed_count"],
            "delivered_count": delivered,
            "failed_count": failed,
            "queue": self.store.summary(),
            "jobs": jobs,
        }


def _environment_webhook() -> dict:
    endpoint = os.environ.get("WIFI_ANALYZER_SIEM_URL", "").strip()
    raw_hosts = os.environ.get("WIFI_ANALYZER_SIEM_ALLOWED_HOSTS", "")
    hosts = [item.strip() for item in raw_hosts.split(",") if item.strip()]
    key_id = os.environ.get("WIFI_ANALYZER_SIEM_KEY_ID", "").strip()
    secret_path = os.environ.get("WIFI_ANALYZER_SIEM_SECRET_FILE", "").strip()
    return {
        "endpoint": endpoint,
        "allowed_hosts": hosts,
        "key_id": key_id,
        "signing_secret": _read_secret_file(secret_path),
    }


def main() -> int:
    try:
        webhook = _validate_webhook(_environment_webhook())
        poll_seconds = int(os.environ.get("WIFI_ANALYZER_SIEM_POLL_SECONDS", "10"))
        max_events = int(os.environ.get("WIFI_ANALYZER_SIEM_MAX_EVENTS_PER_CYCLE", "100"))
        max_jobs = int(os.environ.get("WIFI_ANALYZER_SIEM_MAX_JOBS_PER_CYCLE", "5"))
        timeout_seconds = float(os.environ.get("WIFI_ANALYZER_SIEM_TIMEOUT_SECONDS", "8"))
        lease_seconds = int(os.environ.get("WIFI_ANALYZER_SIEM_LEASE_SECONDS", "120"))
        retention_days = int(os.environ.get("WIFI_ANALYZER_SIEM_RETENTION_DAYS", "90"))
        if not 1 <= poll_seconds <= 300:
            raise ValueError("poll seconds must be from 1 to 300")
        if not 1 <= max_events <= MAX_INGEST_BATCH:
            raise ValueError(f"max events must be from 1 to {MAX_INGEST_BATCH}")
        if not 1 <= max_jobs <= MAX_DELIVERY_BATCH:
            raise ValueError(f"max jobs must be from 1 to {MAX_DELIVERY_BATCH}")
        store = SecuritySiemStore(retention_days=retention_days)
        worker = SecuritySiemWorker(
            store=store,
            worker_id=os.environ.get("WIFI_ANALYZER_SIEM_WORKER_ID") or None,
            timeout_seconds=timeout_seconds,
            lease_seconds=lease_seconds,
        )
    except (TypeError, ValueError) as error:
        raise SystemExit(f"Security SIEM worker configuration error: {error}") from None

    stopping = False

    def request_stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    print("WiFi Analyzer Pro security SIEM exporter started.")
    while not stopping:
        try:
            result = worker.run_once(webhook, max_events=max_events, max_jobs=max_jobs)
            if result["source_event_count"] or result["claimed_count"]:
                print(
                    "Security SIEM export cycle: "
                    f"{result['ingested_count']} queued, "
                    f"{result['delivered_count']} delivered, "
                    f"{result['failed_count']} failed, "
                    f"{result['queue']['pending_count']} pending."
                )
            else:
                time.sleep(poll_seconds)
        except Exception as error:
            print(
                "Security SIEM export cycle failed "
                f"({type(error).__name__}); check protected configuration and queue health."
            )
            time.sleep(poll_seconds)
    print("WiFi Analyzer Pro security SIEM exporter stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
