"""Pinned-TLS worker for durable router-report webhook delivery."""
from __future__ import annotations

import http.client
import ipaddress
import os
import re
import signal
import socket
import ssl
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from .feature_plugins.feature_187_router_webhook_egress_policy_verifier import run as verify_egress
from .feature_plugins.feature_189_router_scheduled_report_delivery_package import run as prepare_delivery
from .router_adapters.report_job_store import ReportJobNotFoundError, RouterReportJobStore

MAX_DNS_ADDRESSES = 32
MAX_RESPONSE_BYTES = 16 * 1024
MAX_REQUEST_BYTES = 1024 * 1024
MAX_WORKER_BATCH = 5
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
SIGNED_HEADERS = (
    "X-WiFiAnalyzer-Key-Id", "X-WiFiAnalyzer-Timestamp",
    "X-WiFiAnalyzer-Signature", "Idempotency-Key",
)


class _DeliveryFailure(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _timestamp(value: object, field: str) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp") from error
    else:
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone offset")
    return parsed.astimezone(timezone.utc)


def _hostname(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ValueError(f"{field} must be a fully-qualified DNS hostname")
    try:
        host = value.rstrip(".").lower().encode("idna").decode("ascii")
    except UnicodeError as error:
        raise ValueError(f"{field} must be a valid IDNA hostname") from error
    if not host or len(host) > 253 or "." not in host:
        raise ValueError(f"{field} must be a fully-qualified DNS hostname")
    if any(not HOST_LABEL.fullmatch(label) for label in host.split(".")):
        raise ValueError(f"{field} is not a valid DNS hostname")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    raise ValueError(f"{field} must be a DNS hostname, not an IP address")


def _validate_webhook(webhook: object) -> dict:
    """Validate the exact endpoint, allowlist, key identifier and secret before claiming jobs."""
    if not isinstance(webhook, dict):
        raise ValueError("webhook must be an object")
    endpoint = webhook.get("endpoint")
    if not isinstance(endpoint, str) or len(endpoint) > 2048:
        raise ValueError("webhook.endpoint must be an HTTPS URL of at most 2048 characters")
    if any(ord(char) < 32 or ord(char) == 127 or char == "\\" for char in endpoint):
        raise ValueError("webhook.endpoint contains invalid control characters or backslashes")
    if "?" in endpoint or "#" in endpoint:
        raise ValueError("webhook.endpoint must not contain a query string or fragment")
    try:
        parsed = urlsplit(endpoint)
        host_value, port = parsed.hostname, parsed.port
    except ValueError as error:
        raise ValueError("webhook.endpoint must be a valid HTTPS URL") from error
    if parsed.scheme.lower() != "https" or not parsed.netloc or host_value is None:
        raise ValueError("webhook.endpoint must use HTTPS and contain a DNS hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("webhook.endpoint must not contain embedded credentials")
    if port not in (None, 443):
        raise ValueError("webhook.endpoint must use HTTPS port 443")
    host = _hostname(host_value, "webhook.endpoint.hostname")
    raw_hosts = webhook.get("allowed_hosts")
    if not isinstance(raw_hosts, list) or not 1 <= len(raw_hosts) <= 50:
        raise ValueError("webhook.allowed_hosts must contain from 1 to 50 DNS hostnames")
    allowed_hosts = [_hostname(item, f"webhook.allowed_hosts[{i}]") for i, item in enumerate(raw_hosts)]
    if len(allowed_hosts) != len(set(allowed_hosts)):
        raise ValueError("webhook.allowed_hosts entries must be unique")
    if host not in allowed_hosts:
        raise ValueError("webhook.endpoint hostname is not present in the exact host allowlist")
    path = parsed.path or "/"
    if not path.startswith("/") or path.startswith("//"):
        raise ValueError("webhook.endpoint path must be absolute")
    key_id = webhook.get("key_id")
    if not isinstance(key_id, str) or not IDENTIFIER.fullmatch(key_id):
        raise ValueError("webhook.key_id must be a 1 to 64 character identifier")
    secret = webhook.get("signing_secret")
    if not isinstance(secret, str) or not 32 <= len(secret.encode("utf-8")) <= 4096:
        raise ValueError("webhook.signing_secret must contain from 32 to 4096 UTF-8 bytes")
    return {
        "endpoint": urlunsplit(("https", host, path, "", "")),
        "allowed_hosts": sorted(allowed_hosts),
        "key_id": key_id,
        "signing_secret": secret,
    }


def _normalise_resolver_result(raw: object) -> list[str]:
    if not isinstance(raw, (list, tuple)) or not raw:
        raise _DeliveryFailure("dns_resolution_failed")
    if len(raw) > MAX_DNS_ADDRESSES:
        raise _DeliveryFailure("dns_policy_blocked")
    values = []
    for item in raw:
        if not isinstance(item, str) or "%" in item:
            raise _DeliveryFailure("dns_policy_blocked")
        try:
            address = ipaddress.ip_address(item)
        except ValueError as error:
            raise _DeliveryFailure("dns_policy_blocked") from error
        effective = (address.ipv4_mapped or address) if isinstance(address, ipaddress.IPv6Address) else address
        if not effective.is_global or effective.is_multicast or effective.is_reserved or effective.is_unspecified:
            raise _DeliveryFailure("dns_policy_blocked")
        values.append(str(address))
    return sorted(
        set(values),
        key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value))),
    )


def _resolve_public_addresses(host: str) -> list[str]:
    """Resolve immediately before delivery and reject mixed public/private DNS answers."""
    try:
        records = socket.getaddrinfo(
            host, 443, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except (OSError, socket.gaierror, TimeoutError) as error:
        raise _DeliveryFailure("dns_resolution_failed") from error
    return _normalise_resolver_result([record[4][0] for record in records])


class _PinnedHTTPSConnection:
    """Direct socket transport pinned to one IP, with original-host TLS verification."""

    def __init__(self, host: str, peer_ip: str, timeout_seconds: float):
        address = ipaddress.ip_address(peer_ip)
        family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        raw = socket.socket(family, socket.SOCK_STREAM)
        raw.settimeout(timeout_seconds)
        sockaddr = (str(address), 443, 0, 0) if address.version == 6 else (str(address), 443)
        try:
            raw.connect(sockaddr)
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
            tls_socket = context.wrap_socket(raw, server_hostname=host)
            actual_peer = ipaddress.ip_address(tls_socket.getpeername()[0])
            if actual_peer != address:
                tls_socket.close()
                raise OSError("connected peer did not match pinned DNS address")
            if not tls_socket.getpeercert(binary_form=True):
                tls_socket.close()
                raise ssl.SSLError("TLS peer certificate was not available")
            self.sock = tls_socket
            self.peer_ip = str(actual_peer)
            self.connected_port = 443
            self.tls_version = tls_socket.version()
            self.tls_verified = True
            self.hostname_verified = context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
            if self.tls_version not in {"TLSv1.2", "TLSv1.3"}:
                self.close()
                raise ssl.SSLError("TLSv1.2 or TLSv1.3 is required")
        except BaseException:
            raw.close()
            raise

    def post(self, endpoint: str, headers: dict, body: str, *, max_response_bytes: int) -> dict:
        if not isinstance(body, str) or len(body.encode("utf-8")) > MAX_REQUEST_BYTES:
            raise _DeliveryFailure("delivery_request_too_large")
        parsed = urlsplit(endpoint)
        path = parsed.path or "/"
        if not path.startswith("/") or path.startswith("//") or any(char in path for char in "\r\n"):
            raise _DeliveryFailure("delivery_endpoint_invalid")
        raw_body = body.encode("utf-8")
        outgoing = {
            "Host": parsed.hostname or "",
            "Content-Type": "application/json",
            "Content-Length": str(len(raw_body)),
            "Connection": "close",
            "User-Agent": "WiFiAnalyzerPro-ReportWorker/1.0",
        }
        if not isinstance(headers, dict):
            raise _DeliveryFailure("delivery_envelope_invalid")
        for name in SIGNED_HEADERS:
            value = headers.get(name)
            if not isinstance(value, str) or not value or any(char in value for char in "\r\n"):
                raise _DeliveryFailure("delivery_envelope_invalid")
            outgoing[name] = value
        lines = [f"POST {path} HTTP/1.1"]
        lines.extend(f"{name}: {value}" for name, value in outgoing.items())
        self.sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + raw_body)
        response = http.client.HTTPResponse(self.sock)
        response.begin()
        response_body = response.read(max_response_bytes + 1)
        if len(response_body) > max_response_bytes:
            raise _DeliveryFailure("delivery_response_too_large")
        return {
            "status": response.status,
            "redirected": 300 <= response.status < 400,
            "response_bytes": len(response_body),
        }

    def close(self):
        sock = getattr(self, "sock", None)
        if sock is not None:
            self.sock = None
            try:
                sock.close()
            except OSError:
                pass


class RouterReportWebhookWorker:
    """Claim and deliver due report jobs through one explicitly configured webhook."""

    def __init__(
        self, store: RouterReportJobStore | None = None, worker_id: str | None = None,
        *, timeout_seconds: float = 8, lease_seconds: int = 120,
        resolver=None, connection_factory=None, clock=None,
    ):
        self.store = store or RouterReportJobStore()
        self.worker_id = worker_id or f"report-worker-{uuid.uuid4().hex[:12]}"
        if not IDENTIFIER.fullmatch(self.worker_id):
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
        return _timestamp(self.clock(), "worker clock")

    def _fail(self, job: dict, code: str) -> dict:
        try:
            failed = self.store.fail(job["id"], job["lease_id"], code, now=self._now())
            return {
                "job_id": job["id"], "report_id": job["report_id"],
                "status": failed["status"], "error_code": code,
            }
        except ReportJobNotFoundError:
            return {"job_id": job["id"], "report_id": job["report_id"], "status": "lease_lost"}

    def _deliver(self, claimed_job: dict, webhook: dict, event_mode: str, maximum_finding_events: int) -> dict:
        connection = None
        job_id = claimed_job["id"]
        try:
            lease_id = claimed_job["lease_id"]
            job = self.store.get_leased_job(job_id, lease_id, now=self._now())
            if job is None:
                return {"job_id": job_id, "report_id": claimed_job["report_id"], "status": "lease_lost"}
            host = urlsplit(webhook["endpoint"]).hostname
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
                "endpoint": webhook["endpoint"],
                "allowed_hosts": webhook["allowed_hosts"],
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
            if not verify_egress(evidence)["approved"]:
                raise _DeliveryFailure("egress_policy_blocked")

            self.store.renew_lease(job_id, lease_id, now=self._now(), lease_seconds=self.lease_seconds)
            job = self.store.get_leased_job(job_id, lease_id, now=self._now())
            package = prepare_delivery({
                "now": self._now().isoformat(),
                "claimed_job": job,
                "webhook": webhook,
                "egress_evidence": evidence,
                "event_mode": event_mode,
                "maximum_finding_events": maximum_finding_events,
            })
            if package.get("status") != "ready" or not isinstance(package.get("delivery"), dict):
                raise _DeliveryFailure("egress_policy_blocked")
            delivery = package["delivery"]
            response = connection.post(
                delivery["endpoint"], delivery["headers"], delivery["body"],
                max_response_bytes=MAX_RESPONSE_BYTES,
            )
            status = response.get("status")
            size = response.get("response_bytes")
            if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= MAX_RESPONSE_BYTES:
                raise _DeliveryFailure("delivery_response_too_large")
            if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
                raise _DeliveryFailure("delivery_transport_error")
            if response.get("redirected") or 300 <= status < 400:
                raise _DeliveryFailure("redirect_refused")
            if not 200 <= status < 300:
                raise _DeliveryFailure("delivery_http_error")

            completed = self.store.complete(job_id, lease_id, {
                "report_id": job["report_id"],
                "content_hash": job["report_bundle"]["content_hash"],
                "event_batch_id": job["job_key"],
                "delivered_at": self._now().isoformat(),
                "http_status": status,
                "delivery_status": "delivered",
            }, now=self._now())
            return {
                "job_id": job_id, "report_id": job["report_id"],
                "status": completed["status"], "http_status": status,
                "event_count": package["summary"]["event_count"],
                "idempotency_key": job["job_key"],
            }
        except _DeliveryFailure as error:
            return self._fail(claimed_job, error.code)
        except ReportJobNotFoundError:
            return {"job_id": job_id, "report_id": claimed_job["report_id"], "status": "lease_lost"}
        except ssl.SSLError:
            return self._fail(claimed_job, "delivery_tls_failed")
        except (socket.timeout, TimeoutError):
            return self._fail(claimed_job, "delivery_timeout")
        except (OSError, http.client.HTTPException):
            return self._fail(claimed_job, "delivery_transport_error")
        except ValueError:
            return self._fail(claimed_job, "delivery_package_invalid")
        except Exception:
            return self._fail(claimed_job, "delivery_worker_error")
        finally:
            if connection is not None:
                connection.close()

    def run_once(
        self, webhook: dict, *, max_jobs: int = 1, event_mode: str = "summary",
        maximum_finding_events: int = 100, now: datetime | str | None = None,
    ) -> dict:
        safe_webhook = _validate_webhook(webhook)
        if isinstance(max_jobs, bool) or not isinstance(max_jobs, int) or not 1 <= max_jobs <= MAX_WORKER_BATCH:
            raise ValueError(f"max_jobs must be from 1 to {MAX_WORKER_BATCH}")
        if event_mode not in {"summary", "summary_and_findings"}:
            raise ValueError("event_mode must be summary or summary_and_findings")
        if isinstance(maximum_finding_events, bool) or not isinstance(maximum_finding_events, int) or not 1 <= maximum_finding_events <= 499:
            raise ValueError("maximum_finding_events must be from 1 to 499")
        moment = _timestamp(now, "now") if now is not None else self._now()
        claimed = self.store.claim_due(
            self.worker_id, now=moment, lease_seconds=self.lease_seconds, limit=max_jobs,
        )
        jobs = [self._deliver(item, safe_webhook, event_mode, maximum_finding_events) for item in claimed["jobs"]]
        delivered = sum(item["status"] == "completed" for item in jobs)
        failed = sum(item["status"] in {"retry_wait", "dead_letter", "cancelled", "lease_lost"} for item in jobs)
        return {
            "worker_id": self.worker_id, "claimed_count": len(claimed["jobs"]),
            "processed_count": len(jobs), "delivered_count": delivered,
            "failed_count": failed, "jobs": jobs,
        }


def _environment_webhook() -> dict:
    secret = os.environ.get("WIFI_ANALYZER_REPORT_WEBHOOK_SIGNING_SECRET", "")
    secret_file = os.environ.get("WIFI_ANALYZER_REPORT_WEBHOOK_SIGNING_SECRET_FILE", "")
    if secret and secret_file:
        raise SystemExit("Configure only one signing-secret source")
    if secret_file:
        path = Path(secret_file).expanduser()
        try:
            info = path.stat()
            if not path.is_file() or info.st_size > 4096:
                raise SystemExit("Signing-secret file must be regular and no larger than 4096 bytes")
            if os.name != "nt" and info.st_mode & 0o077:
                raise SystemExit("Signing-secret file must not be accessible by group or other users")
            secret = path.read_text(encoding="utf-8").rstrip("\r\n")
        except OSError:
            raise SystemExit("Signing-secret file could not be read") from None
    return {
        "endpoint": os.environ.get("WIFI_ANALYZER_REPORT_WEBHOOK_URL", ""),
        "allowed_hosts": [
            item.strip() for item in os.environ.get("WIFI_ANALYZER_REPORT_WEBHOOK_ALLOWED_HOSTS", "").split(",")
            if item.strip()
        ],
        "key_id": os.environ.get("WIFI_ANALYZER_REPORT_WEBHOOK_KEY_ID", ""),
        "signing_secret": secret,
    }


def main() -> int:
    webhook = _validate_webhook(_environment_webhook())
    try:
        poll_seconds = float(os.environ.get("WIFI_ANALYZER_REPORT_WORKER_POLL_SECONDS", "5"))
        timeout_seconds = float(os.environ.get("WIFI_ANALYZER_REPORT_WORKER_TIMEOUT_SECONDS", "8"))
        max_jobs = int(os.environ.get("WIFI_ANALYZER_REPORT_WORKER_BATCH_SIZE", "1"))
        lease_seconds = int(os.environ.get("WIFI_ANALYZER_REPORT_WORKER_LEASE_SECONDS", "120"))
        maximum_finding_events = int(os.environ.get("WIFI_ANALYZER_REPORT_WORKER_MAX_FINDINGS", "100"))
    except ValueError as error:
        raise SystemExit("Report worker numeric configuration is invalid") from error
    if not 1 <= poll_seconds <= 300:
        raise SystemExit("Worker poll interval must be from 1 to 300 seconds")
    if not 1 <= max_jobs <= MAX_WORKER_BATCH:
        raise SystemExit(f"Worker batch size must be from 1 to {MAX_WORKER_BATCH}")
    if not 1 <= maximum_finding_events <= 499:
        raise SystemExit("Maximum finding events must be from 1 to 499")
    event_mode = os.environ.get("WIFI_ANALYZER_REPORT_WORKER_EVENT_MODE", "summary")
    if event_mode not in {"summary", "summary_and_findings"}:
        raise SystemExit("Worker event mode must be summary or summary_and_findings")
    worker = RouterReportWebhookWorker(
        worker_id=os.environ.get("WIFI_ANALYZER_REPORT_WORKER_ID") or None,
        timeout_seconds=timeout_seconds, lease_seconds=lease_seconds,
    )

    stopping = False

    def request_stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    print(f"WiFi Analyzer Pro report worker started ({worker.worker_id}).")
    while not stopping:
        try:
            result = worker.run_once(
                webhook, max_jobs=max_jobs, event_mode=event_mode,
                maximum_finding_events=maximum_finding_events,
            )
            if result["claimed_count"]:
                print(
                    f"Report worker processed {result['processed_count']} job(s): "
                    f"{result['delivered_count']} delivered, {result['failed_count']} failed."
                )
            else:
                time.sleep(poll_seconds)
        except Exception:
            print("Report worker cycle failed; check protected local configuration and service logs.")
            time.sleep(poll_seconds)
    print("WiFi Analyzer Pro report worker stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
