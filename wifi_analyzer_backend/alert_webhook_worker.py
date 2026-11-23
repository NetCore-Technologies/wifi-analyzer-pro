"""Bridge durable site-alert transitions into the signed webhook outbox.

This producer performs no network I/O. It loads signing material from a protected
external file, creates deterministic HMAC envelopes and enqueues them for the
separate DNS-pinned webhook dispatcher.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import stat
import time
from datetime import datetime, timezone
from pathlib import Path

if __package__:
    from .alert_rule_store import AlertRuleStore
    from .feature_plugins.feature_185_router_webhook_envelope_builder import run as build_envelope
    from .feature_plugins.feature_190_router_webhook_subscription_router import run as route_events
    from .webhook_delivery_store import WebhookDeliveryStore
    from .webhook_subscription_store import WebhookSubscriptionStore
else:
    from alert_rule_store import AlertRuleStore
    from feature_plugins.feature_185_router_webhook_envelope_builder import run as build_envelope
    from feature_plugins.feature_190_router_webhook_subscription_router import run as route_events
    from webhook_delivery_store import WebhookDeliveryStore
    from webhook_subscription_store import WebhookSubscriptionStore

KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
MAX_SIGNING_KEY_FILE_BYTES = 64 * 1024
MAX_SIGNING_KEYS = 100
MAX_BRIDGE_BATCH = 100


class AlertWebhookBridgeError(RuntimeError):
    """A bounded operational failure safe to store without endpoint or secret data."""

    def __init__(self, code: str):
        if not isinstance(code, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code):
            raise ValueError("error code is invalid")
        self.code = code
        super().__init__(code)


def _normalise_signing_keys(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or not 1 <= len(value) <= MAX_SIGNING_KEYS:
        raise ValueError(f"signing key document must contain from 1 to {MAX_SIGNING_KEYS} keys")
    result = {}
    for key_id, secret in value.items():
        if not isinstance(key_id, str) or not KEY_ID_PATTERN.fullmatch(key_id):
            raise ValueError("signing key document contains an invalid key identifier")
        if not isinstance(secret, str) or not 32 <= len(secret.encode("utf-8")) <= 4096:
            raise ValueError("each webhook signing secret must contain from 32 to 4096 UTF-8 bytes")
        result[key_id] = secret
    return result


def load_signing_keys(path_value: str) -> dict[str, str]:
    """Read a bounded JSON key map through a no-follow file descriptor."""
    if not isinstance(path_value, str) or not path_value.strip():
        raise ValueError("WIFI_ANALYZER_WEBHOOK_SIGNING_KEYS_FILE is required")
    path = Path(path_value).expanduser()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(str(path), flags)
    except OSError:
        raise ValueError("webhook signing key file could not be opened safely") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SIGNING_KEY_FILE_BYTES:
            raise ValueError("webhook signing key file must be a regular file no larger than 64 KiB")
        if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("webhook signing key file must not be accessible by group or other users")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            raw = stream.read(MAX_SIGNING_KEY_FILE_BYTES + 1)
        if len(raw) > MAX_SIGNING_KEY_FILE_BYTES:
            raise ValueError("webhook signing key file exceeds the 64 KiB limit")
        document = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("webhook signing key file is unreadable or invalid JSON") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return _normalise_signing_keys(document)


def _event_for_routing(notification: dict) -> dict:
    transition = notification.get("transition")
    event = notification.get("event")
    if transition not in {"opened", "acknowledged", "resolved"} or not isinstance(event, dict):
        raise ValueError("notification record is invalid")
    site_id = event.get("site_id")
    event_id = event.get("event_id")
    rule_id = event.get("rule_id")
    severity = event.get("severity")
    if not isinstance(site_id, str) or not isinstance(event_id, str) or not isinstance(rule_id, str):
        raise ValueError("notification identifiers are invalid")
    if severity not in {"critical", "warning", "info"}:
        raise ValueError("notification severity is invalid")

    occurred_at = {
        "opened": event.get("first_seen_at"),
        "acknowledged": event.get("acknowledged_at"),
        "resolved": event.get("resolved_at"),
    }[transition] or notification.get("created_at")
    stable_id = hashlib.sha256(
        f"{site_id}\0{event_id}\0{transition}".encode("utf-8")
    ).hexdigest()
    current_status = {
        "opened": "active",
        "acknowledged": "acknowledged",
        "resolved": "resolved",
    }[transition]
    message = event.get("message")
    if not isinstance(message, str) or not message.strip():
        message = event.get("rule_name") or "Site alert"
    prefixes = {"opened": "Alert opened: ", "acknowledged": "Alert acknowledged: ", "resolved": "Alert resolved: "}
    summary = (prefixes[transition] + message.strip())[:256]
    attributes = {
        "resource_type": "alert_rule",
        "resource_id": rule_id,
        "current_status": current_status,
        "observed": event.get("observed_value"),
        "threshold": event.get("threshold"),
    }
    if transition != "opened":
        attributes["previous_status"] = "active"
    return {
        "event_id": stable_id,
        "event_type": f"site.alert.{transition}",
        "severity": severity,
        "occurred_at": occurred_at,
        "site_id": site_id,
        "router_id": None,
        "summary": summary,
        "attributes": attributes,
    }


class AlertWebhookBridgeWorker:
    """Turn pending alert transitions into deterministic signed webhook outbox rows."""

    def __init__(
        self,
        alert_store: AlertRuleStore | None = None,
        subscription_store: WebhookSubscriptionStore | None = None,
        delivery_store: WebhookDeliveryStore | None = None,
        *,
        signing_keys: dict[str, str],
        clock=None,
    ):
        self.alert_store = alert_store or AlertRuleStore()
        self.subscription_store = subscription_store or WebhookSubscriptionStore()
        self.delivery_store = delivery_store or WebhookDeliveryStore()
        self.signing_keys = _normalise_signing_keys(signing_keys)
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def _now(self) -> datetime:
        value = self.clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("worker clock must return a timezone-aware datetime")
        return value.astimezone(timezone.utc)

    def _prepare_deliveries(self, notification: dict, subscriptions: list[dict]) -> list[dict]:
        routed = route_events({
            "subscriptions": subscriptions,
            "events": [_event_for_routing(notification)],
        })
        batches = routed.get("batches")
        if not isinstance(batches, list):
            raise AlertWebhookBridgeError("webhook_routing_failed")
        deliveries = []
        for batch in batches:
            if not isinstance(batch, dict):
                raise AlertWebhookBridgeError("webhook_routing_failed")
            key_id = batch.get("key_id")
            secret = self.signing_keys.get(key_id)
            if secret is None:
                raise AlertWebhookBridgeError("signing_key_missing")
            try:
                prepared = build_envelope({
                    "now": notification["created_at"],
                    "batch_id": batch["batch_id"],
                    "endpoint": batch["endpoint"],
                    "allowed_hosts": batch["allowed_hosts"],
                    "key_id": key_id,
                    "signing_secret": secret,
                    "events": batch["events"],
                })
                signed = prepared["delivery"]
                deliveries.append({
                    "subscription_id": batch["subscription_id"],
                    "batch_id": batch["batch_id"],
                    "endpoint": signed["endpoint"],
                    "allowed_hosts": batch["allowed_hosts"],
                    "headers": signed["headers"],
                    "body": signed["body"],
                    "event_count": batch["event_count"],
                })
            except AlertWebhookBridgeError:
                raise
            except Exception:
                raise AlertWebhookBridgeError("webhook_envelope_build_failed") from None
        return deliveries

    def run_once(self, *, limit: int = 50) -> dict:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_BRIDGE_BATCH:
            raise ValueError(f"limit must be from 1 to {MAX_BRIDGE_BATCH}")
        moment = self._now()
        pending = self.alert_store.pending_notifications(limit=limit, now=moment.isoformat())
        if not pending:
            return {"processed_count": 0, "queued_count": 0, "not_configured_count": 0, "retry_count": 0}

        queued = skipped = retried = 0
        try:
            subscriptions = self.subscription_store.list_subscriptions(include_disabled=False)
        except Exception:
            subscriptions = None

        for notification in pending:
            notification_id = notification["notification_id"]
            try:
                if subscriptions is None:
                    raise AlertWebhookBridgeError("subscription_store_unavailable")
                if not subscriptions:
                    self.alert_store.mark_notification_processed(notification_id, "not_configured")
                    skipped += 1
                    continue
                deliveries = self._prepare_deliveries(notification, subscriptions)
                if not deliveries:
                    self.alert_store.mark_notification_processed(notification_id, "not_configured")
                    skipped += 1
                    continue
                self.delivery_store.enqueue_many(
                    deliveries,
                    now=notification["created_at"],
                    max_attempts=6,
                )
                self.alert_store.mark_notification_processed(notification_id, "queued")
                queued += 1
            except AlertWebhookBridgeError as error:
                self.alert_store.retry_notification(notification_id, error.code, now=moment.isoformat())
                retried += 1
            except Exception:
                self.alert_store.retry_notification(
                    notification_id, "webhook_notification_enqueue_failed", now=moment.isoformat(),
                )
                retried += 1

        return {
            "processed_count": len(pending),
            "queued_count": queued,
            "not_configured_count": skipped,
            "retry_count": retried,
        }


def main() -> int:
    try:
        signing_keys = load_signing_keys(
            os.environ.get("WIFI_ANALYZER_WEBHOOK_SIGNING_KEYS_FILE", "")
        )
        poll_seconds = float(os.environ.get("WIFI_ANALYZER_ALERT_WEBHOOK_POLL_SECONDS", "5"))
        batch_size = int(os.environ.get("WIFI_ANALYZER_ALERT_WEBHOOK_BATCH_SIZE", "50"))
    except (TypeError, ValueError) as error:
        raise SystemExit(str(error)) from None
    if not 1 <= poll_seconds <= 300:
        raise SystemExit("Alert webhook poll interval must be from 1 to 300 seconds")
    if not 1 <= batch_size <= MAX_BRIDGE_BATCH:
        raise SystemExit(f"Alert webhook batch size must be from 1 to {MAX_BRIDGE_BATCH}")

    worker = AlertWebhookBridgeWorker(signing_keys=signing_keys)
    stopping = False

    def request_stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    print("WiFi Analyzer Pro alert webhook bridge started.")
    while not stopping:
        try:
            result = worker.run_once(limit=batch_size)
            if result["processed_count"]:
                print(
                    "Alert webhook bridge processed "
                    f"{result['processed_count']} transition(s): "
                    f"{result['queued_count']} queued, "
                    f"{result['not_configured_count']} not configured, "
                    f"{result['retry_count']} retrying."
                )
            else:
                time.sleep(poll_seconds)
        except Exception:
            print("Alert webhook bridge cycle failed; inspect protected configuration and service health.")
            time.sleep(poll_seconds)
    print("WiFi Analyzer Pro alert webhook bridge stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
