"""Workspace subscription billing, signed Stripe webhooks and plan entitlements.

This module deliberately keeps provider secrets server-side. A deployment owns
one billing workspace; shared SaaS tenancy requires a separate control plane
and tenant-isolated data stores, which this local deployment does not claim.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .site_history import default_history_path


MAX_WEBHOOK_BYTES = 256 * 1024
MAX_RETAINED_EVENTS = 20_000
SIGNATURE_TOLERANCE_SECONDS = 300
PAST_DUE_GRACE_SECONDS = 72 * 60 * 60

PLAN_CATALOG = {
    "free": {
        "label": "Free",
        "limits": {"users": 1, "agents": 1, "webhook_subscriptions": 1, "sites": 1, "feature_runs_monthly": 100},
    },
    "pro": {
        "label": "Pro",
        "limits": {"users": 5, "agents": 5, "webhook_subscriptions": 5, "sites": 3, "feature_runs_monthly": 5_000},
    },
    "business": {
        "label": "Business",
        "limits": {"users": 25, "agents": 50, "webhook_subscriptions": 25, "sites": 25, "feature_runs_monthly": 25_000},
    },
    "enterprise": {
        "label": "Enterprise",
        "limits": {"users": 100, "agents": 256, "webhook_subscriptions": 100, "sites": 100, "feature_runs_monthly": 100_000},
    },
}
_PLAN_IDS = set(PLAN_CATALOG)
_PRICE_ID = re.compile(r"^price_[A-Za-z0-9]{4,128}$")
_SECRET_KEY = re.compile(r"^sk_(?:test|live)_[A-Za-z0-9]{8,}$")


class StripeSignatureError(ValueError):
    """The webhook signature is missing, malformed, invalid or stale."""


class StripeApiError(RuntimeError):
    """A Stripe API request failed without exposing response secrets."""


def default_billing_path() -> Path:
    override = os.getenv("WIFI_ANALYZER_BILLING_DB")
    if override:
        return Path(override).expanduser()
    return Path(default_history_path()).with_name("billing.sqlite3")


def configured_price_plans(environ: dict[str, str] | None = None) -> dict[str, str]:
    source = os.environ if environ is None else environ
    result = {}
    for plan_id in ("pro", "business", "enterprise"):
        price_id = source.get(f"WIFI_ANALYZER_STRIPE_PRICE_{plan_id.upper()}", "").strip()
        if price_id:
            if not _PRICE_ID.fullmatch(price_id):
                raise ValueError(f"Configured Stripe price for {plan_id} is invalid")
            if price_id in result:
                raise ValueError("Each paid plan must use a distinct Stripe price ID")
            result[price_id] = plan_id
    return result


def verify_stripe_signature(
    payload: bytes,
    signature_header: str | None,
    secret: str,
    *,
    now: float | None = None,
    tolerance_seconds: int = SIGNATURE_TOLERANCE_SECONDS,
) -> dict[str, Any]:
    """Verify Stripe's timestamped HMAC-SHA256 signature before JSON parsing."""
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_WEBHOOK_BYTES:
        raise StripeSignatureError("Webhook payload is empty or exceeds the size limit")
    if not isinstance(secret, str) or not secret.startswith("whsec_") or len(secret) < 16:
        raise StripeSignatureError("Stripe webhook signing is not configured")
    if not isinstance(signature_header, str) or len(signature_header) > 4096:
        raise StripeSignatureError("Stripe signature header is missing or invalid")
    if isinstance(tolerance_seconds, bool) or not isinstance(tolerance_seconds, int) or not 1 <= tolerance_seconds <= 3600:
        raise ValueError("tolerance_seconds must be between 1 and 3600")

    timestamp = None
    signatures = []
    for item in signature_header.split(","):
        key, separator, value = item.strip().partition("=")
        if not separator or not value:
            continue
        if key == "t":
            if timestamp is not None or not value.isdigit():
                raise StripeSignatureError("Stripe signature timestamp is malformed")
            timestamp = int(value)
        elif key == "v1":
            if re.fullmatch(r"[a-f0-9]{64}", value):
                signatures.append(value)

    if timestamp is None or not signatures:
        raise StripeSignatureError("Stripe signature header is incomplete")
    moment = time.time() if now is None else now
    if isinstance(moment, bool) or not isinstance(moment, (int, float)):
        raise ValueError("now must be a Unix timestamp")
    if abs(moment - timestamp) > tolerance_seconds:
        raise StripeSignatureError("Stripe webhook signature timestamp is outside the allowed tolerance")

    signed = str(timestamp).encode("ascii") + b"." + payload
    expected = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    if not any(hmac.compare_digest(expected, candidate) for candidate in signatures):
        raise StripeSignatureError("Stripe webhook signature verification failed")

    try:
        event = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StripeSignatureError("Signed webhook payload is not valid JSON") from error
    if not isinstance(event, dict):
        raise StripeSignatureError("Signed webhook payload must be a JSON object")
    if not isinstance(event.get("id"), str) or not re.fullmatch(r"evt_[A-Za-z0-9]{4,128}", event["id"]):
        raise StripeSignatureError("Stripe event identifier is invalid")
    if not isinstance(event.get("type"), str) or not isinstance(event.get("data"), dict):
        raise StripeSignatureError("Stripe event structure is invalid")
    if not isinstance(event["data"].get("object"), dict):
        raise StripeSignatureError("Stripe event object is invalid")
    return event


def _public_base_url(value: str) -> str:
    if not isinstance(value, str) or len(value) > 512:
        raise ValueError("WIFI_ANALYZER_PUBLIC_URL must be a valid HTTPS origin")
    parsed = urllib.parse.urlsplit(value.strip())
    host = (parsed.hostname or "").lower()
    local_http = parsed.scheme == "http" and host in {"localhost", "127.0.0.1", "::1"}
    if (
        parsed.scheme != "https" and not local_http
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or parsed.port not in {None, 80, 443}
    ):
        raise ValueError("WIFI_ANALYZER_PUBLIC_URL must be an HTTPS origin (HTTP is allowed only on loopback)")
    return f"{parsed.scheme}://{parsed.netloc}"


def _stripe_post(
    path: str,
    fields: dict[str, str],
    *,
    secret_key: str,
    opener=None,
) -> dict[str, Any]:
    if not isinstance(secret_key, str) or not _SECRET_KEY.fullmatch(secret_key):
        raise StripeApiError("Stripe secret key is not configured or has an invalid format")
    if not path.startswith("/") or ".." in path:
        raise ValueError("Invalid Stripe API path")
    body = urllib.parse.urlencode(fields).encode("ascii")
    request = urllib.request.Request(
        f"https://api.stripe.com/v1{path}",
        data=body,
        headers={
            "Authorization": f"Bearer {secret_key}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Idempotency-Key": str(uuid.uuid4()),
            "User-Agent": "WiFi-Analyzer-Pro/1.0",
        },
        method="POST",
    )
    open_request = urllib.request.urlopen if opener is None else opener
    try:
        response = open_request(request, timeout=12)
        with response:
            raw = response.read(256 * 1024 + 1)
    except urllib.error.HTTPError as error:
        try:
            error.read(4096)
        except Exception:
            pass
        raise StripeApiError(f"Stripe API returned HTTP {error.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise StripeApiError("Could not reach the Stripe API") from None
    if len(raw) > 256 * 1024:
        raise StripeApiError("Stripe API response exceeded the size limit")
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise StripeApiError("Stripe API returned an invalid response") from None
    if not isinstance(result, dict):
        raise StripeApiError("Stripe API returned an invalid response")
    return result


def create_checkout_session(
    *,
    secret_key: str,
    price_id: str,
    instance_id: str,
    public_url: str,
    customer_id: str | None = None,
    opener=None,
) -> dict[str, str]:
    if not _PRICE_ID.fullmatch(price_id or ""):
        raise ValueError("A configured Stripe price ID is required for this plan")
    if not isinstance(instance_id, str) or not re.fullmatch(r"[a-f0-9]{32}", instance_id):
        raise ValueError("Billing workspace identifier is invalid")
    base_url = _public_base_url(public_url)
    fields = {
        "mode": "subscription",
        "success_url": f"{base_url}/?billing=success",
        "cancel_url": f"{base_url}/?billing=cancel",
        "client_reference_id": instance_id,
        "line_items[0][price]": price_id,
        "line_items[0][quantity]": "1",
        "allow_promotion_codes": "true",
        "metadata[workspace_id]": instance_id,
        "subscription_data[metadata][workspace_id]": instance_id,
    }
    if customer_id:
        if not re.fullmatch(r"cus_[A-Za-z0-9]{4,128}", customer_id):
            raise ValueError("Stored Stripe customer identifier is invalid")
        fields["customer"] = customer_id
    result = _stripe_post("/checkout/sessions", fields, secret_key=secret_key, opener=opener)
    url = result.get("url")
    parsed = urllib.parse.urlsplit(url) if isinstance(url, str) else None
    if not parsed or parsed.scheme != "https" or parsed.hostname != "checkout.stripe.com":
        raise StripeApiError("Stripe did not return a valid hosted checkout URL")
    return {"checkout_session_id": str(result.get("id", "")), "url": url}


def create_billing_portal_session(
    *,
    secret_key: str,
    customer_id: str,
    public_url: str,
    opener=None,
) -> dict[str, str]:
    if not isinstance(customer_id, str) or not re.fullmatch(r"cus_[A-Za-z0-9]{4,128}", customer_id):
        raise ValueError("A valid Stripe customer is required before opening the billing portal")
    base_url = _public_base_url(public_url)
    result = _stripe_post(
        "/billing_portal/sessions",
        {"customer": customer_id, "return_url": f"{base_url}/?billing=return"},
        secret_key=secret_key,
        opener=opener,
    )
    url = result.get("url")
    parsed = urllib.parse.urlsplit(url) if isinstance(url, str) else None
    if not parsed or parsed.scheme != "https" or parsed.hostname != "billing.stripe.com":
        raise StripeApiError("Stripe did not return a valid hosted billing portal URL")
    return {"url": url}


class WorkspaceBillingStore:
    """Single-deployment billing state and idempotent Stripe event ledger."""

    def __init__(self, path: str | None = None, *, clock=time.time):
        self.path = Path(path).expanduser() if path else default_billing_path()
        self._clock = clock

    @contextmanager
    def _connection(self):
        parent = self.path.parent
        existed = parent.exists()
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt" and not existed:
            try:
                os.chmod(parent, 0o700)
            except OSError:
                pass
        connection = sqlite3.connect(str(self.path), timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS billing_instance (
                id INTEGER PRIMARY KEY CHECK(id = 1),
                instance_id TEXT NOT NULL UNIQUE
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS workspace_subscription (
                id INTEGER PRIMARY KEY CHECK(id = 1),
                stripe_customer_id TEXT,
                stripe_subscription_id TEXT,
                subscription_status TEXT,
                plan_id TEXT NOT NULL DEFAULT 'free',
                price_id TEXT,
                current_period_end REAL,
                cancel_at_period_end INTEGER NOT NULL DEFAULT 0,
                grace_until REAL,
                updated_at REAL NOT NULL
            )
            """
        )
        subscription_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(workspace_subscription)")
        }
        if "last_stripe_event_created" not in subscription_columns:
            connection.execute(
                "ALTER TABLE workspace_subscription ADD COLUMN last_stripe_event_created REAL"
            )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS stripe_webhook_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                event_type TEXT NOT NULL,
                processed_at REAL NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS workspace_monthly_usage (
                usage_month TEXT NOT NULL,
                resource TEXT NOT NULL,
                used INTEGER NOT NULL CHECK(used >= 0),
                updated_at REAL NOT NULL,
                PRIMARY KEY (usage_month, resource)
            )
            """
        )
        connection.execute(
            "INSERT OR IGNORE INTO workspace_subscription(id, plan_id, updated_at) VALUES (1, 'free', ?)",
            (float(self._clock()),),
        )
        # Commit schema/default-row initialization before application methods
        # open their own explicit BEGIN IMMEDIATE transaction.
        connection.commit()
        try:
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
            if os.name != "nt" and self.path.exists():
                try:
                    os.chmod(self.path, 0o600)
                except OSError:
                    pass

    def instance_id(self) -> str:
        with self._connection() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO billing_instance(id, instance_id) VALUES (1, ?)",
                (uuid.uuid4().hex,),
            )
            row = connection.execute("SELECT instance_id FROM billing_instance WHERE id=1").fetchone()
            return str(row["instance_id"])

    def stripe_customer_id(self) -> str | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT stripe_customer_id FROM workspace_subscription WHERE id=1"
            ).fetchone()
        return row["stripe_customer_id"] if row else None

    def status(self) -> dict[str, Any]:
        now = float(self._clock())
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM workspace_subscription WHERE id=1"
            ).fetchone()
            event_count = connection.execute(
                "SELECT COUNT(*) AS count FROM stripe_webhook_events"
            ).fetchone()["count"]
            usage_month = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m")
            usage_row = connection.execute(
                "SELECT used FROM workspace_monthly_usage WHERE usage_month=? AND resource='feature_runs'",
                (usage_month,),
            ).fetchone()
            monthly_feature_runs = int(usage_row["used"]) if usage_row else 0
        row = dict(row) if row else {}
        raw_status = row.get("subscription_status") or "inactive"
        period_end = row.get("current_period_end")
        grace_until = row.get("grace_until")
        paid_access = (
            row.get("plan_id") in _PLAN_IDS - {"free"}
            and raw_status in {"active", "trialing"}
            and isinstance(period_end, (int, float))
            and period_end > now
        )
        grace_access = (
            row.get("plan_id") in _PLAN_IDS - {"free"}
            and raw_status == "past_due"
            and isinstance(grace_until, (int, float))
            and grace_until > now
        )
        active_plan = row.get("plan_id") if paid_access or grace_access else "free"
        plan = PLAN_CATALOG[active_plan]
        period_end_text = (
            datetime.fromtimestamp(period_end, timezone.utc).isoformat()
            if isinstance(period_end, (int, float)) and period_end > 0 else None
        )
        grace_text = (
            datetime.fromtimestamp(grace_until, timezone.utc).isoformat()
            if isinstance(grace_until, (int, float)) and grace_until > 0 else None
        )
        return {
            "plan_id": active_plan,
            "plan_label": plan["label"],
            "subscription_status": raw_status,
            "active": bool(paid_access or grace_access),
            "grace_period": bool(grace_access),
            "current_period_end": period_end_text,
            "cancel_at_period_end": bool(row.get("cancel_at_period_end", False)),
            "grace_period_ends_at": grace_text,
            "limits": dict(plan["limits"]),
            "usage_period": usage_month,
            "monthly_usage": {"feature_runs": monthly_feature_runs},
            "webhook_events_retained": int(event_count),
            "billing_configured": bool(
                _SECRET_KEY.fullmatch(os.getenv("WIFI_ANALYZER_STRIPE_SECRET_KEY", ""))
                and os.getenv("WIFI_ANALYZER_PUBLIC_URL")
            ),
            "webhook_configured": bool(
                os.getenv("WIFI_ANALYZER_STRIPE_WEBHOOK_SECRET", "").startswith("whsec_")
            ),
        }

    def capacity(self, resource: str, used: int) -> dict[str, Any]:
        if resource not in {"users", "agents", "webhook_subscriptions", "sites"}:
            raise ValueError("Unknown subscription resource")
        if isinstance(used, bool) or not isinstance(used, int) or used < 0:
            raise ValueError("used must be a non-negative integer")
        status = self.status()
        limit = status["limits"][resource]
        return {
            "allowed": used < limit,
            "resource": resource,
            "used": used,
            "limit": limit,
            "plan_id": status["plan_id"],
        }

    def consume_monthly_feature_run(self) -> dict[str, Any]:
        """Atomically consume one diagnostic execution from the current UTC month."""
        now = float(self._clock())
        usage_month = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m")
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            subscription = connection.execute(
                """
                SELECT plan_id, subscription_status, current_period_end, grace_until
                FROM workspace_subscription WHERE id=1
                """
            ).fetchone()
            row = connection.execute(
                "SELECT used FROM workspace_monthly_usage WHERE usage_month=? AND resource='feature_runs'",
                (usage_month,),
            ).fetchone()

            # Re-evaluate entitlements after acquiring the SQLite write lock.
            # A concurrent Stripe cancellation/downgrade therefore wins before
            # a new run is allowed, rather than racing a stale status() read.
            subscription = dict(subscription) if subscription else {}
            raw_status = subscription.get("subscription_status") or "inactive"
            period_end = subscription.get("current_period_end")
            grace_until = subscription.get("grace_until")
            active = (
                subscription.get("plan_id") in _PLAN_IDS - {"free"}
                and raw_status in {"active", "trialing"}
                and isinstance(period_end, (int, float))
                and not isinstance(period_end, bool)
                and period_end > now
            ) or (
                subscription.get("plan_id") in _PLAN_IDS - {"free"}
                and raw_status == "past_due"
                and isinstance(grace_until, (int, float))
                and not isinstance(grace_until, bool)
                and grace_until > now
            )
            plan_id = subscription.get("plan_id") if active else "free"
            limit = int(PLAN_CATALOG[plan_id]["limits"]["feature_runs_monthly"])
            used = int(row["used"]) if row else 0
            if used >= limit:
                return {
                    "allowed": False,
                    "resource": "feature_runs_monthly",
                    "used": used,
                    "limit": limit,
                    "plan_id": plan_id,
                    "period": usage_month,
                }
            if row:
                connection.execute(
                    """
                    UPDATE workspace_monthly_usage
                    SET used=used+1, updated_at=?
                    WHERE usage_month=? AND resource='feature_runs'
                    """,
                    (now, usage_month),
                )
            else:
                connection.execute(
                    """
                    INSERT INTO workspace_monthly_usage(usage_month, resource, used, updated_at)
                    VALUES (?, 'feature_runs', 1, ?)
                    """,
                    (usage_month, now),
                )
            return {
                "allowed": True,
                "resource": "feature_runs_monthly",
                "used": used + 1,
                "limit": limit,
                "plan_id": plan_id,
                "period": usage_month,
            }

    def refund_monthly_feature_run(self, usage_period: str) -> bool:
        """Undo a reserved diagnostic run when the feature rejects or fails."""
        if not isinstance(usage_period, str) or not re.fullmatch(r"\d{4}-\d{2}", usage_period):
            raise ValueError("usage_period must use YYYY-MM format")
        now = float(self._clock())
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT used FROM workspace_monthly_usage WHERE usage_month=? AND resource='feature_runs'",
                (usage_period,),
            ).fetchone()
            if row is None or int(row["used"]) <= 0:
                return False
            if int(row["used"]) == 1:
                connection.execute(
                    "DELETE FROM workspace_monthly_usage WHERE usage_month=? AND resource='feature_runs'",
                    (usage_period,),
                )
            else:
                connection.execute(
                    """
                    UPDATE workspace_monthly_usage
                    SET used=used-1, updated_at=?
                    WHERE usage_month=? AND resource='feature_runs'
                    """,
                    (now, usage_period),
                )
        return True

    def process_stripe_event(
        self,
        event: dict[str, Any],
        *,
        price_plans: dict[str, str],
    ) -> bool:
        if not isinstance(event, dict):
            raise ValueError("Stripe event must be an object")
        event_id = event.get("id")
        event_type = event.get("type")
        data = event.get("data")
        if not isinstance(event_id, str) or not re.fullmatch(r"evt_[A-Za-z0-9]{4,128}", event_id):
            raise ValueError("Stripe event identifier is invalid")
        if not isinstance(event_type, str) or len(event_type) > 128 or not isinstance(data, dict):
            raise ValueError("Stripe event type or data is invalid")
        obj = data.get("object")
        if not isinstance(obj, dict):
            raise ValueError("Stripe event object is invalid")
        if not isinstance(price_plans, dict) or any(
            not isinstance(price, str) or not _PRICE_ID.fullmatch(price)
            or plan not in _PLAN_IDS - {"free"}
            for price, plan in price_plans.items()
        ):
            raise ValueError("Stripe price-to-plan configuration is invalid")

        now = float(self._clock())
        event_created = event.get("created", now)
        if (
            isinstance(event_created, bool)
            or not isinstance(event_created, (int, float))
            or event_created < 0
        ):
            raise ValueError("Stripe event creation timestamp is invalid")
        event_created = float(event_created)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute(
                "SELECT 1 FROM stripe_webhook_events WHERE event_id=?", (event_id,)
            ).fetchone():
                return False

            connection.execute(
                "INSERT OR IGNORE INTO billing_instance(id, instance_id) VALUES (1, ?)",
                (uuid.uuid4().hex,),
            )
            instance_id = connection.execute(
                "SELECT instance_id FROM billing_instance WHERE id=1"
            ).fetchone()["instance_id"]
            current = connection.execute(
                """
                SELECT stripe_customer_id, subscription_status, grace_until,
                       last_stripe_event_created
                FROM workspace_subscription WHERE id=1
                """
            ).fetchone()
            known_customer = current["stripe_customer_id"] if current else None

            if event_type == "checkout.session.completed":
                metadata = obj.get("metadata") if isinstance(obj.get("metadata"), dict) else {}
                workspace_ref = obj.get("client_reference_id") or metadata.get("workspace_id")
                if workspace_ref == instance_id:
                    customer_id = obj.get("customer")
                    subscription_id = obj.get("subscription")
                    if customer_id is not None and not (
                        isinstance(customer_id, str) and re.fullmatch(r"cus_[A-Za-z0-9]{4,128}", customer_id)
                    ):
                        raise ValueError("Stripe checkout customer identifier is invalid")
                    if subscription_id is not None and not (
                        isinstance(subscription_id, str) and re.fullmatch(r"sub_[A-Za-z0-9]{4,128}", subscription_id)
                    ):
                        raise ValueError("Stripe subscription identifier is invalid")
                    connection.execute(
                        """
                        UPDATE workspace_subscription
                        SET stripe_customer_id=COALESCE(?, stripe_customer_id),
                            stripe_subscription_id=COALESCE(?, stripe_subscription_id),
                            updated_at=?
                        WHERE id=1
                        """,
                        (customer_id, subscription_id, now),
                    )

            elif event_type in {
                "customer.subscription.created",
                "customer.subscription.updated",
                "customer.subscription.deleted",
            }:
                metadata = obj.get("metadata") if isinstance(obj.get("metadata"), dict) else {}
                workspace_ref = metadata.get("workspace_id")
                customer_id = obj.get("customer")
                belongs_here = workspace_ref == instance_id or (
                    isinstance(customer_id, str) and known_customer is not None
                    and hmac.compare_digest(customer_id, known_customer)
                )
                last_event_created = current["last_stripe_event_created"] if current else None
                stale_event = (
                    belongs_here
                    and last_event_created is not None
                    and event_created < float(last_event_created)
                )
                # Stripe can retry or deliver distinct events out of order.
                # Record stale events for idempotency, but never let them
                # overwrite newer subscription state.
                if belongs_here and not stale_event:
                    subscription_id = obj.get("id")
                    if not isinstance(subscription_id, str) or not re.fullmatch(r"sub_[A-Za-z0-9]{4,128}", subscription_id):
                        raise ValueError("Stripe subscription identifier is invalid")
                    items = obj.get("items") if isinstance(obj.get("items"), dict) else {}
                    item_rows = items.get("data") if isinstance(items.get("data"), list) else []
                    price_ids = []
                    for item in item_rows[:20]:
                        if isinstance(item, dict) and isinstance(item.get("price"), dict):
                            price = item["price"].get("id")
                            if isinstance(price, str) and _PRICE_ID.fullmatch(price):
                                price_ids.append(price)
                    matched_price = next((price for price in price_ids if price in price_plans), None)
                    plan_id = price_plans.get(matched_price, "free")
                    status = "canceled" if event_type == "customer.subscription.deleted" else obj.get("status", "inactive")
                    if status not in {"active", "trialing", "past_due", "unpaid", "canceled", "incomplete", "incomplete_expired", "paused"}:
                        status = "inactive"
                    period_end = obj.get("current_period_end")
                    if isinstance(period_end, bool) or not isinstance(period_end, (int, float)) or period_end <= 0:
                        period_end = None
                    cancel_at_period_end = obj.get("cancel_at_period_end", False)
                    if not isinstance(cancel_at_period_end, bool):
                        cancel_at_period_end = False
                    if status == "past_due":
                        existing_grace = current["grace_until"] if current else None
                        if (
                            current
                            and current["subscription_status"] == "past_due"
                            and isinstance(existing_grace, (int, float))
                            and not isinstance(existing_grace, bool)
                        ):
                            # Repeated past-due updates must not restart the
                            # payment grace window on every webhook delivery.
                            grace_until = float(existing_grace)
                        else:
                            grace_until = now + PAST_DUE_GRACE_SECONDS
                    else:
                        grace_until = None
                    if status == "canceled" and event_type == "customer.subscription.deleted" and period_end is None:
                        period_end = now
                    if status not in {"active", "trialing", "past_due"}:
                        plan_id = "free"
                    connection.execute(
                        """
                        UPDATE workspace_subscription SET
                            stripe_customer_id=COALESCE(?, stripe_customer_id),
                            stripe_subscription_id=?,
                            subscription_status=?,
                            plan_id=?,
                            price_id=?,
                            current_period_end=?,
                            cancel_at_period_end=?,
                            grace_until=?,
                            last_stripe_event_created=?,
                            updated_at=?
                        WHERE id=1
                        """,
                        (
                            customer_id if isinstance(customer_id, str) else None,
                            subscription_id,
                            status,
                            plan_id,
                            matched_price,
                            period_end,
                            int(cancel_at_period_end),
                            grace_until,
                            event_created,
                            now,
                        ),
                    )

            connection.execute(
                "INSERT INTO stripe_webhook_events(event_id, event_type, processed_at) VALUES (?, ?, ?)",
                (event_id, event_type, now),
            )
            connection.execute(
                """
                DELETE FROM stripe_webhook_events
                WHERE id NOT IN (
                    SELECT id FROM stripe_webhook_events
                    ORDER BY id DESC LIMIT ?
                )
                """,
                (MAX_RETAINED_EVENTS,),
            )
        return True
