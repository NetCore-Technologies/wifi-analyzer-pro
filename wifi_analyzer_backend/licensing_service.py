"""Vendor-controlled Stripe licensing service for WiFi Analyzer Pro.

Run this service on the vendor's infrastructure, not on customer installations.
It owns the vendor Stripe secret and Ed25519 private signing key. Customer
installations receive only short-lived, installation-bound signed licence
tokens and an activation secret that can renew those tokens.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

try:
    from .billing import (
        PLAN_CATALOG, StripeApiError, _stripe_post, verify_stripe_signature,
        create_billing_portal_session,
    )
    from .license import LicenseVerificationError, create_signed_license
    from .rate_limit import TokenBucketRateLimiter
except ImportError:  # Direct script execution inside the production container.
    from billing import (
        PLAN_CATALOG, StripeApiError, _stripe_post, verify_stripe_signature,
        create_billing_portal_session,
    )
    from license import LicenseVerificationError, create_signed_license
    from rate_limit import TokenBucketRateLimiter


LICENSE_TTL_SECONDS = 24 * 60 * 60
LICENSE_OFFLINE_GRACE_SECONDS = 6 * 60 * 60
PAYMENT_GRACE_SECONDS = 72 * 60 * 60
MAX_CONTROL_EVENT_COUNT = 100_000
_INSTALLATION_ID = re.compile(r"^[a-f0-9]{32}$")
_LICENSE_ID = re.compile(r"^lic_[A-Za-z0-9_-]{12,120}$")
_CUSTOMER_ID = re.compile(r"^cus_[A-Za-z0-9]{4,128}$")
_SUBSCRIPTION_ID = re.compile(r"^sub_[A-Za-z0-9]{4,128}$")
_CHECKOUT_ID = re.compile(r"^cs_(?:test|live)_[A-Za-z0-9]{8,128}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_PRICE_ID = re.compile(r"^price_[A-Za-z0-9]{4,128}$")


class LicenseServiceConflict(RuntimeError):
    """The requested licence operation conflicts with its current state."""


class LicenseNotReady(RuntimeError):
    """Stripe has not yet confirmed an active subscription for the licence."""


def configured_vendor_price_plans(environ: dict[str, str] | None = None) -> dict[str, str]:
    source = os.environ if environ is None else environ
    result = {}
    for plan_id in ("pro", "business", "enterprise"):
        price_id = source.get(f"WIFI_ANALYZER_VENDOR_STRIPE_PRICE_{plan_id.upper()}", "").strip()
        if price_id:
            if not _PRICE_ID.fullmatch(price_id):
                raise ValueError(f"Vendor Stripe price for {plan_id} is invalid")
            if price_id in result:
                raise ValueError("Vendor paid plans must use distinct Stripe prices")
            result[price_id] = plan_id
    return result


def load_vendor_signing_key(environ: dict[str, str] | None = None) -> Ed25519PrivateKey:
    source = os.environ if environ is None else environ
    encoded = source.get("WIFI_ANALYZER_VENDOR_LICENSE_SIGNING_PRIVATE_KEY", "").strip()
    if not encoded:
        key_file = source.get("WIFI_ANALYZER_VENDOR_LICENSE_SIGNING_PRIVATE_KEY_FILE", "").strip()
        if key_file:
            path = Path(key_file)
            try:
                if path.is_symlink() or not path.is_file():
                    raise ValueError("Vendor licence signing key path must be a regular, non-symlink file")
                metadata = path.stat()
                if metadata.st_size > 4096:
                    raise ValueError("Vendor licence signing key file exceeds the size limit")
                if os.name != "nt" and metadata.st_mode & 0o077:
                    raise ValueError("Vendor licence signing key file permissions must exclude group and other access")
                encoded = path.read_text(encoding="ascii").strip()
            except (OSError, UnicodeDecodeError) as error:
                raise ValueError("Vendor licence signing key file cannot be read") from error
    if not encoded:
        raise ValueError("Vendor licence signing private key is not configured")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise ValueError("Vendor licence signing private key must be base64") from error
    if len(raw) != 32:
        raise ValueError("Vendor Ed25519 private key must contain 32 raw bytes")
    return Ed25519PrivateKey.from_private_bytes(raw)


def vendor_public_key_text(private_key: Ed25519PrivateKey) -> str:
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(public_key).decode("ascii")


def _service_public_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value.strip() if isinstance(value, str) else "")
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or parsed.port not in {None, 443}
    ):
        raise ValueError("Vendor licence service URL must be a public HTTPS origin")
    return f"https://{parsed.netloc}"


class VendorLicenseService:
    """Multi-installation vendor subscription and signed licence issuer."""

    def __init__(
        self,
        path: str | os.PathLike,
        *,
        stripe_secret_key: str,
        stripe_webhook_secret: str,
        public_url: str,
        price_plans: dict[str, str],
        signing_private_key: Ed25519PrivateKey,
        key_id: str = "primary",
        admin_token: str | None = None,
        clock=time.time,
        stripe_opener=None,
    ):
        if not isinstance(stripe_secret_key, str) or not re.fullmatch(r"sk_(?:test|live)_[A-Za-z0-9]{8,}", stripe_secret_key):
            raise ValueError("Vendor Stripe secret key is missing or invalid")
        if not isinstance(stripe_webhook_secret, str) or not stripe_webhook_secret.startswith("whsec_"):
            raise ValueError("Vendor Stripe webhook secret is missing or invalid")
        if not isinstance(signing_private_key, Ed25519PrivateKey):
            raise ValueError("Vendor Ed25519 signing private key is required")
        if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
            raise ValueError("Vendor signing key ID is invalid")
        if not isinstance(price_plans, dict) or not price_plans:
            raise ValueError("At least one vendor Stripe price must be configured")
        for price_id, plan_id in price_plans.items():
            if (
                not isinstance(price_id, str) or not _PRICE_ID.fullmatch(price_id)
                or plan_id not in {"pro", "business", "enterprise"}
            ):
                raise ValueError("Vendor Stripe price-to-plan mapping is invalid")
        self.path = Path(path).expanduser()
        self.stripe_secret_key = stripe_secret_key
        self.stripe_webhook_secret = stripe_webhook_secret
        self.public_url = _service_public_url(public_url)
        self.price_plans = dict(price_plans)
        self.signing_private_key = signing_private_key
        self.key_id = key_id
        if admin_token is not None and (
            not isinstance(admin_token, str) or len(admin_token) < 32 or len(admin_token) > 512
        ):
            raise ValueError("Vendor admin token must contain 32 to 512 characters")
        self._admin_token_hash = (
            hashlib.sha256(admin_token.encode("utf-8")).digest()
            if isinstance(admin_token, str) else None
        )
        self._clock = clock
        self._stripe_opener = stripe_opener
        self._lock = threading.RLock()

    @contextmanager
    def _connection(self):
        parent = self.path.parent
        existed = parent.exists()
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt" and not existed:
            os.chmod(parent, 0o700)
        connection = sqlite3.connect(str(self.path), timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS vendor_licenses (
                license_id TEXT PRIMARY KEY,
                installation_id TEXT NOT NULL,
                activation_secret_hash TEXT NOT NULL,
                plan_id TEXT NOT NULL,
                price_id TEXT NOT NULL,
                checkout_session_id TEXT UNIQUE,
                stripe_customer_id TEXT,
                stripe_subscription_id TEXT,
                subscription_status TEXT NOT NULL DEFAULT 'pending',
                current_period_end REAL,
                grace_until REAL,
                cancel_at_period_end INTEGER NOT NULL DEFAULT 0,
                last_subscription_event_created REAL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            )
            """
        )
        license_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(vendor_licenses)")
        }
        migrations = {
            "customer_email": "TEXT",
            "unit_amount": "INTEGER",
            "currency": "TEXT",
            "billing_interval": "TEXT",
            "interval_count": "INTEGER NOT NULL DEFAULT 1",
        }
        for column, declaration in migrations.items():
            if column not in license_columns:
                connection.execute(f"ALTER TABLE vendor_licenses ADD COLUMN {column} {declaration}")
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_vendor_licenses_installation ON vendor_licenses(installation_id, created_at DESC)"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS vendor_stripe_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                event_type TEXT NOT NULL,
                processed_at REAL NOT NULL
            )
            """
        )
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

    def _active_row(self, connection, installation_id: str, now: float):
        rows = connection.execute(
            """
            SELECT * FROM vendor_licenses
            WHERE installation_id=?
            ORDER BY created_at DESC
            LIMIT 10
            """,
            (installation_id,),
        ).fetchall()
        for row in rows:
            status = row["subscription_status"]
            period_end = row["current_period_end"]
            grace_until = row["grace_until"]
            if (
                status in {"active", "trialing"}
                and isinstance(period_end, (int, float))
                and period_end > now
            ) or (
                status == "past_due"
                and isinstance(grace_until, (int, float))
                and grace_until > now
            ):
                return row
        return None

    def create_checkout(
        self,
        *,
        installation_id: str,
        plan_id: str,
        customer_email: str | None = None,
    ) -> dict[str, str]:
        if not isinstance(installation_id, str) or not _INSTALLATION_ID.fullmatch(installation_id):
            raise ValueError("Installation identifier is invalid")
        if plan_id not in {"pro", "business", "enterprise"}:
            raise ValueError("plan_id must be pro, business or enterprise")
        price_id = next((key for key, mapped in self.price_plans.items() if mapped == plan_id), None)
        if not price_id:
            raise ValueError(f"Vendor Stripe price for {plan_id} is not configured")
        email = None
        if customer_email is not None:
            if (
                not isinstance(customer_email, str)
                or len(customer_email) > 254
                or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", customer_email)
            ):
                raise ValueError("customer_email must be a valid email address")
            email = customer_email

        now = float(self._clock())
        license_id = "lic_" + secrets.token_urlsafe(24)
        activation_secret = secrets.token_urlsafe(32)
        activation_hash = hashlib.sha256(activation_secret.encode("utf-8")).hexdigest()
        with self._lock, self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if self._active_row(connection, installation_id, now):
                raise LicenseServiceConflict("This installation already has an active vendor subscription")
            pending = connection.execute(
                """
                SELECT license_id FROM vendor_licenses
                WHERE installation_id=? AND subscription_status='pending' AND created_at>?
                LIMIT 1
                """,
                (installation_id, now - 30 * 60),
            ).fetchone()
            if pending:
                raise LicenseServiceConflict("A checkout is already pending for this installation; finish it or try again later")
            connection.execute(
                """
                INSERT INTO vendor_licenses(
                    license_id, installation_id, activation_secret_hash,
                    plan_id, price_id, subscription_status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
                """,
                (license_id, installation_id, activation_hash, plan_id, price_id, now, now),
            )

        fields = {
            "mode": "subscription",
            "success_url": f"{self.public_url}/checkout/success",
            "cancel_url": f"{self.public_url}/checkout/cancel",
            "client_reference_id": installation_id,
            "line_items[0][price]": price_id,
            "line_items[0][quantity]": "1",
            "allow_promotion_codes": "true",
            "metadata[installation_id]": installation_id,
            "metadata[license_id]": license_id,
            "metadata[plan_id]": plan_id,
            "subscription_data[metadata][installation_id]": installation_id,
            "subscription_data[metadata][license_id]": license_id,
            "subscription_data[metadata][plan_id]": plan_id,
        }
        if email:
            fields["customer_email"] = email

        try:
            result = _stripe_post(
                "/checkout/sessions",
                fields,
                secret_key=self.stripe_secret_key,
                opener=self._stripe_opener,
            )
            checkout_url = result.get("url")
            checkout_id = result.get("id")
            parsed = urllib.parse.urlsplit(checkout_url) if isinstance(checkout_url, str) else None
            if (
                not parsed
                or parsed.scheme != "https"
                or parsed.hostname != "checkout.stripe.com"
                or not isinstance(checkout_id, str)
                or not _CHECKOUT_ID.fullmatch(checkout_id)
            ):
                raise StripeApiError("Stripe did not return a valid hosted checkout session")
            with self._connection() as connection:
                connection.execute(
                    """
                    UPDATE vendor_licenses
                    SET checkout_session_id=?, updated_at=?
                    WHERE license_id=? AND installation_id=?
                    """,
                    (checkout_id, float(self._clock()), license_id, installation_id),
                )
        except Exception:
            with self._connection() as connection:
                connection.execute("DELETE FROM vendor_licenses WHERE license_id=?", (license_id,))
            raise

        return {
            "license_id": license_id,
            "checkout_session_id": checkout_id,
            "checkout_url": checkout_url,
            "activation_secret": activation_secret,
        }

    def receive_webhook(self, payload: bytes, signature_header: str | None) -> dict[str, Any]:
        event = verify_stripe_signature(
            payload,
            signature_header,
            self.stripe_webhook_secret,
            now=self._clock(),
        )
        return self.process_event(event)

    def process_event(self, event: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(event, dict):
            raise ValueError("Stripe event must be an object")
        event_id = event.get("id")
        event_type = event.get("type")
        created = event.get("created", self._clock())
        data = event.get("data")
        if (
            not isinstance(event_id, str)
            or not re.fullmatch(r"evt_[A-Za-z0-9]{4,128}", event_id)
            or not isinstance(event_type, str)
            or not isinstance(data, dict)
            or not isinstance(data.get("object"), dict)
            or isinstance(created, bool)
            or not isinstance(created, (int, float))
            or created < 0
        ):
            raise ValueError("Stripe event structure is invalid")
        obj = data["object"]
        now = float(self._clock())
        stale = False
        matched = False
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute(
                "SELECT 1 FROM vendor_stripe_events WHERE event_id=?", (event_id,)
            ).fetchone():
                return {"processed": False, "duplicate": True, "matched": False}
            metadata = obj.get("metadata") if isinstance(obj.get("metadata"), dict) else {}
            license_id = metadata.get("license_id")
            installation_id = metadata.get("installation_id")
            row = None
            if isinstance(license_id, str) and _LICENSE_ID.fullmatch(license_id):
                row = connection.execute(
                    "SELECT * FROM vendor_licenses WHERE license_id=?",
                    (license_id,),
                ).fetchone()
            if row is None and event_type.startswith("customer.subscription."):
                subscription_id = obj.get("id")
                if isinstance(subscription_id, str) and _SUBSCRIPTION_ID.fullmatch(subscription_id):
                    row = connection.execute(
                        "SELECT * FROM vendor_licenses WHERE stripe_subscription_id=?",
                        (subscription_id,),
                    ).fetchone()
            if row is not None:
                matched = True
                if installation_id is not None and installation_id != row["installation_id"]:
                    raise ValueError("Stripe event installation binding does not match the stored licence")
                if event_type == "checkout.session.completed":
                    checkout_id = obj.get("id")
                    if (
                        obj.get("mode") == "subscription"
                        and obj.get("payment_status") in {"paid", "no_payment_required"}
                        and isinstance(checkout_id, str)
                        and _CHECKOUT_ID.fullmatch(checkout_id)
                    ):
                        customer_id = obj.get("customer")
                        subscription_id = obj.get("subscription")
                        if customer_id is not None and not (
                            isinstance(customer_id, str) and _CUSTOMER_ID.fullmatch(customer_id)
                        ):
                            raise ValueError("Stripe customer identifier is invalid")
                        if subscription_id is not None and not (
                            isinstance(subscription_id, str) and _SUBSCRIPTION_ID.fullmatch(subscription_id)
                        ):
                            raise ValueError("Stripe subscription identifier is invalid")
                        if (
                            row["checkout_session_id"] is None
                            or hmac.compare_digest(row["checkout_session_id"], checkout_id)
                        ):
                            connection.execute(
                                """
                                UPDATE vendor_licenses SET
                                    checkout_session_id=?,
                                    stripe_customer_id=COALESCE(?, stripe_customer_id),
                                    stripe_subscription_id=COALESCE(?, stripe_subscription_id),
                                    customer_email=COALESCE(?, customer_email),
                                    updated_at=?
                                WHERE license_id=?
                                """,
                                (
                                    checkout_id, customer_id, subscription_id,
                                    (
                                        (obj.get("customer_details") or {}).get("email")
                                        if isinstance(obj.get("customer_details"), dict)
                                        else obj.get("customer_email")
                                    ),
                                    now, license_id,
                                ),
                            )
                elif event_type in {
                    "customer.subscription.created",
                    "customer.subscription.updated",
                    "customer.subscription.deleted",
                }:
                    subscription_id = obj.get("id")
                    customer_id = obj.get("customer")
                    if not isinstance(subscription_id, str) or not _SUBSCRIPTION_ID.fullmatch(subscription_id):
                        raise ValueError("Stripe subscription identifier is invalid")
                    if customer_id is not None and not (
                        isinstance(customer_id, str) and _CUSTOMER_ID.fullmatch(customer_id)
                    ):
                        raise ValueError("Stripe customer identifier is invalid")
                    prior_created = row["last_subscription_event_created"]
                    stale = prior_created is not None and float(created) < float(prior_created)
                    if not stale:
                        item_list = obj.get("items") if isinstance(obj.get("items"), dict) else {}
                        items = item_list.get("data") if isinstance(item_list.get("data"), list) else []
                        recognised_items = []
                        for item in items[:20]:
                            if isinstance(item, dict) and isinstance(item.get("price"), dict):
                                candidate = item["price"].get("id")
                                if isinstance(candidate, str) and candidate in self.price_plans:
                                    recognised_items.append(item["price"])
                        price_object = recognised_items[0] if recognised_items else {}
                        matched_price = price_object.get("id") if isinstance(price_object.get("id"), str) else None
                        plan_id = self.price_plans.get(matched_price, "free")
                        amount = price_object.get("unit_amount")
                        unit_amount = (
                            amount if isinstance(amount, int) and not isinstance(amount, bool) and amount >= 0
                            else None
                        )
                        currency = price_object.get("currency")
                        if not isinstance(currency, str) or not re.fullmatch(r"[A-Za-z]{3}", currency):
                            currency = None
                        else:
                            currency = currency.lower()
                        recurring = price_object.get("recurring") if isinstance(price_object.get("recurring"), dict) else {}
                        billing_interval = recurring.get("interval")
                        if billing_interval not in {"day", "week", "month", "year"}:
                            billing_interval = None
                        interval_count = recurring.get("interval_count", 1)
                        if (
                            isinstance(interval_count, bool) or not isinstance(interval_count, int)
                            or not 1 <= interval_count <= 12
                        ):
                            interval_count = 1
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
                            old_grace = row["grace_until"]
                            if row["subscription_status"] == "past_due" and isinstance(old_grace, (int, float)):
                                grace_until = float(old_grace)
                            else:
                                grace_until = now + PAYMENT_GRACE_SECONDS
                        else:
                            grace_until = None
                        if status not in {"active", "trialing", "past_due"}:
                            plan_id = "free"
                        connection.execute(
                            """
                            UPDATE vendor_licenses SET
                                stripe_customer_id=COALESCE(?, stripe_customer_id),
                                stripe_subscription_id=?,
                                subscription_status=?,
                                plan_id=?,
                                price_id=?,
                                unit_amount=?,
                                currency=?,
                                billing_interval=?,
                                interval_count=?,
                                current_period_end=?,
                                grace_until=?,
                                cancel_at_period_end=?,
                                last_subscription_event_created=?,
                                updated_at=?
                            WHERE license_id=?
                            """,
                            (
                                customer_id if isinstance(customer_id, str) else None,
                                subscription_id, status, plan_id, matched_price,
                                unit_amount, currency, billing_interval, interval_count,
                                period_end, grace_until, int(cancel_at_period_end),
                                float(created), now, license_id,
                            ),
                        )
            connection.execute(
                "INSERT INTO vendor_stripe_events(event_id, event_type, processed_at) VALUES (?, ?, ?)",
                (event_id, event_type, now),
            )
            connection.execute(
                """
                DELETE FROM vendor_stripe_events
                WHERE id NOT IN (
                    SELECT id FROM vendor_stripe_events ORDER BY id DESC LIMIT ?
                )
                """,
                (MAX_CONTROL_EVENT_COUNT,),
            )
        return {"processed": True, "duplicate": False, "matched": matched, "stale": stale}

    def create_portal_session(
        self,
        *,
        installation_id: str,
        license_id: str,
        activation_secret: str,
    ) -> dict[str, str]:
        if not isinstance(installation_id, str) or not _INSTALLATION_ID.fullmatch(installation_id):
            raise ValueError("Installation identifier is invalid")
        if not isinstance(license_id, str) or not _LICENSE_ID.fullmatch(license_id):
            raise ValueError("Vendor licence identifier is invalid")
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM vendor_licenses WHERE license_id=? AND installation_id=?",
                (license_id, installation_id),
            ).fetchone()
            if row is None:
                raise LicenseNotReady("Vendor licence was not found for this installation")
            self._verify_activation_secret(row, activation_secret)
            customer_id = row["stripe_customer_id"]
            if not isinstance(customer_id, str) or not _CUSTOMER_ID.fullmatch(customer_id):
                raise LicenseNotReady("The vendor Stripe customer has not been confirmed yet")
        return create_billing_portal_session(
            secret_key=self.stripe_secret_key,
            customer_id=customer_id,
            public_url=self.public_url,
            opener=self._stripe_opener,
        )

    def _issue_license(self, row, now: float) -> dict[str, Any]:
        status = row["subscription_status"]
        period_end = row["current_period_end"]
        grace_until = row["grace_until"]
        if status in {"active", "trialing"} and isinstance(period_end, (int, float)) and period_end > now:
            access_until = float(period_end)
        elif status == "past_due" and isinstance(grace_until, (int, float)) and grace_until > now:
            access_until = float(grace_until)
        else:
            raise LicenseNotReady("Stripe has not confirmed an active subscription for this installation")
        plan_id = row["plan_id"]
        if plan_id not in {"pro", "business", "enterprise"}:
            raise LicenseNotReady("This subscription does not have a valid paid product plan")
        expires_at = int(min(now + LICENSE_TTL_SECONDS, access_until))
        claims = {
            "schema": "wifi-analyzer-pro.vendor-license.v1",
            "key_id": self.key_id,
            "license_id": row["license_id"],
            "installation_id": row["installation_id"],
            "plan_id": plan_id,
            "issued_at": int(now),
            "expires_at": expires_at,
            "offline_grace_seconds": LICENSE_OFFLINE_GRACE_SECONDS,
            "limits": dict(PLAN_CATALOG[plan_id]["limits"]),
        }
        return {
            "license_token": create_signed_license(claims, self.signing_private_key),
            "license_id": row["license_id"],
            "plan_id": plan_id,
            "expires_at": expires_at,
            "subscription_status": status,
        }

    def claim_license(
        self,
        *,
        installation_id: str,
        checkout_session_id: str,
        activation_secret: str,
    ) -> dict[str, Any]:
        if not isinstance(installation_id, str) or not _INSTALLATION_ID.fullmatch(installation_id):
            raise ValueError("Installation identifier is invalid")
        if not isinstance(checkout_session_id, str) or not _CHECKOUT_ID.fullmatch(checkout_session_id):
            raise ValueError("Stripe Checkout session identifier is invalid")
        now = float(self._clock())
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT * FROM vendor_licenses
                WHERE installation_id=? AND checkout_session_id=?
                """,
                (installation_id, checkout_session_id),
            ).fetchone()
            if row is None:
                raise LicenseNotReady("Checkout has not been confirmed by Stripe yet")
            self._verify_activation_secret(row, activation_secret)
            return self._issue_license(row, now)

    def refresh_license(
        self,
        *,
        installation_id: str,
        license_id: str,
        activation_secret: str,
    ) -> dict[str, Any]:
        if not isinstance(installation_id, str) or not _INSTALLATION_ID.fullmatch(installation_id):
            raise ValueError("Installation identifier is invalid")
        if not isinstance(license_id, str) or not _LICENSE_ID.fullmatch(license_id):
            raise ValueError("Vendor licence identifier is invalid")
        now = float(self._clock())
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM vendor_licenses WHERE license_id=? AND installation_id=?",
                (license_id, installation_id),
            ).fetchone()
            if row is None:
                raise LicenseNotReady("Vendor licence was not found for this installation")
            self._verify_activation_secret(row, activation_secret)
            return self._issue_license(row, now)

    @staticmethod
    def _verify_activation_secret(row, activation_secret: str) -> None:
        if not isinstance(activation_secret, str) or not 32 <= len(activation_secret) <= 256:
            raise LicenseVerificationError("Vendor licence activation credential is invalid")
        digest = hashlib.sha256(activation_secret.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(digest, row["activation_secret_hash"]):
            raise LicenseVerificationError("Vendor licence activation credential is invalid")

    def authenticate_admin(self, authorization: str | None) -> bool:
        if self._admin_token_hash is None or not isinstance(authorization, str):
            return False
        scheme, separator, token = authorization.partition(" ")
        if not separator or scheme.lower() != "bearer" or not 32 <= len(token) <= 512:
            return False
        candidate = hashlib.sha256(token.encode("utf-8")).digest()
        return hmac.compare_digest(candidate, self._admin_token_hash)

    @staticmethod
    def _is_access_active(row, now: float) -> bool:
        return (
            row["plan_id"] in {"pro", "business", "enterprise"}
            and row["subscription_status"] in {"active", "trialing"}
            and isinstance(row["current_period_end"], (int, float))
            and not isinstance(row["current_period_end"], bool)
            and row["current_period_end"] > now
        )

    def admin_summary(self) -> dict[str, Any]:
        now = float(self._clock())
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT plan_id, subscription_status, current_period_end, grace_until,
                       unit_amount, currency, billing_interval, interval_count,
                       cancel_at_period_end
                FROM vendor_licenses
                """
            ).fetchall()
            event_row = connection.execute(
                "SELECT COUNT(*) AS count, MAX(processed_at) AS last_processed FROM vendor_stripe_events"
            ).fetchone()
        active = []
        pending = grace = expired = canceling = unmapped = 0
        plan_counts: dict[str, int] = {}
        currency_totals: dict[str, dict[str, int]] = {}
        for row in rows:
            if row["subscription_status"] == "pending":
                pending += 1
            elif (
                row["subscription_status"] == "past_due"
                and isinstance(row["grace_until"], (int, float))
                and row["grace_until"] > now
            ):
                grace += 1
            elif self._is_access_active(row, now):
                active.append(row)
            elif (
                row["subscription_status"] in {"active", "trialing"}
                and isinstance(row["current_period_end"], (int, float))
                and not isinstance(row["current_period_end"], bool)
                and row["current_period_end"] > now
                and row["plan_id"] not in {"pro", "business", "enterprise"}
            ):
                # An active Stripe record with an unknown/unconfigured Price
                # is not a paid product entitlement and must not inflate MRR.
                unmapped += 1
            else:
                expired += 1
            if row["cancel_at_period_end"]:
                canceling += 1
        for row in active:
            plan = row["plan_id"]
            plan_counts[plan] = plan_counts.get(plan, 0) + 1
            currency, amount = row["currency"], row["unit_amount"]
            interval, count = row["billing_interval"], row["interval_count"]
            if (
                not isinstance(currency, str) or not re.fullmatch(r"[a-z]{3}", currency)
                or isinstance(amount, bool) or not isinstance(amount, int) or amount < 0
                or interval not in {"day", "week", "month", "year"}
                or isinstance(count, bool) or not isinstance(count, int) or count < 1
            ):
                continue
            factor = {"day": 365, "week": 52, "month": 12, "year": 1}[interval] / (12 * count)
            totals = currency_totals.setdefault(
                currency, {"active_subscriptions": 0, "catalog_mrr_minor_units": 0},
            )
            totals["active_subscriptions"] += 1
            totals["catalog_mrr_minor_units"] += int(round(amount * factor))
        return {
            "total_licenses": len(rows),
            "active_subscriptions": len(active),
            "pending_checkouts": pending,
            "payment_grace_subscriptions": grace,
            "expired_or_cancelled": expired,
            "unmapped_price_subscriptions": unmapped,
            "scheduled_cancellations": canceling,
            "active_plan_counts": dict(sorted(plan_counts.items())),
            "catalog_mrr_by_currency": [
                {"currency": currency, **totals}
                for currency, totals in sorted(currency_totals.items())
            ],
            "stripe_events_processed": int(event_row["count"]),
            "last_stripe_event_at": event_row["last_processed"],
            "calculated_at": now,
        }

    def admin_list_licenses(self, limit: int = 100) -> dict[str, Any]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
            raise ValueError("limit must be an integer from 1 to 200")
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT license_id, installation_id, plan_id, price_id,
                       customer_email, stripe_customer_id, stripe_subscription_id,
                       subscription_status, current_period_end, grace_until,
                       cancel_at_period_end, unit_amount, currency,
                       billing_interval, interval_count, created_at, updated_at
                FROM vendor_licenses ORDER BY updated_at DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        records = []
        for row in rows:
            item = dict(row)
            if (
                item["subscription_status"] in {"active", "trialing"}
                and item["plan_id"] not in {"pro", "business", "enterprise"}
            ):
                item["price_mapping_state"] = "unmapped"
                item["plan_id"] = "unmapped"
            else:
                item["price_mapping_state"] = "mapped"
            records.append(item)
        return {"licenses": records, "limit": limit}

    def public_key(self) -> dict[str, str]:
        public = self.signing_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return {"key_id": self.key_id, "public_key": base64.b64encode(public).decode("ascii")}


ADMIN_DASHBOARD_HTML = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><title>NetCore Licensing Operations</title>
<style>
:root{color-scheme:dark;--bg:#08111b;--panel:#0e1b29;--line:#23384a;--text:#e8f1f7;--muted:#8da2b4;--accent:#50e3d2;--warn:#ffc66d;--bad:#ff8b91}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top right,#14324a 0,#08111b 48%);color:var(--text);font:14px system-ui,sans-serif}
header{padding:24px clamp(18px,4vw,52px);border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center;gap:18px;flex-wrap:wrap}
h1{font-size:20px;margin:0;letter-spacing:.02em}header p{margin:5px 0 0;color:var(--muted);font-size:12px}main{max-width:1440px;margin:0 auto;padding:28px clamp(16px,4vw,52px) 60px}
.card{background:linear-gradient(145deg,#112233ee,#0c1926ee);border:1px solid var(--line);border-radius:13px;padding:18px;box-shadow:0 12px 35px #0003}
.login{max-width:520px;margin:9vh auto}.login h2{font-size:16px;margin:0 0 8px}.login p{color:var(--muted);font-size:12px;line-height:1.6}
label{display:block;color:var(--muted);font-size:11px;margin:15px 0 7px}input{width:100%;padding:12px;border:1px solid #2c4458;border-radius:8px;background:#07121e;color:var(--text);font:13px ui-monospace,monospace}
button{border:1px solid #50e3d2aa;background:#14323a;color:var(--accent);border-radius:8px;padding:10px 14px;font-weight:700;cursor:pointer}button:disabled{opacity:.55;cursor:wait}.secondary{border-color:var(--line);background:#102031;color:var(--text)}
.toolbar{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:18px}.status{min-height:18px;margin-top:10px;color:var(--muted);font-size:12px}.status.error{color:var(--bad)}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:14px 0 18px}.metric{min-height:105px}.metric .label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.1em}.metric .value{font:26px ui-monospace,monospace;margin-top:12px}.metric .hint{font-size:10px;color:var(--muted);margin-top:5px}
.section{margin-top:18px}.section h2{font-size:15px;margin:0 0 12px}.section p{font-size:11px;color:var(--muted);margin:-4px 0 13px}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:9px}
table{width:100%;border-collapse:collapse;min-width:720px;font-size:11px}th,td{padding:10px 12px;text-align:left;border-bottom:1px solid #223548;white-space:nowrap}th{background:#102031;color:var(--muted);font-weight:600;position:sticky;top:0}tr:last-child td{border-bottom:0}
.pill{display:inline-block;border:1px solid #294356;border-radius:99px;padding:3px 7px;color:var(--accent);font-size:9px;text-transform:uppercase}.muted{color:var(--muted)}.warning{color:var(--warn)}.foot{margin-top:20px;color:var(--muted);font-size:10px;line-height:1.6}
@media(max-width:900px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:520px){.grid{grid-template-columns:1fr}header{align-items:flex-start}.toolbar{align-items:flex-start}}
</style></head>
<body>
<header><div><h1>NETCORE / LICENSING OPERATIONS</h1><p>Vendor subscriptions · licence fleet · catalogue MRR</p></div><span class="pill">Vendor-only</span></header>
<main>
<section class="card login" id="login">
<h2>Connect to vendor control plane</h2><p>Enter the vendor admin bearer token from the protected <code>.env.vendor</code> file. It remains in page memory and is never written to browser storage, cookies or URLs.</p>
<form id="login-form"><label for="admin-token">Vendor admin token</label><input id="admin-token" type="password" autocomplete="off" minlength="32" required><div style="display:flex;justify-content:flex-end;margin-top:12px"><button id="connect" type="submit">Connect securely</button></div></form>
<div id="login-status" class="status" role="status" aria-live="polite"></div>
</section>
<section id="dashboard" hidden>
<div class="toolbar"><div><strong>Subscription overview</strong><div class="muted" style="font-size:11px;margin-top:4px">Read-only vendor licensing database view.</div></div><div style="display:flex;gap:8px"><button class="secondary" id="refresh">Refresh</button><button class="secondary" id="disconnect">Disconnect</button></div></div>
<div id="status" class="status" role="status" aria-live="polite"></div>
<div class="grid">
<article class="card metric"><div class="label">Active subscriptions</div><div class="value" id="active">—</div><div class="hint" id="plans">Plan distribution pending</div></article>
<article class="card metric"><div class="label">Pending checkouts</div><div class="value" id="pending">—</div><div class="hint">Awaiting Stripe confirmation</div></article>
<article class="card metric"><div class="label">Payment grace</div><div class="value" id="grace">—</div><div class="hint">Past due inside grace window</div></article>
<article class="card metric"><div class="label">Expired / cancelled</div><div class="value" id="expired">—</div><div class="hint" id="canceling">Scheduled cancellations: —</div></article>
</div>
<section class="card section"><h2>Catalogue MRR by currency</h2><p>Stripe recurring list-price value normalised monthly. This is not collected cash, net revenue or profit.</p><div class="table-wrap"><table><thead><tr><th>Currency</th><th>Active subscriptions</th><th>Catalogue MRR</th></tr></thead><tbody id="mrr-body"><tr><td colspan="3" class="muted">Connect to load data.</td></tr></tbody></table></div></section>
<section class="card section"><h2>Recent customer licences</h2><p>Support and reconciliation view. Activation secrets, secret hashes and Checkout session IDs are never returned by this API.</p><div class="table-wrap"><table><thead><tr><th>Customer</th><th>Plan</th><th>Status</th><th>Currency</th><th>Recurring price</th><th>Period end</th><th>Cancel at period end</th></tr></thead><tbody id="license-body"><tr><td colspan="7" class="muted">Connect to load licences.</td></tr></tbody></table></div></section>
<div class="foot">Last Stripe event: <span id="last-event">—</span> · Calculated: <span id="calculated">—</span><br>Disconnect when finished. Restrict the service behind VPN/IP allowlists and a trusted TLS proxy. Rotate the token if exposed.</div>
</section></main>
<script nonce="__NONCE__">
(() => {
"use strict";
let adminToken="";
const $=id=>document.getElementById(id);
const number=value=>Number.isFinite(Number(value))?Number(value).toLocaleString():"—";
const date=value=>{if(!value)return "—";const parsed=new Date(Number(value)*1000);return Number.isNaN(parsed.getTime())?"—":parsed.toLocaleString();};
const setStatus=(message,error=false)=>{const node=$("status");node.textContent=message||"";node.className=error?"status error":"status";};
const formatMoney=(minor,currency)=>{
 if(!currency||!Number.isFinite(Number(minor)))return "—";
 try{const code=String(currency).toUpperCase();const digits=new Intl.NumberFormat(undefined,{style:"currency",currency:code}).resolvedOptions().maximumFractionDigits;return new Intl.NumberFormat(undefined,{style:"currency",currency:code}).format(Number(minor)/(10**digits));}
 catch{return String(currency)+" "+String(minor);}
};
const cell=(row,value,className="")=>{const td=document.createElement("td");td.textContent=value===null||value===undefined||value===""?"—":String(value);if(className)td.className=className;row.appendChild(td);return td;};
const request=async path=>{
 const response=await fetch(path,{method:"GET",headers:{Authorization:"Bearer "+adminToken,Accept:"application/json"},cache:"no-store",credentials:"omit",redirect:"error"});
 let data;try{data=await response.json();}catch{throw new Error("Vendor API returned HTTP "+response.status+" with invalid JSON");}
 if(!response.ok)throw new Error(data.error||"Vendor API returned HTTP "+response.status);return data;
};
const renderSummary=summary=>{
 $("active").textContent=number(summary.active_subscriptions);$("pending").textContent=number(summary.pending_checkouts);$("grace").textContent=number(summary.payment_grace_subscriptions);$("expired").textContent=number(summary.expired_or_cancelled);
 $("canceling").textContent="Scheduled cancellations: "+number(summary.scheduled_cancellations);
 const plans=Object.entries(summary.active_plan_counts||{}).map(([key,value])=>key+": "+number(value));$("plans").textContent=plans.join(" · ")||"No active paid plans";
 $("last-event").textContent=date(summary.last_stripe_event_at);$("calculated").textContent=date(summary.calculated_at);
 const body=$("mrr-body");body.replaceChildren();const totals=summary.catalog_mrr_by_currency||[];
 if(!totals.length){const row=document.createElement("tr");const td=cell(row,"No priced active subscriptions","muted");td.colSpan=3;body.appendChild(row);}
 for(const total of totals){const row=document.createElement("tr");cell(row,String(total.currency||"").toUpperCase());cell(row,number(total.active_subscriptions));cell(row,formatMoney(total.catalog_mrr_minor_units,total.currency));body.appendChild(row);}
};
const renderLicenses=result=>{
 const body=$("license-body");body.replaceChildren();const records=result.licenses||[];
 if(!records.length){const row=document.createElement("tr");const td=cell(row,"No licences found","muted");td.colSpan=7;body.appendChild(row);return;}
 for(const item of records){const row=document.createElement("tr");cell(row,item.customer_email||item.installation_id);cell(row,item.plan_id);cell(row,item.subscription_status,item.subscription_status==="active"?"":"warning");cell(row,item.currency?String(item.currency).toUpperCase():"—");const recurring=item.unit_amount===null||item.unit_amount===undefined?"—":formatMoney(item.unit_amount,item.currency)+" / "+(item.billing_interval||"period");cell(row,recurring);cell(row,date(item.current_period_end));cell(row,item.cancel_at_period_end?"Yes":"No");body.appendChild(row);}
};
const refresh=async()=>{
 $("refresh").disabled=true;setStatus("Refreshing vendor subscription data…");
 try{const values=await Promise.all([request("/api/admin/summary"),request("/api/admin/licenses?limit=100")]);renderSummary(values[0].summary);renderLicenses(values[1]);setStatus("Vendor billing data refreshed.");}
 catch(error){setStatus(error.message||"Could not load vendor subscription data.",true);}
 finally{$("refresh").disabled=false;}
};
$("login-form").addEventListener("submit",async event=>{
 event.preventDefault();const candidate=$("admin-token").value;
 if(candidate.length<32){$("login-status").textContent="Admin token must contain at least 32 characters.";return;}
 adminToken=candidate;$("connect").disabled=true;$("login-status").textContent="Authenticating…";
 try{await request("/api/admin/summary");$("admin-token").value="";$("login").hidden=true;$("dashboard").hidden=false;await refresh();}
 catch(error){adminToken="";$("login-status").textContent=error.message||"Authentication failed.";}
 finally{$("connect").disabled=false;}
});
$("refresh").addEventListener("click",refresh);
$("disconnect").addEventListener("click",()=>{adminToken="";$("dashboard").hidden=true;$("login").hidden=false;$("login-status").textContent="Disconnected.";$("admin-token").value="";});
})();
</script></body></html>""";

MAX_VENDOR_REQUEST_BYTES = 64 * 1024


class LicensingHandler(BaseHTTPRequestHandler):
    """Small HTTPS-proxy-facing HTTP API for vendor product subscriptions."""

    service: VendorLicenseService | None = None
    limiter = TokenBucketRateLimiter(max_buckets=4096)
    policies = {
        "/api/checkout": (5, 60),
        "/api/claim": (15, 60),
        "/api/refresh": (30, 60),
        "/api/portal": (10, 60),
        "/api/webhook": (120, 60),
        "/api/admin/summary": (30, 60),
        "/api/admin/licenses": (30, 60),
    }

    def log_message(self, fmt, *args):
        # Do not log request bodies, query strings, credentials or Stripe tokens.
        path = urllib.parse.urlsplit(self.path).path[:128]
        print(f"[LICENSING] {self.address_string()} {self.command} {path}")

    def send_json(self, payload: dict[str, Any], status: int = 200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, content: str, status: int = 200, *, nonce: str | None = None):
        body = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        policy = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; object-src 'none'; form-action 'none'; frame-ancestors 'none'"
        if nonce:
            policy += f"; script-src 'nonce-{nonce}'; connect-src 'self'"
        self.send_header("Content-Security-Policy", policy)
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self, maximum: int = MAX_VENDOR_REQUEST_BYTES) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except (TypeError, ValueError) as error:
            raise ValueError("Content-Length is invalid") from error
        if length <= 0 or length > maximum:
            raise ValueError("Request body is empty or exceeds the size limit")
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise ValueError("Content-Type must be application/json")
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise ValueError("Request body is truncated")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("Request body must contain valid JSON") from error
        if not isinstance(value, dict):
            raise ValueError("Request JSON must be an object")
        return value

    def _limited(self, path: str) -> bool:
        policy = self.policies.get(path)
        if policy is None:
            return True
        capacity, period = policy
        peer = str(self.client_address[0]) if self.client_address else "unknown"
        decision = self.limiter.consume(
            f"vendor:{path}:{peer}",
            capacity=capacity,
            period_seconds=period,
        )
        if decision["allowed"]:
            return True
        self.send_json({
            "error": "Rate limit exceeded",
            "retry_after_seconds": decision["retry_after_seconds"],
        }, 429)
        return False

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path in {"/admin", "/admin/"}:
            nonce = secrets.token_urlsafe(18)
            self.send_html(
                ADMIN_DASHBOARD_HTML.replace("__NONCE__", nonce),
                nonce=nonce,
            )
            return
        if path == "/health":
            self.send_json({"status": "ok", "service": "wifi-analyzer-pro-licensing"})
            return
        if path == "/api/public-key":
            self.send_json(self.service.public_key())
            return
        if path in {"/api/admin/summary", "/api/admin/licenses"}:
            if not self.service.authenticate_admin(self.headers.get("Authorization")):
                self.send_json({"error": "Vendor administrator authentication is required"}, 401)
                return
            if not self._limited(path):
                return
            if path == "/api/admin/summary":
                self.send_json({"summary": self.service.admin_summary()})
                return
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            try:
                raw_limit = query.get("limit", ["100"])
                if len(raw_limit) != 1 or not raw_limit[0].isdigit():
                    raise ValueError("limit must be an integer from 1 to 200")
                self.send_json(self.service.admin_list_licenses(int(raw_limit[0])))
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
            return
        if path == "/checkout/success":
            self.send_html("""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Payment received</title><body style="font:16px system-ui;max-width:620px;margin:12vh auto;padding:24px;color:#e5e7eb;background:#0b1220"><h1>Payment received</h1><p>Stripe is confirming your subscription. Return to WiFi Analyzer Pro, open <b>Plans &amp; Licensing</b>, and select <b>Sync licence</b> to activate the signed product licence.</p><p>You can safely close this page after returning to the app.</p></body></html>""")
            return
        if path == "/checkout/cancel":
            self.send_html("""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Checkout cancelled</title><body style="font:16px system-ui;max-width:620px;margin:12vh auto;padding:24px;color:#e5e7eb;background:#0b1220"><h1>Checkout cancelled</h1><p>No product licence was activated. Return to WiFi Analyzer Pro to choose another plan or continue on Free.</p></body></html>""")
            return
        self.send_json({"error": "Not found"}, 404)

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        if path not in self.policies:
            self.send_json({"error": "Not found"}, 404)
            return
        if not self._limited(path):
            return
        try:
            if path == "/api/webhook":
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except (TypeError, ValueError) as error:
                    raise ValueError("Content-Length is invalid") from error
                if length <= 0 or length > 256 * 1024:
                    raise ValueError("Webhook body is empty or exceeds 256 KiB")
                if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
                    raise ValueError("Content-Type must be application/json")
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise ValueError("Webhook body is truncated")
                result = self.service.receive_webhook(raw, self.headers.get("Stripe-Signature"))
                self.send_json(result)
                return

            payload = self._read_json()
            if path == "/api/checkout":
                result = self.service.create_checkout(
                    installation_id=payload.get("installation_id"),
                    plan_id=payload.get("plan_id"),
                    customer_email=payload.get("customer_email"),
                )
                self.send_json(result, 201)
                return
            if path == "/api/claim":
                result = self.service.claim_license(
                    installation_id=payload.get("installation_id"),
                    checkout_session_id=payload.get("checkout_session_id"),
                    activation_secret=payload.get("activation_secret"),
                )
                self.send_json(result)
                return
            if path == "/api/refresh":
                result = self.service.refresh_license(
                    installation_id=payload.get("installation_id"),
                    license_id=payload.get("license_id"),
                    activation_secret=payload.get("activation_secret"),
                )
                self.send_json(result)
                return

            if path == "/api/portal":
                result = self.service.create_portal_session(
                    installation_id=payload.get("installation_id"),
                    license_id=payload.get("license_id"),
                    activation_secret=payload.get("activation_secret"),
                )
                self.send_json(result)
                return
        except LicenseNotReady as error:
            self.send_json({"error": str(error), "code": "license_not_ready"}, 409)
        except LicenseVerificationError as error:
            self.send_json({"error": str(error)}, 403)
        except StripeApiError as error:
            self.send_json({"error": str(error)}, 502)
        except ValueError as error:
            self.send_json({"error": str(error)}, 400)
        except LicenseServiceConflict as error:
            self.send_json({"error": str(error)}, 409)
        except Exception as error:
            print(f"[LICENSING ERROR] {type(error).__name__}")
            self.send_json({"error": "Vendor licensing service failed"}, 500)


def build_service_from_environment() -> VendorLicenseService:
    database_path = os.getenv(
        "WIFI_ANALYZER_VENDOR_LICENSE_DB",
        str(Path.home() / ".local" / "state" / "wifi-analyzer-pro" / "vendor-licensing.sqlite3"),
    )
    public_url = os.getenv("WIFI_ANALYZER_LICENSE_SERVICE_PUBLIC_URL", "")
    return VendorLicenseService(
        database_path,
        stripe_secret_key=os.getenv("WIFI_ANALYZER_VENDOR_STRIPE_SECRET_KEY", ""),
        stripe_webhook_secret=os.getenv("WIFI_ANALYZER_VENDOR_STRIPE_WEBHOOK_SECRET", ""),
        public_url=public_url,
        price_plans=configured_vendor_price_plans(),
        signing_private_key=load_vendor_signing_key(),
        key_id=os.getenv("WIFI_ANALYZER_VENDOR_LICENSE_KEY_ID", "primary"),
        admin_token=os.getenv("WIFI_ANALYZER_VENDOR_ADMIN_TOKEN", ""),
    )


def main() -> None:
    service = build_service_from_environment()
    host = os.getenv("WIFI_ANALYZER_LICENSE_SERVICE_HOST", "127.0.0.1")
    port_text = os.getenv("WIFI_ANALYZER_LICENSE_SERVICE_PORT", "1999")
    try:
        port = int(port_text)
    except ValueError as error:
        raise SystemExit("WIFI_ANALYZER_LICENSE_SERVICE_PORT must be an integer") from error
    if not 1 <= port <= 65535:
        raise SystemExit("WIFI_ANALYZER_LICENSE_SERVICE_PORT must be between 1 and 65535")
    LicensingHandler.service = service
    httpd = ThreadingHTTPServer((host, port), LicensingHandler)
    httpd.daemon_threads = True
    print(f"[LICENSING] Listening on {host}:{port}; place behind a trusted HTTPS reverse proxy")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("[LICENSING] Shutting down")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
