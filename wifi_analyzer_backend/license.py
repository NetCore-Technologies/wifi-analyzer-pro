"""Vendor-issued Ed25519 product licences for local installations.

The verifier contains only public keys. Stripe credentials and Ed25519 signing
private keys belong in the vendor licensing control plane, never on customer
installations.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

try:
    from .billing import PLAN_CATALOG
    from .site_history import default_history_path
except ImportError:  # Direct module execution in the production container.
    from billing import PLAN_CATALOG
    from site_history import default_history_path


LICENSE_SCHEMA = "wifi-analyzer-pro.vendor-license.v1"
MAX_LICENSE_TOKEN_BYTES = 16 * 1024
MAX_LICENSE_LIFETIME_SECONDS = 10 * 365 * 24 * 60 * 60
DEFAULT_OFFLINE_GRACE_SECONDS = 72 * 60 * 60
_LICENSE_ID = re.compile(r"^lic_[A-Za-z0-9_-]{12,120}$")
_INSTALLATION_ID = re.compile(r"^[a-f0-9]{32}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_CHECKOUT_ID = re.compile(r"^cs_(?:test|live)_[A-Za-z0-9]{8,128}$")
_VENDOR_LICENSE_ID = re.compile(r"^lic_[A-Za-z0-9_-]{12,120}$")
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")


class LicenseVerificationError(ValueError):
    """A vendor licence is missing, malformed, invalid or outside its grace."""

class VendorLicenseServiceError(RuntimeError):
    """The configured vendor licensing service could not complete an operation."""


class _RejectVendorRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        # Requests carry activation secrets. Never forward them to another host.
        return None


def _post_vendor_service(
    url: str,
    payload: dict[str, Any],
    *,
    opener=None,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("Vendor licensing request must be a JSON object")
    encoded = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=encoded,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "WiFi-Analyzer-Pro/1.0",
        },
        method="POST",
    )
    if opener is None:
        open_request = urllib.request.build_opener(_RejectVendorRedirects()).open
    elif hasattr(opener, "open"):
        open_request = opener.open
    else:
        open_request = opener
    try:
        response = open_request(request, timeout=15)
        with response:
            raw = response.read(64 * 1024 + 1)
    except urllib.error.HTTPError as error:
        try:
            raw = error.read(4096)
            detail = json.loads(raw.decode("utf-8")).get("error")
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, AttributeError):
            detail = None
        message = detail if isinstance(detail, str) and len(detail) <= 256 else f"Vendor service returned HTTP {error.code}"
        raise VendorLicenseServiceError(message) from None
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise VendorLicenseServiceError("Could not reach the vendor licensing service") from None
    if len(raw) > 64 * 1024:
        raise VendorLicenseServiceError("Vendor licensing response exceeded the size limit")
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise VendorLicenseServiceError("Vendor licensing service returned invalid JSON") from None
    if not isinstance(result, dict):
        raise VendorLicenseServiceError("Vendor licensing service returned an invalid response")
    return result


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
    ).encode("utf-8")


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or not value or not _B64URL.fullmatch(value):
        raise LicenseVerificationError("Product licence encoding is invalid")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as error:
        raise LicenseVerificationError("Product licence encoding is invalid") from error


def load_public_keys(environ: dict[str, str] | None = None) -> dict[str, bytes]:
    """Load one or more trusted vendor public keys from deployment environment."""
    source = os.environ if environ is None else environ
    raw_map = source.get("WIFI_ANALYZER_VENDOR_LICENSE_PUBLIC_KEYS", "").strip()
    if raw_map:
        try:
            parsed = json.loads(raw_map)
        except json.JSONDecodeError as error:
            raise ValueError("WIFI_ANALYZER_VENDOR_LICENSE_PUBLIC_KEYS must be a JSON object") from error
        if not isinstance(parsed, dict) or not parsed or len(parsed) > 8:
            raise ValueError("Vendor licence public-key map must contain 1 to 8 keys")
        result = {}
        for key_id, encoded in parsed.items():
            if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
                raise ValueError("Vendor licence key ID is invalid")
            if not isinstance(encoded, str):
                raise ValueError("Vendor licence public keys must be base64 strings")
            try:
                key_bytes = base64.b64decode(encoded, validate=True)
            except (ValueError, binascii.Error) as error:
                raise ValueError(f"Vendor licence public key {key_id} is not valid base64") from error
            if len(key_bytes) != 32:
                raise ValueError(f"Vendor licence public key {key_id} must contain 32 bytes")
            result[key_id] = key_bytes
        return result

    encoded = source.get("WIFI_ANALYZER_VENDOR_LICENSE_PUBLIC_KEY", "").strip()
    if not encoded:
        return {}
    key_id = source.get("WIFI_ANALYZER_VENDOR_LICENSE_KEY_ID", "primary").strip()
    if not _KEY_ID.fullmatch(key_id):
        raise ValueError("WIFI_ANALYZER_VENDOR_LICENSE_KEY_ID is invalid")
    try:
        key_bytes = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError("WIFI_ANALYZER_VENDOR_LICENSE_PUBLIC_KEY is not valid base64") from error
    if len(key_bytes) != 32:
        raise ValueError("WIFI_ANALYZER_VENDOR_LICENSE_PUBLIC_KEY must contain 32 bytes")
    return {key_id: key_bytes}


def create_signed_license(payload: dict[str, Any], private_key: Ed25519PrivateKey) -> str:
    """Create a compact licence token for the vendor control plane and tests."""
    if not isinstance(payload, dict):
        raise ValueError("Licence claims must be an object")
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("An Ed25519 private key is required")
    claims = dict(payload)
    claims.setdefault("schema", LICENSE_SCHEMA)
    encoded = _b64url_encode(_canonical(claims))
    signature = _b64url_encode(private_key.sign(encoded.encode("ascii")))
    return f"{encoded}.{signature}"


def verify_license_token(
    token: str,
    *,
    public_keys: dict[str, bytes],
    expected_installation_id: str,
    now: float | None = None,
    offline_grace_seconds: int = DEFAULT_OFFLINE_GRACE_SECONDS,
) -> dict[str, Any]:
    """Verify a signed licence and bind it to one installation fingerprint."""
    if not isinstance(token, str) or not token or len(token.encode("utf-8")) > MAX_LICENSE_TOKEN_BYTES:
        raise LicenseVerificationError("Product licence is empty or exceeds the size limit")
    if not isinstance(public_keys, dict) or not public_keys or len(public_keys) > 8:
        raise LicenseVerificationError("Trusted vendor licence public keys are not configured")
    if not isinstance(expected_installation_id, str) or not _INSTALLATION_ID.fullmatch(expected_installation_id):
        raise ValueError("Expected installation identifier is invalid")
    if (
        isinstance(offline_grace_seconds, bool)
        or not isinstance(offline_grace_seconds, int)
        or not 0 <= offline_grace_seconds <= 30 * 24 * 60 * 60
    ):
        raise ValueError("offline_grace_seconds must be between 0 and 30 days")

    parts = token.split(".")
    if len(parts) != 2:
        raise LicenseVerificationError("Product licence format is invalid")
    raw_payload = _b64url_decode(parts[0])
    signature = _b64url_decode(parts[1])
    if len(raw_payload) > MAX_LICENSE_TOKEN_BYTES or len(signature) != 64:
        raise LicenseVerificationError("Product licence signature or payload is invalid")
    try:
        claims = json.loads(raw_payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LicenseVerificationError("Product licence claims are invalid") from error
    if not isinstance(claims, dict):
        raise LicenseVerificationError("Product licence claims must be an object")
    if claims.get("schema") != LICENSE_SCHEMA:
        raise LicenseVerificationError("Unsupported product licence schema")
    key_id = claims.get("key_id")
    if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
        raise LicenseVerificationError("Product licence key ID is invalid")
    key_bytes = public_keys.get(key_id)
    if not isinstance(key_bytes, bytes) or len(key_bytes) != 32:
        raise LicenseVerificationError("Product licence was signed by an untrusted key")
    try:
        Ed25519PublicKey.from_public_bytes(key_bytes).verify(signature, parts[0].encode("ascii"))
    except (InvalidSignature, ValueError) as error:
        raise LicenseVerificationError("Product licence signature verification failed") from error

    license_id = claims.get("license_id")
    installation_id = claims.get("installation_id")
    plan_id = claims.get("plan_id")
    issued_at = claims.get("issued_at")
    expires_at = claims.get("expires_at")
    limits = claims.get("limits")

    if not isinstance(license_id, str) or not _LICENSE_ID.fullmatch(license_id):
        raise LicenseVerificationError("Product licence identifier is invalid")
    if not isinstance(installation_id, str) or not _INSTALLATION_ID.fullmatch(installation_id):
        raise LicenseVerificationError("Product licence installation binding is invalid")
    if not __import__("hmac").compare_digest(installation_id, expected_installation_id):
        raise LicenseVerificationError("Product licence belongs to a different installation")
    if plan_id not in PLAN_CATALOG or plan_id == "free":
        raise LicenseVerificationError("Product licence plan is invalid")
    for field, value in (("issued_at", issued_at), ("expires_at", expires_at)):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise LicenseVerificationError(f"Product licence {field} is invalid")
    if expires_at <= issued_at or expires_at - issued_at > MAX_LICENSE_LIFETIME_SECONDS:
        raise LicenseVerificationError("Product licence validity period is invalid")
    if limits != PLAN_CATALOG[plan_id]["limits"]:
        raise LicenseVerificationError("Product licence entitlements do not match the signed plan")

    moment = time.time() if now is None else now
    if isinstance(moment, bool) or not isinstance(moment, (int, float)):
        raise ValueError("now must be a Unix timestamp")
    if issued_at > moment + 300:
        raise LicenseVerificationError("Product licence was issued in the future")
    signed_offline_grace = claims.get("offline_grace_seconds", offline_grace_seconds)
    if (
        isinstance(signed_offline_grace, bool)
        or not isinstance(signed_offline_grace, int)
        or not 0 <= signed_offline_grace <= DEFAULT_OFFLINE_GRACE_SECONDS
    ):
        raise LicenseVerificationError("Product licence offline grace period is invalid")
    if moment > expires_at + signed_offline_grace:
        raise LicenseVerificationError("Product licence has expired")

    grace = moment > expires_at
    return {
        "valid": True,
        "active": True,
        "grace_period": grace,
        "license_id": license_id,
        "installation_id": installation_id,
        "plan_id": plan_id,
        "plan_label": PLAN_CATALOG[plan_id]["label"],
        "issued_at": issued_at,
        "expires_at": expires_at,
        "offline_grace_seconds": signed_offline_grace,
        "limits": dict(limits),
        "key_id": key_id,
    }


def default_license_path() -> Path:
    configured = os.getenv("WIFI_ANALYZER_VENDOR_LICENSE_FILE")
    if configured:
        return Path(configured).expanduser()
    return Path(default_history_path()).with_name("vendor-license.json")


class VendorLicenseStore:
    """Persist and verify a vendor-issued installation-bound licence token."""

    def __init__(
        self,
        path: str | os.PathLike | None = None,
        *,
        public_keys: dict[str, bytes] | None = None,
        clock=time.time,
    ):
        self.path = Path(path).expanduser() if path is not None else default_license_path()
        self.refresh_path = self.path.with_name("vendor-license-refresh.json")
        self.public_keys = load_public_keys() if public_keys is None else dict(public_keys)
        self._clock = clock
        self._service_opener = None
        self._lock = threading.RLock()

    @staticmethod
    def _service_origin(value: str) -> str:
        parsed = __import__("urllib.parse", fromlist=["urlsplit"]).urlsplit(
            value.strip() if isinstance(value, str) else ""
        )
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
            raise ValueError("Vendor licence service must use a trusted HTTPS origin")
        return f"https://{parsed.netloc}"

    def _write_refresh_credentials(self, credentials: dict[str, str]) -> None:
        parent_existed = self.refresh_path.parent.exists()
        self.refresh_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt" and not parent_existed:
            os.chmod(self.refresh_path.parent, 0o700)
        descriptor, temporary = tempfile.mkstemp(
            prefix=".vendor-license-refresh-", suffix=".tmp", dir=str(self.refresh_path.parent),
        )
        try:
            if os.name != "nt":
                os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(credentials, handle, sort_keys=True, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.refresh_path)
            if os.name != "nt":
                os.chmod(self.refresh_path, 0o600)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def start_checkout(
        self,
        *,
        service_url: str,
        installation_id: str,
        plan_id: str,
        customer_email: str | None = None,
        opener=None,
    ) -> dict[str, str]:
        if not self.configured():
            raise LicenseVerificationError("Vendor public verification key is not configured")
        if not isinstance(installation_id, str) or not _INSTALLATION_ID.fullmatch(installation_id):
            raise ValueError("Installation identifier is invalid")
        if plan_id not in {"pro", "business", "enterprise"}:
            raise ValueError("plan_id must be pro, business or enterprise")
        origin = self._service_origin(service_url)
        payload = {
            "installation_id": installation_id,
            "plan_id": plan_id,
            "customer_email": customer_email,
        }
        result = _post_vendor_service(f"{origin}/api/checkout", payload, opener=opener)
        checkout_url = result.get("checkout_url")
        parsed = urllib.parse.urlsplit(checkout_url) if isinstance(checkout_url, str) else None
        if (
            not parsed
            or parsed.scheme != "https"
            or parsed.hostname != "checkout.stripe.com"
            or parsed.username is not None
            or parsed.password is not None
            or not isinstance(result.get("checkout_session_id"), str)
            or not _CHECKOUT_ID.fullmatch(result["checkout_session_id"])
            or not isinstance(result.get("activation_secret"), str)
            or not 32 <= len(result["activation_secret"]) <= 256
            or not isinstance(result.get("license_id"), str)
            or not _VENDOR_LICENSE_ID.fullmatch(result["license_id"])
        ):
            raise VendorLicenseServiceError("Vendor service returned an invalid Checkout response")
        self.configure_service(
            service_url=origin,
            checkout_session_id=result["checkout_session_id"],
            activation_secret=result["activation_secret"],
            license_id=result["license_id"],
        )
        return {
            "checkout_url": checkout_url,
            "checkout_session_id": result["checkout_session_id"],
            "license_id": result["license_id"],
            "plan_id": plan_id,
        }

    def sync_from_vendor(
        self,
        *,
        installation_id: str,
        opener=None,
    ) -> dict[str, Any]:
        credentials = self.refresh_credentials()
        if credentials is None:
            raise LicenseVerificationError("No vendor checkout or renewal credentials are stored")
        if not isinstance(installation_id, str) or not _INSTALLATION_ID.fullmatch(installation_id):
            raise ValueError("Installation identifier is invalid")
        existing = self.status(installation_id)
        if existing.get("installed"):
            endpoint = "/api/refresh"
            payload = {
                "installation_id": installation_id,
                "license_id": credentials["license_id"],
                "activation_secret": credentials["activation_secret"],
            }
        else:
            endpoint = "/api/claim"
            payload = {
                "installation_id": installation_id,
                "checkout_session_id": credentials["checkout_session_id"],
                "activation_secret": credentials["activation_secret"],
            }
        result = _post_vendor_service(
            f"{credentials['service_url']}{endpoint}",
            payload,
            opener=opener,
        )
        token = result.get("license_token")
        if not isinstance(token, str):
            raise VendorLicenseServiceError("Vendor service did not return a signed licence")
        activated = self.activate(token, installation_id)
        if result.get("license_id") != activated["license_id"]:
            raise VendorLicenseServiceError("Vendor licence identity does not match its signed token")
        return {
            **activated,
            "subscription_status": result.get("subscription_status"),
            "product_license": self.status(installation_id),
        }

    def configure_service(
        self,
        *,
        service_url: str,
        checkout_session_id: str,
        activation_secret: str,
        license_id: str,
    ) -> None:
        if not isinstance(checkout_session_id, str) or not _CHECKOUT_ID.fullmatch(checkout_session_id):
            raise ValueError("Vendor checkout session identifier is invalid")
        if not isinstance(activation_secret, str) or not 32 <= len(activation_secret) <= 256:
            raise ValueError("Vendor activation credential is invalid")
        if not isinstance(license_id, str) or not _VENDOR_LICENSE_ID.fullmatch(license_id):
            raise ValueError("Vendor licence identifier is invalid")
        credentials = {
            "version": 1,
            "service_url": self._service_origin(service_url),
            "checkout_session_id": checkout_session_id,
            "activation_secret": activation_secret,
            "license_id": license_id,
        }
        with self._lock:
            self._write_refresh_credentials(credentials)

    def refresh_credentials(self) -> dict[str, str] | None:
        with self._lock:
            if not self.refresh_path.exists():
                return None
            try:
                if self.refresh_path.stat().st_size > 4096:
                    raise ValueError("Stored vendor refresh credentials exceed the size limit")
                credentials = json.loads(self.refresh_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
                raise LicenseVerificationError("Stored vendor refresh credentials cannot be read") from error
            if not isinstance(credentials, dict) or credentials.get("version") != 1:
                raise LicenseVerificationError("Stored vendor refresh credentials are invalid")
            try:
                service_url = self._service_origin(credentials.get("service_url"))
            except (TypeError, ValueError) as error:
                raise LicenseVerificationError("Stored vendor service URL is invalid") from error
            checkout_id = credentials.get("checkout_session_id")
            activation_secret = credentials.get("activation_secret")
            license_id = credentials.get("license_id")
            if (
                not isinstance(checkout_id, str) or not _CHECKOUT_ID.fullmatch(checkout_id)
                or not isinstance(activation_secret, str) or not 32 <= len(activation_secret) <= 256
                or not isinstance(license_id, str) or not _VENDOR_LICENSE_ID.fullmatch(license_id)
            ):
                raise LicenseVerificationError("Stored vendor refresh credentials are invalid")
            return {
                "service_url": service_url,
                "checkout_session_id": checkout_id,
                "activation_secret": activation_secret,
                "license_id": license_id,
            }

    def update_vendor_license_id(self, license_id: str) -> None:
        credentials = self.refresh_credentials()
        if credentials is None:
            raise LicenseVerificationError("Vendor refresh credentials are not configured")
        if not isinstance(license_id, str) or not _VENDOR_LICENSE_ID.fullmatch(license_id):
            raise ValueError("Vendor licence identifier is invalid")
        credentials["license_id"] = license_id
        with self._lock:
            self._write_refresh_credentials({"version": 1, **credentials})

    def renewal_configured(self) -> bool:
        try:
            return self.refresh_credentials() is not None
        except LicenseVerificationError:
            return False

    def configured(self) -> bool:
        return bool(self.public_keys)

    def _read_token(self) -> str | None:
        if not self.path.exists():
            return None
        try:
            if self.path.stat().st_size > MAX_LICENSE_TOKEN_BYTES:
                raise LicenseVerificationError("Stored product licence exceeds the size limit")
            token = self.path.read_text(encoding="ascii").strip()
        except (OSError, UnicodeDecodeError) as error:
            raise LicenseVerificationError("Stored product licence cannot be read") from error
        return token or None

    def status(self, expected_installation_id: str) -> dict[str, Any]:
        with self._lock:
            try:
                token = self._read_token()
            except LicenseVerificationError as error:
                return {
                    "configured": self.configured(), "installed": True, "active": False,
                    "grace_period": False, "plan_id": "free",
                    "renewal_configured": self.renewal_configured(), "error": str(error),
                }
            if token is None:
                return {
                    "configured": self.configured(), "installed": False, "active": False,
                    "grace_period": False, "plan_id": None,
                    "renewal_configured": self.renewal_configured(),
                }
            if not self.configured():
                return {
                    "configured": False, "installed": True, "active": False,
                    "grace_period": False, "plan_id": "free",
                    "renewal_configured": self.renewal_configured(),
                    "error": "Vendor licence verification is not configured on this installation",
                }
            try:
                verified = verify_license_token(
                    token,
                    public_keys=self.public_keys,
                    expected_installation_id=expected_installation_id,
                    now=self._clock(),
                )
            except (LicenseVerificationError, ValueError) as error:
                return {
                    "configured": True, "installed": True, "active": False,
                    "grace_period": False, "plan_id": "free",
                    "renewal_configured": self.renewal_configured(), "error": str(error),
                }
            return {
                "configured": True, "installed": True,
                "renewal_configured": self.renewal_configured(),
                **verified,
            }

    def activate(self, token: str, expected_installation_id: str) -> dict[str, Any]:
        with self._lock:
            if not self.configured():
                raise LicenseVerificationError("Vendor licence verification is not configured")
            verified = verify_license_token(
                token,
                public_keys=self.public_keys,
                expected_installation_id=expected_installation_id,
                now=self._clock(),
            )
            parent_existed = self.path.parent.exists()
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if os.name != "nt" and not parent_existed:
                os.chmod(self.path.parent, 0o700)
            descriptor, temporary = tempfile.mkstemp(
                prefix=".vendor-license-", suffix=".tmp", dir=str(self.path.parent),
            )
            try:
                if os.name != "nt":
                    os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "w", encoding="ascii") as handle:
                    handle.write(token)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, self.path)
                if os.name != "nt":
                    os.chmod(self.path, 0o600)
            finally:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass
            return {
                "license_id": verified["license_id"],
                "plan_id": verified["plan_id"],
                "plan_label": verified["plan_label"],
                "expires_at": verified["expires_at"],
                "active": verified["active"],
            }

    def deactivate(self) -> bool:
        with self._lock:
            removed = False
            for target in (self.path, self.refresh_path):
                try:
                    target.unlink()
                    removed = True
                except FileNotFoundError:
                    pass
            return removed
