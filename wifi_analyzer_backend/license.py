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
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .billing import PLAN_CATALOG
from .site_history import default_history_path


LICENSE_SCHEMA = "wifi-analyzer-pro.vendor-license.v1"
MAX_LICENSE_TOKEN_BYTES = 16 * 1024
MAX_LICENSE_LIFETIME_SECONDS = 10 * 365 * 24 * 60 * 60
DEFAULT_OFFLINE_GRACE_SECONDS = 72 * 60 * 60
_LICENSE_ID = re.compile(r"^lic_[A-Za-z0-9_-]{12,120}$")
_INSTALLATION_ID = re.compile(r"^[a-f0-9]{32}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")


class LicenseVerificationError(ValueError):
    """A vendor licence is missing, malformed, invalid or outside its grace."""


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
    if moment > expires_at + offline_grace_seconds:
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
        self.public_keys = load_public_keys() if public_keys is None else dict(public_keys)
        self._clock = clock
        self._lock = threading.RLock()

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
                    "grace_period": False, "plan_id": "free", "error": str(error),
                }
            if token is None:
                return {
                    "configured": self.configured(), "installed": False, "active": False,
                    "grace_period": False, "plan_id": None,
                }
            if not self.configured():
                return {
                    "configured": False, "installed": True, "active": False,
                    "grace_period": False, "plan_id": "free",
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
                    "grace_period": False, "plan_id": "free", "error": str(error),
                }
            return {
                "configured": True, "installed": True,
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
            try:
                self.path.unlink()
                return True
            except FileNotFoundError:
                return False
