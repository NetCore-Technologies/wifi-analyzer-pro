"""Create and restore authenticated-encrypted router report backup archives."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import re
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

FORMAT = "wifi-analyzer-pro/encrypted-report-archive"
SCHEMA_VERSION = "1.0"
ALGORITHM = "AES-256-GCM"
KDF = "scrypt"
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LENGTH = 32
SALT_LENGTH = 16
NONCE_LENGTH = 12
MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
MAX_PASSPHRASE_BYTES = 1024
MIN_PASSPHRASE_BYTES = 12
ARCHIVE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,63}$")
AAD = f"{FORMAT}|{SCHEMA_VERSION}|{ALGORITHM}|{KDF}|{SCRYPT_N}|{SCRYPT_R}|{SCRYPT_P}".encode("ascii")


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone offset")
    return parsed.astimezone(timezone.utc)


def _passphrase(value: object) -> bytes:
    if not isinstance(value, str):
        raise ValueError("passphrase must be a string")
    encoded = value.encode("utf-8")
    if not MIN_PASSPHRASE_BYTES <= len(encoded) <= MAX_PASSPHRASE_BYTES:
        raise ValueError(
            f"passphrase must contain from {MIN_PASSPHRASE_BYTES} to {MAX_PASSPHRASE_BYTES} UTF-8 bytes"
        )
    return encoded


def _canonical(value: object, field: str) -> bytes:
    try:
        rendered = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field} must contain JSON-compatible finite values") from error
    encoded = rendered.encode("utf-8")
    if len(encoded) > MAX_INPUT_BYTES:
        raise ValueError(f"{field} exceeds the {MAX_INPUT_BYTES}-byte plaintext limit")
    return encoded


def _derive_key(passphrase: bytes, salt: bytes) -> bytes:
    return Scrypt(
        salt=salt,
        length=KEY_LENGTH,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    ).derive(passphrase)


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode_b64(value: object, field: str, maximum: int) -> bytes:
    if not isinstance(value, str) or len(value) > maximum:
        raise ValueError(f"{field} must be a bounded base64 string")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise ValueError(f"{field} is not valid base64") from error
    if _b64(decoded) != value:
        raise ValueError(f"{field} is not canonical base64")
    return decoded


def _archive_id(value: object) -> str:
    if not isinstance(value, str) or not ARCHIVE_ID.fullmatch(value):
        raise ValueError("archive_id must be an 8 to 64 character identifier")
    return value


def _encrypt(payload: dict) -> dict:
    now = _timestamp(payload.get("created_at"), "created_at")
    archive_id = _archive_id(payload.get("archive_id"))
    passphrase = _passphrase(payload.get("passphrase"))
    data = payload.get("data")
    if not isinstance(data, dict):
        raise ValueError("data must be a JSON object")
    data_bytes = _canonical(data, "data")
    data_hash = hashlib.sha256(data_bytes).hexdigest()
    plaintext = _canonical({
        "schema_version": SCHEMA_VERSION,
        "archive_id": archive_id,
        "created_at": now.isoformat(),
        "data_sha256": data_hash,
        "data": data,
    }, "archive plaintext")
    salt = os.urandom(SALT_LENGTH)
    nonce = os.urandom(NONCE_LENGTH)
    key = _derive_key(passphrase, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, AAD)
    archive = {
        "format": FORMAT,
        "schema_version": SCHEMA_VERSION,
        "algorithm": ALGORITHM,
        "kdf": KDF,
        "kdf_parameters": {
            "n": SCRYPT_N,
            "r": SCRYPT_R,
            "p": SCRYPT_P,
            "key_length": KEY_LENGTH,
        },
        "archive_id": archive_id,
        "created_at": now.isoformat(),
        "salt": _b64(salt),
        "nonce": _b64(nonce),
        "ciphertext": _b64(ciphertext),
    }
    archive_json = json.dumps(archive, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if len(archive_json.encode("utf-8")) > MAX_ARCHIVE_BYTES:
        raise ValueError("encrypted archive exceeds the supported archive size")
    return {
        "status": "encrypted",
        "archive": archive,
        "archive_json": archive_json,
        "summary": {
            "archive_id": archive_id,
            "created_at": now.isoformat(),
            "algorithm": ALGORITHM,
            "kdf": KDF,
            "plaintext_bytes": len(plaintext),
            "ciphertext_bytes": len(ciphertext),
            "content_sha256": data_hash,
        },
        "note": (
            "The passphrase is not returned or stored. Keep it separately from this archive; losing it makes "
            "the encrypted data unrecoverable. Use a unique high-entropy passphrase and store the archive in "
            "a separate protected location."
        ),
    }


def _restore(payload: dict) -> dict:
    passphrase = _passphrase(payload.get("passphrase"))
    raw_archive = payload.get("archive")
    if isinstance(raw_archive, str):
        if len(raw_archive.encode("utf-8")) > MAX_ARCHIVE_BYTES:
            raise ValueError("archive exceeds the supported archive size")
        try:
            raw_archive = json.loads(raw_archive)
        except (TypeError, ValueError) as error:
            raise ValueError("archive_json must contain a valid JSON archive object") from error
    if not isinstance(raw_archive, dict):
        raise ValueError("archive must be an encrypted archive object or archive JSON string")
    try:
        archive_bytes = json.dumps(
            raw_archive, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError("archive contains invalid JSON values") from error
    if len(archive_bytes) > MAX_ARCHIVE_BYTES:
        raise ValueError("archive exceeds the supported archive size")
    required = {
        "format", "schema_version", "algorithm", "kdf", "kdf_parameters",
        "archive_id", "created_at", "salt", "nonce", "ciphertext",
    }
    if set(raw_archive) != required:
        raise ValueError("archive contains missing or unsupported fields")
    if raw_archive.get("format") != FORMAT or raw_archive.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("archive format or schema version is unsupported")
    if raw_archive.get("algorithm") != ALGORITHM or raw_archive.get("kdf") != KDF:
        raise ValueError("archive cryptographic algorithm or KDF is unsupported")
    parameters = raw_archive.get("kdf_parameters")
    expected_parameters = {
        "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "key_length": KEY_LENGTH,
    }
    if parameters != expected_parameters:
        raise ValueError("archive KDF parameters are unsupported")
    archive_id = _archive_id(raw_archive.get("archive_id"))
    created_at = _timestamp(raw_archive.get("created_at"), "archive.created_at")
    salt = _decode_b64(raw_archive.get("salt"), "archive.salt", 64)
    nonce = _decode_b64(raw_archive.get("nonce"), "archive.nonce", 64)
    ciphertext = _decode_b64(raw_archive.get("ciphertext"), "archive.ciphertext", MAX_ARCHIVE_BYTES)
    if len(salt) != SALT_LENGTH or len(nonce) != NONCE_LENGTH:
        raise ValueError("archive salt or nonce length is invalid")
    if len(ciphertext) < 16 or len(ciphertext) > MAX_INPUT_BYTES + 4096:
        raise ValueError("archive ciphertext length is outside the supported range")

    key = _derive_key(passphrase, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, AAD)
    except InvalidTag as error:
        raise ValueError("archive authentication failed: wrong passphrase or modified archive") from error
    if len(plaintext) > MAX_INPUT_BYTES:
        raise ValueError("decrypted archive payload exceeds the plaintext limit")
    try:
        document = json.loads(plaintext)
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError("authenticated archive plaintext is not valid JSON") from error
    if not isinstance(document, dict) or set(document) != {
        "schema_version", "archive_id", "created_at", "data_sha256", "data",
    }:
        raise ValueError("authenticated archive plaintext schema is invalid")
    if document.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("authenticated archive plaintext version is unsupported")
    if document.get("archive_id") != archive_id:
        raise ValueError("archive identity does not match its authenticated header")
    document_time = _timestamp(document.get("created_at"), "archive plaintext.created_at")
    if document_time != created_at:
        raise ValueError("archive creation time does not match its authenticated header")
    data = document.get("data")
    if not isinstance(data, dict):
        raise ValueError("restored archive data must be an object")
    data_bytes = _canonical(data, "restored data")
    actual_hash = hashlib.sha256(data_bytes).hexdigest()
    if not isinstance(document.get("data_sha256"), str) or not hmac.compare_digest(actual_hash, document["data_sha256"]):
        raise ValueError("restored archive content digest is invalid")
    return {
        "status": "restored",
        "archive_id": archive_id,
        "created_at": created_at.isoformat(),
        "data": data,
        "summary": {
            "archive_id": archive_id,
            "created_at": created_at.isoformat(),
            "algorithm": ALGORITHM,
            "kdf": KDF,
            "restored_bytes": len(data_bytes),
            "content_sha256": actual_hash,
        },
        "note": (
            "The archive passed AES-GCM authentication and the inner content digest check. Review restored "
            "data and its source before importing it into live application state."
        ),
    }


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    try:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError("archive input must contain JSON-compatible finite values") from error
    if len(encoded) > MAX_ARCHIVE_BYTES:
        raise ValueError(f"archive input exceeds the {MAX_ARCHIVE_BYTES}-byte input limit")
    mode = payload.get("mode")
    if mode == "encrypt":
        return _encrypt(payload)
    if mode == "restore":
        return _restore(payload)
    raise ValueError("mode must be encrypt or restore")


FEATURE = {
    "id": "F186",
    "slug": "router_encrypted_report_archive",
    "name": "Authenticated-encrypted router report archive",
    "category": "Router operations",
    "description": (
        "Encrypt and restore caller-supplied router report/alert backup data using Scrypt-derived AES-256-GCM "
        "keys, authenticated archive metadata and bounded strict-format validation."
    ),
    "parameters": {
        "mode": "encrypt or restore",
        "archive_id": "stable 8 to 64 character archive identifier when encrypting",
        "created_at": "timezone-aware timestamp when encrypting",
        "passphrase": "12 to 1024 UTF-8 bytes, held separately by the caller",
        "data": "JSON object to encrypt",
        "archive": "encrypted archive object or canonical archive JSON string to restore",
    },
    "run": run,
}
