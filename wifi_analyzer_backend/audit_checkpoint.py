"""Ed25519-signed checkpoints for independently verifying the local audit head."""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SCHEMA = "wifi-analyzer-pro.security-audit-checkpoint.v1"
ALGORITHM = "Ed25519"
_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
_EVENT_HASH = re.compile(r"^[0-9a-f]{64}$")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _private_key_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _load_or_create_key(path: Path) -> Ed25519PrivateKey:
    """Load the persistent signer, creating it once without replacing bad keys."""
    path = path.expanduser()
    parent_existed = path.parent.exists()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt" and not parent_existed:
        try:
            os.chmod(path.parent, 0o700)
        except OSError as error:
            raise RuntimeError("could not secure audit signing-key directory") from error

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(str(path), flags, 0o600)
    except FileExistsError:
        raw = b""
        for attempt in range(20):
            read_flags = os.O_RDONLY | (getattr(os, "O_NOFOLLOW", 0))
            try:
                read_fd = os.open(str(path), read_flags)
            except OSError as error:
                raise RuntimeError("could not read the existing audit signing key") from error
            with os.fdopen(read_fd, "rb") as handle:
                raw = handle.read(33)
            if len(raw) == 32:
                break
            if attempt < 19 and not raw:
                time.sleep(0.01)
        if len(raw) != 32:
            raise RuntimeError("existing audit signing key is invalid; restore it from a trusted backup")
        if os.name != "nt":
            try:
                os.chmod(path, 0o600)
            except OSError as error:
                raise RuntimeError("could not secure the audit signing key permissions") from error
        try:
            return Ed25519PrivateKey.from_private_bytes(raw)
        except ValueError as error:
            raise RuntimeError("existing audit signing key is invalid") from error

    key = Ed25519PrivateKey.generate()
    raw = _private_key_bytes(key)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            os.chmod(path, 0o600)
    except OSError as error:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise RuntimeError("could not persist the audit signing key") from error
    return key


def create_signed_checkpoint(audit_store: Any, *, key_path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """Sign the verified ledger head; never issue a checkpoint for a broken chain."""
    verification = audit_store.verify_chain()
    if not verification.get("valid"):
        raise ValueError("audit chain verification failed; no checkpoint was signed")
    event_count = verification.get("event_count")
    latest_hash = verification.get("latest_hash")
    if isinstance(event_count, bool) or not isinstance(event_count, int) or event_count < 0:
        raise RuntimeError("audit store returned an invalid event count")
    if not isinstance(latest_hash, str) or not _EVENT_HASH.fullmatch(latest_hash):
        raise RuntimeError("audit store returned an invalid ledger head")

    path = Path(key_path).expanduser() if key_path is not None else Path(audit_store.path).with_name(
        "security-audit-signing-key.ed25519"
    )
    private_key = _load_or_create_key(path)
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fingerprint = hashlib.sha256(public_bytes).hexdigest()
    checkpoint = {
        "schema_version": 1,
        "checkpoint_id": uuid.uuid4().hex,
        "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "event_count": event_count,
        "latest_event_hash": latest_hash,
        "chain_verified": True,
        "chain_hash_algorithm": "SHA-256",
    }
    signed_payload = {
        "schema": SCHEMA,
        "checkpoint": checkpoint,
        "public_key_fingerprint": fingerprint,
    }
    signature = private_key.sign(_canonical(signed_payload))
    return {
        "schema": SCHEMA,
        "algorithm": ALGORITHM,
        "checkpoint": checkpoint,
        "public_key": base64.b64encode(public_bytes).decode("ascii"),
        "public_key_fingerprint": fingerprint,
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def verify_signed_checkpoint(
    bundle: Any,
    *,
    expected_public_key_fingerprint: str | None = None,
) -> dict[str, Any]:
    """Verify a checkpoint bundle, optionally requiring a separately pinned key."""
    try:
        if not isinstance(bundle, dict) or bundle.get("schema") != SCHEMA or bundle.get("algorithm") != ALGORITHM:
            raise ValueError("unsupported checkpoint schema or signature algorithm")
        checkpoint = bundle["checkpoint"]
        if not isinstance(checkpoint, dict):
            raise ValueError("checkpoint metadata must be an object")
        if checkpoint.get("schema_version") != 1 or checkpoint.get("chain_verified") is not True:
            raise ValueError("checkpoint metadata is invalid")
        count = checkpoint.get("event_count")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("checkpoint event count is invalid")
        if not isinstance(checkpoint.get("checkpoint_id"), str) or not re.fullmatch(r"[a-f0-9]{32}", checkpoint["checkpoint_id"]):
            raise ValueError("checkpoint identifier is invalid")
        if not isinstance(checkpoint.get("latest_event_hash"), str) or not _EVENT_HASH.fullmatch(checkpoint["latest_event_hash"]):
            raise ValueError("checkpoint ledger hash is invalid")
        issued_at = checkpoint.get("issued_at")
        if not isinstance(issued_at, str):
            raise ValueError("checkpoint issue time is invalid")
        parsed_time = datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
        if parsed_time.tzinfo is None or parsed_time.utcoffset() is None:
            raise ValueError("checkpoint issue time must include a timezone")

        fingerprint = bundle["public_key_fingerprint"]
        if not isinstance(fingerprint, str) or not _FINGERPRINT.fullmatch(fingerprint):
            raise ValueError("public-key fingerprint is invalid")
        if expected_public_key_fingerprint is not None:
            if not isinstance(expected_public_key_fingerprint, str) or not _FINGERPRINT.fullmatch(expected_public_key_fingerprint):
                raise ValueError("pinned public-key fingerprint is invalid")
            if not hmac.compare_digest(fingerprint, expected_public_key_fingerprint):
                raise ValueError("checkpoint signing key does not match the pinned fingerprint")

        public_bytes = base64.b64decode(bundle["public_key"], validate=True)
        signature = base64.b64decode(bundle["signature"], validate=True)
        if len(public_bytes) != 32 or len(signature) != 64:
            raise ValueError("checkpoint key or signature has an invalid length")
        actual_fingerprint = hashlib.sha256(public_bytes).hexdigest()
        if not hmac.compare_digest(fingerprint, actual_fingerprint):
            raise ValueError("public-key fingerprint does not match the embedded key")

        signed_payload = {
            "schema": SCHEMA,
            "checkpoint": checkpoint,
            "public_key_fingerprint": fingerprint,
        }
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature, _canonical(signed_payload))
        return {
            "valid": True,
            "public_key_fingerprint": fingerprint,
            "event_count": count,
            "latest_event_hash": checkpoint["latest_event_hash"],
            "issued_at": issued_at,
        }
    except (InvalidSignature, KeyError, TypeError, ValueError, binascii.Error):
        return {"valid": False, "error": "invalid signature, malformed checkpoint, or untrusted signing key"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a WiFi Analyzer Pro Ed25519 audit checkpoint.")
    parser.add_argument("checkpoint", type=Path, help="Path to the exported checkpoint JSON file")
    parser.add_argument(
        "--expected-public-key-fingerprint",
        help="SHA-256 fingerprint pinned through a trusted out-of-band channel",
    )
    args = parser.parse_args(argv)
    try:
        bundle = json.loads(args.checkpoint.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        print(f"Could not read checkpoint: {error}", file=sys.stderr)
        return 2
    result = verify_signed_checkpoint(
        bundle,
        expected_public_key_fingerprint=args.expected_public_key_fingerprint,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
