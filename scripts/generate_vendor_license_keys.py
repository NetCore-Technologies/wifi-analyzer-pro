#!/usr/bin/env python3
"""Generate a vendor Ed25519 licence signing key without printing the secret."""
from __future__ import annotations

import argparse
import base64
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--private-key-file",
        required=True,
        help="Protected destination for the base64 Ed25519 private key file",
    )
    parser.add_argument(
        "--key-id",
        default="primary",
        help="Short public key identifier embedded in signed licences (default: primary)",
    )
    args = parser.parse_args()
    if not args.key_id or len(args.key_id) > 64 or not all(
        char.isalnum() or char in "._-" for char in args.key_id
    ):
        parser.error("--key-id must contain only letters, digits, dot, underscore or hyphen")

    destination = Path(args.private_key_file).expanduser()
    parent = destination.parent
    existed = parent.exists()
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt" and not existed:
        os.chmod(parent, 0o700)

    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    encoded_private = base64.b64encode(private_bytes) + b"\n"
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    encoded_public = base64.b64encode(public_bytes).decode("ascii")

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(destination, flags, 0o600)
    except FileExistsError:
        print("Refusing to overwrite an existing vendor signing key.", file=sys.stderr)
        return 2
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded_private)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            destination.unlink()
        except OSError:
            pass
        raise
    if os.name != "nt":
        os.chmod(destination, 0o600)

    print("Vendor Ed25519 signing key created.")
    print(f"Private key file: {destination}")
    print("Keep this file outside Git and mount it only into the vendor licensing service.")
    print()
    print("Configure these non-secret values on customer installations:")
    print(f"WIFI_ANALYZER_VENDOR_LICENSE_PUBLIC_KEY={encoded_public}")
    print(f"WIFI_ANALYZER_VENDOR_LICENSE_KEY_ID={args.key_id}")
    print()
    print("The private key itself is intentionally never printed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
