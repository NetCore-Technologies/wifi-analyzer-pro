#!/usr/bin/env python3
"""Generate an Ed25519 keypair for the NetCore vendor licence control plane."""
from __future__ import annotations
import argparse, base64, os, tempfile
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("vendor-secrets/vendor-license-signing-key.b64"))
    parser.add_argument("--key-id", default="primary")
    parser.add_argument("--uid", type=int, default=None)
    parser.add_argument("--gid", type=int, default=None)
    args = parser.parse_args()
    if not args.key_id or len(args.key_id) > 64 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for c in args.key_id):
        parser.error("--key-id must be 1-64 safe characters")
    if (args.uid is not None and args.uid < 0) or (args.gid is not None and args.gid < 0):
        parser.error("UID and GID must be non-negative")
    output = args.output.expanduser().absolute()
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt" and (args.uid is not None or args.gid is not None):
        os.chown(output.parent, -1 if args.uid is None else args.uid, -1 if args.gid is None else args.gid)
        os.chmod(output.parent, 0o700)
    if output.exists() or output.is_symlink():
        parser.error(f"refusing to overwrite existing key file: {output}")
    private_key = Ed25519PrivateKey.generate()
    raw_private = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    raw_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fd, temporary = tempfile.mkstemp(prefix=".license-key-", dir=str(output.parent))
    try:
        if os.name != "nt":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(base64.b64encode(raw_private).decode("ascii") + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        if args.uid is not None or args.gid is not None:
            if os.name == "nt":
                raise OSError("UID/GID ownership is not supported on Windows")
            os.chown(temporary, -1 if args.uid is None else args.uid, -1 if args.gid is None else args.gid)
        os.replace(temporary, output)
        if os.name != "nt":
            os.chmod(output, 0o600)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    print("Vendor Ed25519 keypair created.")
    print(f"Private key file: {output}")
    print(f"Key ID: {args.key_id}")
    print("Public verification key (safe to configure on customer installations):")
    print(base64.b64encode(raw_public).decode("ascii"))
    print("Back up the private key offline. Never commit it or distribute it to customers.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
