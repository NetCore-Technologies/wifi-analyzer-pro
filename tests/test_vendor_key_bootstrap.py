"""Tests for the vendor Ed25519 signing-key bootstrap utility."""
import base64
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "generate_vendor_license_key.py"


class VendorKeyBootstrapTests(unittest.TestCase):
    def test_generates_private_file_and_public_configuration_without_printing_private_key(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "vendor" / "signing.key"
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--output", str(target),
                    "--key-id", "production-2026",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(target.is_file())
            raw = base64.b64decode(target.read_text(encoding="ascii").strip(), validate=True)
            self.assertEqual(len(raw), 32)

            private_key = Ed25519PrivateKey.from_private_bytes(raw)
            public = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            expected = base64.b64encode(public).decode("ascii")
            self.assertIn(expected, result.stdout)
            self.assertIn("Key ID: production-2026", result.stdout)
            self.assertNotIn(base64.b64encode(raw).decode("ascii"), result.stdout)
            self.assertNotIn("activation_secret", result.stdout)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(target.parent.stat().st_mode), 0o700)

    def test_refuses_to_overwrite_existing_private_key(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "signing.key"
            target.write_bytes(b"do-not-overwrite")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--output", str(target)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertEqual(target.read_bytes(), b"do-not-overwrite")


if __name__ == "__main__":
    unittest.main()
