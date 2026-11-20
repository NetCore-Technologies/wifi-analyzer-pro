"""Tests for authenticated encryption and restore of router report archives."""
from __future__ import annotations

import copy
import json
import unittest

from wifi_analyzer_backend.feature_plugins.feature_186_router_encrypted_report_archive import run


PASSPHRASE = "correct horse battery staple for router archives"
CREATED = "2026-11-20T10:00:00Z"
DATA = {
    "schema_version": "1.0",
    "reports": [{
        "report_id": "weekly-home",
        "content_hash": "a" * 64,
        "findings": [{"code": "resource.cpu_high", "severity": "warning", "observed": 91}],
    }],
    "alerts": [{
        "alert_key": "b" * 64,
        "status": "acknowledged",
        "site_id": "home",
    }],
}


class RouterEncryptedReportArchiveTests(unittest.TestCase):
    def encrypt(self, data=None):
        return run({
            "mode": "encrypt",
            "archive_id": "backup-weekly-001",
            "created_at": CREATED,
            "passphrase": PASSPHRASE,
            "data": copy.deepcopy(DATA if data is None else data),
        })

    def test_encrypt_restore_round_trip_preserves_report_and_alert_data(self):
        encrypted = self.encrypt()
        self.assertEqual(encrypted["status"], "encrypted")
        self.assertEqual(encrypted["archive"]["algorithm"], "AES-256-GCM")
        self.assertEqual(encrypted["archive"]["kdf"], "scrypt")
        self.assertEqual(encrypted["archive"]["kdf_parameters"], {
            "n": 32768, "r": 8, "p": 1, "key_length": 32,
        })
        restored = run({
            "mode": "restore",
            "passphrase": PASSPHRASE,
            "archive": encrypted["archive"],
        })
        self.assertEqual(restored["status"], "restored")
        self.assertEqual(restored["data"], DATA)
        self.assertEqual(restored["summary"]["content_sha256"], encrypted["summary"]["content_sha256"])
        self.assertEqual(restored["archive_id"], "backup-weekly-001")

    def test_restore_accepts_canonical_archive_json_string(self):
        encrypted = self.encrypt()
        restored = run({
            "mode": "restore",
            "passphrase": PASSPHRASE,
            "archive": encrypted["archive_json"],
        })
        self.assertEqual(restored["data"], DATA)

    def test_wrong_passphrase_and_ciphertext_tampering_fail_authentication(self):
        encrypted = self.encrypt()
        with self.assertRaisesRegex(ValueError, "wrong passphrase or modified archive"):
            run({
                "mode": "restore",
                "passphrase": "a completely different but long passphrase",
                "archive": encrypted["archive"],
            })
        tampered = copy.deepcopy(encrypted["archive"])
        tampered["ciphertext"] = (
            ("A" if tampered["ciphertext"][0] != "A" else "B") + tampered["ciphertext"][1:]
        )
        with self.assertRaisesRegex(ValueError, "wrong passphrase or modified archive"):
            run({"mode": "restore", "passphrase": PASSPHRASE, "archive": tampered})

    def test_authenticated_metadata_tampering_is_rejected(self):
        encrypted = self.encrypt()
        tampered = copy.deepcopy(encrypted["archive"])
        tampered["created_at"] = "2026-11-20T11:00:00+00:00"
        with self.assertRaisesRegex(ValueError, "wrong passphrase or modified archive"):
            run({"mode": "restore", "passphrase": PASSPHRASE, "archive": tampered})

    def test_rejects_unsupported_kdf_parameters_and_unknown_archive_fields_before_decryption(self):
        encrypted = self.encrypt()
        bad_kdf = copy.deepcopy(encrypted["archive"])
        bad_kdf["kdf_parameters"]["n"] = 2**20
        with self.assertRaisesRegex(ValueError, "KDF parameters are unsupported"):
            run({"mode": "restore", "passphrase": PASSPHRASE, "archive": bad_kdf})
        unknown = copy.deepcopy(encrypted["archive"])
        unknown["untrusted_extension"] = "not-supported"
        with self.assertRaisesRegex(ValueError, "missing or unsupported fields"):
            run({"mode": "restore", "passphrase": PASSPHRASE, "archive": unknown})

    def test_rejects_invalid_mode_passphrase_archive_identity_and_timestamp(self):
        with self.assertRaisesRegex(ValueError, "mode must be"):
            run({"mode": "delete"})
        with self.assertRaisesRegex(ValueError, "12 to 1024"):
            run({
                "mode": "encrypt", "archive_id": "backup-weekly-001",
                "created_at": CREATED, "passphrase": "short",
                "data": DATA,
            })
        with self.assertRaisesRegex(ValueError, "8 to 64"):
            run({
                "mode": "encrypt", "archive_id": "bad",
                "created_at": CREATED, "passphrase": PASSPHRASE, "data": DATA,
            })
        with self.assertRaisesRegex(ValueError, "timezone offset"):
            run({
                "mode": "encrypt", "archive_id": "backup-weekly-001",
                "created_at": "2026-11-20T10:00:00",
                "passphrase": PASSPHRASE, "data": DATA,
            })

    def test_rejects_invalid_archive_encoding_lengths_and_non_object_data(self):
        with self.assertRaisesRegex(ValueError, "data must be a JSON object"):
            run({
                "mode": "encrypt", "archive_id": "backup-weekly-001",
                "created_at": CREATED, "passphrase": PASSPHRASE, "data": [],
            })
        encrypted = self.encrypt()
        for field, value, message in (
            ("salt", "!", "valid base64"),
            ("nonce", "AA==", "nonce length"),
            ("ciphertext", "", "ciphertext length"),
        ):
            bad = copy.deepcopy(encrypted["archive"])
            bad[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, message):
                run({"mode": "restore", "passphrase": PASSPHRASE, "archive": bad})

    def test_rejects_non_finite_or_oversized_payloads(self):
        with self.assertRaisesRegex(ValueError, "finite values"):
            self.encrypt({"value": float("nan")})
        with self.assertRaisesRegex(ValueError, "plaintext limit"):
            self.encrypt({"large": "x" * (4 * 1024 * 1024)})

    def test_does_not_echo_passphrase_or_return_derived_key(self):
        encrypted = self.encrypt()
        rendered = json.dumps(encrypted, sort_keys=True)
        self.assertNotIn(PASSPHRASE, rendered)
        self.assertNotIn("derived_key", rendered)
        self.assertNotIn("passphrase", rendered)
        self.assertNotIn("AES key", rendered)

    def test_random_salt_and_nonce_produce_distinct_ciphertexts(self):
        first = self.encrypt()
        second = self.encrypt()
        self.assertNotEqual(first["archive"]["salt"], second["archive"]["salt"])
        self.assertNotEqual(first["archive"]["nonce"], second["archive"]["nonce"])
        self.assertNotEqual(first["archive"]["ciphertext"], second["archive"]["ciphertext"])


if __name__ == "__main__":
    unittest.main()
