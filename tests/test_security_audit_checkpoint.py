import json, os, sqlite3, stat, tempfile, unittest
from pathlib import Path

from wifi_analyzer_backend.audit_checkpoint import create_signed_checkpoint, verify_signed_checkpoint
from wifi_analyzer_backend.audit_store import SecurityAuditStore


OWNER = {"id": "a" * 32, "username": "admin", "role": "owner"}


class SignedAuditCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = SecurityAuditStore(self.root / "security-audit.sqlite3")
        self.store.record("auth.setup.completed", actor=OWNER)

    def tearDown(self):
        self.temp.cleanup()

    def test_checkpoint_signature_verifies_with_pinned_public_key(self):
        bundle = create_signed_checkpoint(self.store)
        result = verify_signed_checkpoint(
            bundle,
            expected_public_key_fingerprint=bundle["public_key_fingerprint"],
        )
        self.assertTrue(result["valid"], result)
        self.assertEqual(result["event_count"], 1)
        self.assertEqual(result["latest_event_hash"], self.store.verify_chain()["latest_hash"])

    def test_signing_identity_is_stable_across_exports(self):
        first = create_signed_checkpoint(self.store)
        second = create_signed_checkpoint(self.store)
        self.assertEqual(first["public_key_fingerprint"], second["public_key_fingerprint"])
        self.assertNotEqual(first["checkpoint"]["checkpoint_id"], second["checkpoint"]["checkpoint_id"])

    def test_tampered_checkpoint_and_wrong_pinned_key_are_rejected(self):
        bundle = create_signed_checkpoint(self.store)
        changed = json.loads(json.dumps(bundle))
        changed["checkpoint"]["event_count"] += 1
        self.assertFalse(verify_signed_checkpoint(changed)["valid"])
        self.assertFalse(verify_signed_checkpoint(
            bundle,
            expected_public_key_fingerprint="0" * 64,
        )["valid"])

    def test_invalid_audit_chain_is_never_signed(self):
        with sqlite3.connect(self.store.path) as db:
            db.execute("DROP TRIGGER audit_no_update")
            db.execute("UPDATE security_audit_events SET action='tampered.action' WHERE id=1")
        with self.assertRaisesRegex(ValueError, "verification failed"):
            create_signed_checkpoint(self.store)

    def test_malformed_existing_signing_key_is_not_silently_replaced(self):
        key_path = self.root / "invalid-key"
        key_path.write_bytes(b"not a valid ed25519 private key")
        with self.assertRaisesRegex(RuntimeError, "existing audit signing key is invalid"):
            create_signed_checkpoint(self.store, key_path=key_path)
        self.assertEqual(key_path.read_bytes(), b"not a valid ed25519 private key")

    @unittest.skipIf(os.name == "nt", "POSIX permission bits are not available on Windows")
    def test_private_signing_key_is_owner_only(self):
        create_signed_checkpoint(self.store)
        key_path = self.root / "security-audit-signing-key.ed25519"
        self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
