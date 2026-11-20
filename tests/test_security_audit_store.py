import json, sqlite3, tempfile, unittest
from pathlib import Path
from wifi_analyzer_backend.audit_store import SecurityAuditStore, ZERO_HASH

OWNER={"id":"a"*32,"username":"admin","role":"owner"}
class SecurityAuditStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.path=Path(self.tmp.name)/"audit.sqlite3"; self.store=SecurityAuditStore(self.path)
    def tearDown(self): self.tmp.cleanup()
    def test_chain_persists_and_excludes_secret_metadata(self):
        a=self.store.record("auth.login.succeeded",actor=OWNER,metadata={"username":"admin","password":"do-not-store"})
        b=self.store.record("user.created",actor=OWNER)
        self.assertEqual(a["previous_hash"],ZERO_HASH); self.assertEqual(b["previous_hash"],a["event_hash"])
        self.assertTrue(SecurityAuditStore(self.path).verify_chain()["valid"])
        self.assertNotIn("do-not-store",json.dumps(self.store.list_events()))
    def test_allowlist_drops_tokens_and_request_bodies(self):
        event=self.store.record("auth.login.failed",outcome="failure",metadata={"username":"visitor","token":"secret","request_body":{"password":"secret"}})
        self.assertEqual(event["metadata"],{"username":"visitor"})
    def test_update_and_delete_are_rejected(self):
        event=self.store.record("user.created",actor=OWNER)
        for sql in ("UPDATE security_audit_events SET outcome='failure' WHERE id=?","DELETE FROM security_audit_events WHERE id=?"):
            with self.assertRaises(sqlite3.IntegrityError):
                with self.store._db() as db: db.execute(sql,(event["id"],))
    def test_verifier_detects_row_tampering(self):
        self.store.record("user.created",actor=OWNER)
        with sqlite3.connect(self.path) as db:
            db.execute("DROP TRIGGER audit_no_update"); db.execute("UPDATE security_audit_events SET action='tampered' WHERE id=1")
        result=self.store.verify_chain(); self.assertFalse(result["valid"]); self.assertEqual(result["verified_count"],0)
    def test_filter_and_cursor_pagination(self):
        first=self.store.record("auth.login.succeeded",actor=OWNER)
        second=self.store.record("auth.login.failed",actor=OWNER,outcome="failure")
        self.store.record("user.created",actor=OWNER)
        self.assertEqual([x["id"] for x in self.store.list_events(limit=2)],[3,2])
        self.assertEqual(self.store.list_events(before_id=second["id"])[0]["id"],first["id"])
        self.assertEqual(self.store.list_events(outcome="failure")[0]["id"],second["id"])
        with self.assertRaises(ValueError): self.store.list_events(limit=201)
    def test_rejects_invalid_action_actor_and_naive_timestamp(self):
        with self.assertRaises(ValueError): self.store.record("Bad Action")
        with self.assertRaises(ValueError): self.store.record("valid.action",actor={"username":"not valid"})
        with self.assertRaises(ValueError): self.store.record("valid.action",occurred_at="2026-11-20T10:00:00")
