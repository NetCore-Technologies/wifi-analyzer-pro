import json
import os
import stat
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from wifi_analyzer_backend.auth import AuthManager, ROLE_PERMISSIONS


class AuthManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.auth_path = str(Path(self.temp.name) / "auth.json")
        self.auth = AuthManager(path=self.auth_path, session_ttl_seconds=300)

    def tearDown(self):
        self.temp.cleanup()

    def test_unconfigured_auth_fails_closed(self):
        self.assertFalse(self.auth.validate(None))
        self.assertFalse(self.auth.validate("arbitrary-token"))
        self.assertFalse(self.auth.status()["authenticated"])

    def test_first_run_setup_creates_protected_owner_and_session(self):
        self.assertFalse(self.auth.configured())
        token = self.auth.setup("correct horse battery staple")
        self.assertTrue(self.auth.validate(token))
        self.assertEqual(self.auth.identity(token)["role"], "owner")
        self.assertEqual(self.auth.identity(token)["username"], "admin")
        self.assertTrue(self.auth.configured())
        self.assertTrue(Path(self.auth_path).exists())
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(Path(self.auth_path).stat().st_mode), 0o600)

    def test_login_survives_auth_manager_restart(self):
        self.auth.setup("correct horse battery staple")
        restarted = AuthManager(path=self.auth_path, session_ttl_seconds=300)
        token = restarted.login("correct horse battery staple")
        self.assertTrue(restarted.validate(token))
        self.assertEqual(restarted.identity(token)["role"], "owner")

    def test_legacy_version_one_password_file_migrates_without_resetting_owner_password(self):
        salt = b"0123456789abcdef"
        verifier = AuthManager._derive("correct horse battery staple", salt)
        Path(self.auth_path).write_text(json.dumps({
            "version": 1, "salt": salt.hex(), "verifier": verifier.hex(), "created_at": 123,
        }), encoding="utf-8")
        migrated = AuthManager(path=self.auth_path)
        token = migrated.login("correct horse battery staple")
        self.assertEqual(migrated.identity(token)["role"], "owner")
        saved = json.loads(Path(self.auth_path).read_text(encoding="utf-8"))
        self.assertEqual(saved["version"], 2)
        self.assertEqual(saved["users"][0]["username"], "admin")
        self.assertEqual(saved["users"][0]["created_at"], 123)

    def test_session_expiry_revokes_token(self):
        token = self.auth.setup("correct horse battery staple")
        digest = __import__("hashlib").sha256(token.encode()).hexdigest()
        self.auth._sessions[digest] = 0
        self.assertFalse(self.auth.validate(token))

    def test_corrupt_auth_file_fails_closed_and_cannot_be_replaced_by_setup(self):
        Path(self.auth_path).write_text("not-json", encoding="utf-8")
        broken = AuthManager(path=self.auth_path)
        self.assertTrue(broken.configured())
        self.assertFalse(broken.validate("anything"))
        self.assertTrue(broken.status()["broken"])
        with self.assertRaisesRegex(RuntimeError, "unreadable"):
            broken.setup("another secure passphrase")
        with self.assertRaisesRegex(RuntimeError, "unreadable"):
            broken.login("another secure passphrase")

    def test_session_token_is_not_written_to_auth_file(self):
        token = self.auth.setup("correct horse battery staple")
        contents = Path(self.auth_path).read_text(encoding="utf-8")
        self.assertNotIn(token, contents)
        self.assertIn("verifier", contents)

    def test_wrong_password_is_rejected(self):
        self.auth.setup("correct horse battery staple")
        with self.assertRaises(PermissionError):
            self.auth.login("wrong password")

    def test_logout_revokes_session(self):
        token = self.auth.setup("correct horse battery staple")
        self.assertTrue(self.auth.logout(token))
        self.assertFalse(self.auth.validate(token))

    def test_setup_requires_twelve_characters(self):
        with self.assertRaises(ValueError):
            self.auth.setup("short")

    def test_setup_cannot_overwrite_existing_identity(self):
        self.auth.setup("correct horse battery staple")
        with self.assertRaises(RuntimeError):
            self.auth.setup("another secure passphrase")

    def test_password_length_is_bounded_to_prevent_hashing_abuse(self):
        with self.assertRaisesRegex(ValueError, "1024 characters"):
            self.auth.setup("x" * 1025)

    def test_concurrent_first_run_setup_creates_only_one_identity(self):
        def setup():
            try:
                return self.auth.setup("correct horse battery staple")
            except RuntimeError:
                return None
        with ThreadPoolExecutor(max_workers=2) as pool:
            tokens = list(pool.map(lambda _index: setup(), range(2)))
        accepted = [token for token in tokens if token]
        self.assertEqual(len(accepted), 1)
        self.assertTrue(self.auth.validate(accepted[0]))

    def test_five_failed_passwords_trigger_temporary_lockout(self):
        self.auth.setup("correct horse battery staple")
        for _ in range(4):
            with self.assertRaises(PermissionError):
                self.auth.login("wrong passphrase")
        with self.assertRaisesRegex(PermissionError, "five minutes"):
            self.auth.login("wrong passphrase")
        with self.assertRaisesRegex(PermissionError, "try again later"):
            self.auth.login("correct horse battery staple")

    def test_named_users_have_distinct_credentials_and_role_permissions(self):
        owner = self.auth.setup("owner passphrase is secure")
        analyst = self.auth.create_user(owner, "Wireless.Analyst", "analyst password secure", "analyst")
        viewer = self.auth.create_user(owner, "read.only", "viewer password secure", "viewer")
        analyst_token = self.auth.login("analyst password secure", "WIRELESS.ANALYST")
        viewer_token = self.auth.login("viewer password secure", "read.only")
        self.assertEqual(analyst["username"], "wireless.analyst")
        self.assertTrue(self.auth.has_permission(analyst_token, "diagnostics.run"))
        self.assertFalse(self.auth.has_permission(analyst_token, "agents.manage"))
        self.assertTrue(self.auth.has_permission(viewer_token, "sites.read"))
        self.assertFalse(self.auth.has_permission(viewer_token, "diagnostics.run"))
        self.assertFalse(self.auth.has_permission(viewer_token, "users.manage"))

    def test_network_admin_can_manage_network_operations_but_not_people(self):
        owner = self.auth.setup("owner passphrase is secure")
        self.auth.create_user(owner, "netadmin", "network admin passphrase", "network_admin")
        token = self.auth.login("network admin passphrase", "netadmin")
        self.assertTrue(self.auth.has_permission(token, "agents.manage"))
        self.assertTrue(self.auth.has_permission(token, "reports.manage"))
        self.assertFalse(self.auth.has_permission(token, "users.manage"))

    def test_only_owner_can_create_administrators(self):
        owner = self.auth.setup("owner passphrase is secure")
        admin = self.auth.create_user(owner, "admin2", "second admin password", "admin")
        admin_token = self.auth.login("second admin password", "admin2")
        with self.assertRaisesRegex(PermissionError, "Only the owner"):
            self.auth.create_user(admin_token, "admin3", "third admin password", "admin")
        self.assertEqual(admin["role"], "admin")

    def test_owner_cannot_be_disabled_or_demoted_by_an_administrator(self):
        owner = self.auth.setup("owner passphrase is secure")
        admin = self.auth.create_user(owner, "admin2", "second admin password", "admin")
        admin_token = self.auth.login("second admin password", "admin2")
        owner_id = self.auth.identity(owner)["id"]
        with self.assertRaisesRegex(PermissionError, "owner account"):
            self.auth.update_user(admin_token, owner_id, enabled=False)
        self.assertTrue(self.auth.validate(owner))

    def test_disabling_or_resetting_a_user_revokes_their_existing_sessions(self):
        owner = self.auth.setup("owner passphrase is secure")
        user = self.auth.create_user(owner, "analyst", "analyst password secure", "analyst")
        old_token = self.auth.login("analyst password secure", "analyst")
        self.auth.update_user(owner, user["id"], enabled=False)
        self.assertFalse(self.auth.validate(old_token))
        with self.assertRaises(PermissionError):
            self.auth.login("analyst password secure", "analyst")

    def test_role_assignment_and_user_directory_are_bounded_and_secret_free(self):
        owner = self.auth.setup("owner passphrase is secure")
        self.auth.create_user(owner, "viewer1", "viewer passphrase secure", "viewer")
        users = self.auth.list_users(owner)
        rendered = json.dumps(users)
        self.assertEqual([item["username"] for item in users], ["admin", "viewer1"])
        self.assertNotIn("verifier", rendered)
        self.assertNotIn("salt", rendered)
        self.assertNotIn("password", rendered)
        self.assertNotIn("token", rendered)
        with self.assertRaises(ValueError):
            self.auth.create_user(owner, "bad", "short", "viewer")
        with self.assertRaises(ValueError):
            self.auth.create_user(owner, "bad name", "valid password secure", "viewer")
        with self.assertRaises(ValueError):
            self.auth.create_user(owner, "viewer2", "valid password secure", "superuser")


if __name__ == "__main__":
    unittest.main()
