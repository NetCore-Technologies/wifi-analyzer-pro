import json
import os
import stat
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from wifi_analyzer_backend.auth import AuthManager


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

    def test_first_run_setup_creates_protected_verifier_and_session(self):
        self.assertFalse(self.auth.configured())
        token = self.auth.setup("correct horse battery staple")
        self.assertTrue(self.auth.validate(token))
        self.assertTrue(self.auth.configured())
        self.assertTrue(Path(self.auth.path).exists())
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(Path(self.auth.path).stat().st_mode), 0o600)

    def test_login_survives_auth_manager_restart(self):
        self.auth.setup("correct horse battery staple")
        restarted = AuthManager(path=self.auth_path, session_ttl_seconds=300)
        token = restarted.login("correct horse battery staple")
        self.assertTrue(restarted.validate(token))

    def test_session_expiry_revokes_token(self):
        token = self.auth.setup("correct horse battery staple")
        digest = __import__("hashlib").sha256(token.encode()).hexdigest()
        self.auth._sessions[digest] = 0
        self.assertFalse(self.auth.validate(token))

    def test_corrupt_auth_file_fails_closed_and_cannot_be_replaced_by_setup(self):
        Path(self.auth.path).write_text("not-json", encoding="utf-8")
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
        contents = Path(self.auth.path).read_text(encoding="utf-8")
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

    def test_version_one_single_password_file_migrates_to_admin_without_password_reset(self):
        legacy_password = "correct horse battery staple"
        salt = b"legacy-auth-salt1"
        verifier = AuthManager._derive(legacy_password, salt)
        Path(self.auth.path).write_text(json.dumps({
            "version": 1,
            "salt": salt.hex(),
            "verifier": verifier.hex(),
            "created_at": 1700000000,
        }), encoding="utf-8")
        migrated = AuthManager(path=self.auth_path, session_ttl_seconds=300)
        token = migrated.login(legacy_password)
        self.assertTrue(migrated.validate(token))
        self.assertEqual(migrated.session_info(token)["username"], "admin")
        self.assertEqual(migrated.session_info(token)["role"], "admin")
        saved = json.loads(Path(self.auth.path).read_text(encoding="utf-8"))
        self.assertEqual(saved["version"], 2)
        self.assertIn("admin", saved["users"])

    def test_viewer_sessions_include_only_assigned_sites_and_revoke_on_scope_change(self):
        self.auth.setup("correct horse battery staple")
        self.auth.create_user(
            "field.viewer", "viewer password phrase 2026", "viewer", ["home", "branch"],
        )
        token = self.auth.login("viewer password phrase 2026", "field.viewer")
        self.assertEqual(self.auth.session_info(token)["role"], "viewer")
        self.assertEqual(self.auth.session_info(token)["site_ids"], ["branch", "home"])
        self.auth.update_user("field.viewer", site_ids=["home"], update_sites=True)
        self.assertFalse(self.auth.validate(token))
        new_token = self.auth.login("viewer password phrase 2026", "field.viewer")
        self.assertEqual(self.auth.session_info(new_token)["site_ids"], ["home"])

    def test_disabling_user_and_resetting_password_revoke_all_existing_sessions(self):
        self.auth.setup("correct horse battery staple")
        self.auth.create_user("operator.one", "operator password phrase", "viewer", ["home"])
        token = self.auth.login("operator password phrase", "operator.one")
        self.auth.update_user("operator.one", enabled=False)
        self.assertFalse(self.auth.validate(token))
        with self.assertRaises(PermissionError):
            self.auth.login("operator password phrase", "operator.one")
        self.auth.update_user("operator.one", enabled=True)
        enabled_token = self.auth.login("operator password phrase", "operator.one")
        self.auth.reset_password("operator.one", "replacement operator phrase 2026")
        self.assertFalse(self.auth.validate(enabled_token))
        self.assertTrue(self.auth.validate(
            self.auth.login("replacement operator phrase 2026", "operator.one")
        ))

    def test_last_enabled_administrator_cannot_be_demoted_disabled_or_deleted(self):
        self.auth.setup("correct horse battery staple")
        for operation in (
            lambda: self.auth.update_user("admin", role="viewer", site_ids=["home"], update_sites=True),
            lambda: self.auth.update_user("admin", enabled=False),
            lambda: self.auth.delete_user("admin"),
        ):
            with self.assertRaisesRegex(ValueError, "at least one enabled administrator"):
                operation()

    def test_removing_one_administrator_keeps_other_administrator_sessions_valid(self):
        self.auth.setup("correct horse battery staple")
        self.auth.create_user("backup.admin", "backup administrator phrase", "admin")
        backup_token = self.auth.login("backup administrator phrase", "backup.admin")
        self.auth.delete_user("admin")
        self.assertTrue(self.auth.validate(backup_token))
        self.assertEqual(self.auth.session_info(backup_token)["role"], "admin")
        with self.assertRaises(PermissionError):
            self.auth.login("correct horse battery staple", "admin")

    def test_usernames_roles_and_site_scope_are_validated(self):
        self.auth.setup("correct horse battery staple")
        for username in ("a", "Contains Space", "../admin"):
            with self.subTest(username=username), self.assertRaises(ValueError):
                self.auth.create_user(username, "another secure password", "viewer", ["home"])
        with self.assertRaisesRegex(ValueError, "role must be admin or viewer"):
            self.auth.create_user("operator.two", "another secure password", "owner", ["home"])
        with self.assertRaisesRegex(ValueError, "invalid site identifier"):
            self.auth.create_user("operator.two", "another secure password", "viewer", ["../secret"])

    def test_five_failed_passwords_trigger_temporary_lockout(self):
        self.auth.setup("correct horse battery staple")
        for _ in range(4):
            with self.assertRaises(PermissionError):
                self.auth.login("wrong passphrase")
        with self.assertRaisesRegex(PermissionError, "five minutes"):
            self.auth.login("wrong passphrase")
        with self.assertRaisesRegex(PermissionError, "try again later"):
            self.auth.login("correct horse battery staple")


if __name__ == "__main__":
    unittest.main()
