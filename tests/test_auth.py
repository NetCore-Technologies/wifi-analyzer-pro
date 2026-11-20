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
        self.assertTrue(Path(self.auth_path).exists())
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(Path(self.auth_path).stat().st_mode), 0o600)

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


if __name__ == "__main__":
    unittest.main()
