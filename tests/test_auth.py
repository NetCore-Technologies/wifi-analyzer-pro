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
        self.assertEqual(saved["version"], 4)
        self.assertTrue(saved["users"][0]["all_sites"])
        self.assertEqual(saved["users"][0]["username"], "admin")
        self.assertEqual(saved["users"][0]["created_at"], 123)

    def test_session_expiry_revokes_token(self):
        token = self.auth.setup("correct horse battery staple")
        digest = __import__("hashlib").sha256(token.encode()).hexdigest()
        self.auth._sessions[digest] = 0
        self.assertFalse(self.auth.validate(token))

    def test_active_sessions_are_bounded_per_user_and_oldest_is_revoked(self):
        from unittest.mock import patch

        first = self.auth.setup("correct horse battery staple")
        with patch("wifi_analyzer_backend.auth.MAX_SESSIONS_PER_USER", 2):
            second = self.auth.login("correct horse battery staple")
            third = self.auth.login("correct horse battery staple")

        self.assertFalse(self.auth.validate(first))
        self.assertTrue(self.auth.validate(second))
        self.assertTrue(self.auth.validate(third))
        self.assertEqual(len(self.auth._sessions), 2)

    def test_expired_sessions_are_pruned_when_creating_a_new_session(self):
        first = self.auth.setup("correct horse battery staple")
        first_digest = __import__("hashlib").sha256(first.encode()).hexdigest()
        self.auth._sessions[first_digest]["expires_at"] = 0

        second = self.auth.login("correct horse battery staple")

        self.assertNotIn(first_digest, self.auth._sessions)
        self.assertTrue(self.auth.validate(second))
        self.assertEqual(len(self.auth._sessions), 1)

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

    def test_failed_login_lockout_is_scoped_to_the_target_account(self):
        owner = self.auth.setup("correct horse battery staple")
        self.auth.create_user(owner, "network1", "network user passphrase", "viewer")
        for _ in range(4):
            with self.assertRaises(PermissionError):
                self.auth.login("wrong password", "admin")
        with self.assertRaisesRegex(PermissionError, "five minutes"):
            self.auth.login("wrong password", "admin")
        # An attack against one username must not deny every other employee.
        colleague_token = self.auth.login("network user passphrase", "network1")
        self.assertTrue(self.auth.validate(colleague_token))
        with self.assertRaisesRegex(PermissionError, "try again later"):
            self.auth.login("correct horse battery staple", "admin")

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

    def test_billing_management_is_limited_to_workspace_owners_and_administrators(self):
        owner = self.auth.setup("owner passphrase is secure")
        self.assertTrue(self.auth.has_permission(owner, "billing.manage"))
        admin = self.auth.create_user(owner, "billing.admin", "billing admin password", "admin")
        admin_token = self.auth.login("billing admin password", "billing.admin")
        self.assertTrue(self.auth.has_permission(admin_token, "billing.manage"))
        analyst = self.auth.create_user(owner, "billing.analyst", "billing analyst password", "analyst")
        analyst_token = self.auth.login("billing analyst password", "billing.analyst")
        self.assertFalse(self.auth.has_permission(analyst_token, "billing.manage"))

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

    def test_role_changes_revoke_existing_sessions_before_new_permissions_apply(self):
        owner_token = self.auth.setup("correct horse battery staple")
        analyst = self.auth.create_user(
            owner_token,
            "role.change",
            "role change secure password",
            "viewer",
        )
        old_token = self.auth.login("role change secure password", "role.change")
        self.assertTrue(self.auth.has_permission(old_token, "diagnostics.read"))
        self.assertFalse(self.auth.has_permission(old_token, "diagnostics.run"))

        self.auth.update_user(owner_token, analyst["id"], role="analyst")
        self.assertFalse(self.auth.validate(old_token))
        self.assertFalse(self.auth.has_permission(old_token, "diagnostics.run"))

        new_token = self.auth.login("role change secure password", "role.change")
        self.assertTrue(self.auth.has_permission(new_token, "diagnostics.run"))
        self.assertTrue(self.auth.validate(new_token))

    def test_non_string_and_oversized_session_tokens_fail_closed(self):
        self.auth.setup("correct horse battery staple")
        for value in (0, object(), [], "x" * 257):
            self.assertFalse(self.auth.validate(value))
            self.assertIsNone(self.auth.identity(value))
            self.assertFalse(self.auth.logout(value))

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

    def test_site_scopes_are_least_privilege_and_take_effect_for_existing_sessions(self):
        owner = self.auth.setup("owner passphrase is secure")
        scoped = self.auth.create_user(
            owner, "site.analyst", "scoped analyst password", "analyst",
            all_sites=False, site_ids=["home", "branch"],
        )
        token = self.auth.login("scoped analyst password", "site.analyst")
        self.assertEqual(scoped["site_ids"], ["branch", "home"])
        self.assertFalse(scoped["all_sites"])
        self.assertTrue(self.auth.can_access_site(token, "home"))
        self.assertFalse(self.auth.can_access_site(token, "office"))
        self.auth.update_user(owner, scoped["id"], site_ids=["office"])
        self.assertFalse(self.auth.can_access_site(token, "home"))
        self.assertTrue(self.auth.can_access_site(token, "office"))

    def test_site_scope_validation_and_delegation_cannot_escalate_access(self):
        owner = self.auth.setup("owner passphrase is secure")
        scoped_admin = self.auth.create_user(
            owner, "scoped.admin", "scoped admin password", "admin",
            all_sites=False, site_ids=["home"],
        )
        admin_token = self.auth.login("scoped admin password", "scoped.admin")
        with self.assertRaisesRegex(PermissionError, "outside your own assigned scope"):
            self.auth.create_user(
                admin_token, "outside.user", "outside user password", "viewer",
                all_sites=False, site_ids=["office"],
            )
        with self.assertRaisesRegex(PermissionError, "outside your own assigned scope"):
            self.auth.create_user(
                admin_token, "global.user", "global user password", "viewer",
                all_sites=True,
            )
        with self.assertRaisesRegex(ValueError, "unique"):
            self.auth.create_user(
                owner, "duplicate.site", "duplicate site password", "viewer",
                site_ids=["home", "home"],
            )
        with self.assertRaisesRegex(ValueError, "all_sites"):
            self.auth.create_user(
                owner, "conflict.site", "conflict site password", "viewer",
                all_sites=True, site_ids=["home"],
            )
        with self.assertRaisesRegex(ValueError, "identifier"):
            self.auth.create_user(
                owner, "invalid.site", "invalid site password", "viewer",
                site_ids=["bad site id"],
            )
        self.assertTrue(self.auth.can_access_site(admin_token, "home"))
        self.assertFalse(self.auth.can_access_site(admin_token, "office"))
        self.assertEqual(self.auth.site_access(admin_token), {
            "all_sites": False, "site_ids": ["home"],
        })

    def test_version_two_accounts_migrate_with_existing_unrestricted_site_access(self):
        owner_token = self.auth.setup("owner passphrase is secure")
        self.auth.create_user(owner_token, "legacy.user", "legacy user password", "viewer")
        saved = json.loads(Path(self.auth_path).read_text(encoding="utf-8"))
        saved["version"] = 2
        for user in saved["users"]:
            user.pop("all_sites", None)
            user.pop("site_ids", None)
        Path(self.auth_path).write_text(json.dumps(saved), encoding="utf-8")
        migrated = AuthManager(path=self.auth_path)
        login = migrated.login("legacy user password", "legacy.user")
        self.assertTrue(migrated.site_access(login)["all_sites"])
        migrated_state = json.loads(Path(self.auth_path).read_text(encoding="utf-8"))
        self.assertEqual(migrated_state["version"], 4)
        self.assertTrue(all(user["all_sites"] for user in migrated_state["users"]))

    def test_totp_enrolment_is_encrypted_confirmed_and_required_at_login(self):
        token = self.auth.setup("correct horse battery staple")
        pending = self.auth.begin_mfa_setup(token, "correct horse battery staple", now=1_800_000_000)
        saved_pending = json.loads(Path(self.auth_path).read_text(encoding="utf-8"))
        owner = saved_pending["users"][0]
        self.assertIsNone(owner["mfa_secret_encrypted"])
        self.assertIsNotNone(owner["mfa_pending_secret_encrypted"])
        self.assertNotIn(pending["secret"], Path(self.auth_path).read_text(encoding="utf-8"))
        self.assertTrue(pending["otpauth_uri"].startswith("otpauth://totp/"))

        with self.assertRaisesRegex(PermissionError, "authenticator code is invalid"):
            self.auth.confirm_mfa_setup(token, "correct horse battery staple", "000000", now=1_800_000_000)
        code = AuthManager._totp_code(pending["secret"], at=1_800_000_000)
        confirmed = self.auth.confirm_mfa_setup(token, "correct horse battery staple", code, now=1_800_000_000)
        self.assertTrue(confirmed["mfa_enabled"])
        self.assertEqual(len(confirmed["recovery_codes"]), 10)
        identity = self.auth.identity(token)
        self.assertTrue(identity["mfa_enabled"])
        self.assertEqual(identity["recovery_codes_remaining"], 10)

        stored = Path(self.auth_path).read_text(encoding="utf-8")
        self.assertNotIn(pending["secret"], stored)
        with self.assertRaisesRegex(PermissionError, "two-factor"):
            self.auth.login("correct horse battery staple")
        with self.assertRaisesRegex(PermissionError, "two-factor code"):
            self.auth.login("correct horse battery staple", code="123456", now=1_800_000_000)
        session = self.auth.login("correct horse battery staple", code=code, now=1_800_000_000)
        self.assertTrue(self.auth.validate(session))

    def test_recovery_codes_are_single_use_and_password_reset_requires_mfa_reenrolment(self):
        token = self.auth.setup("correct horse battery staple")
        pending = self.auth.begin_mfa_setup(token, "correct horse battery staple", now=1_800_000_000)
        code = AuthManager._totp_code(pending["secret"], at=1_800_000_000)
        result = self.auth.confirm_mfa_setup(token, "correct horse battery staple", code, now=1_800_000_000)
        recovery = result["recovery_codes"][0]

        recovered = self.auth.login("correct horse battery staple", code=recovery, now=1_800_000_001)
        self.assertTrue(self.auth.validate(recovered))
        self.assertEqual(self.auth.identity(recovered)["recovery_codes_remaining"], 9)
        with self.assertRaisesRegex(PermissionError, "two-factor code"):
            self.auth.login("correct horse battery staple", code=recovery, now=1_800_000_002)

        owner = self.auth.identity(token)
        self.auth.update_user(token, owner["id"], password="replacement owner passphrase")
        # Password reset intentionally invalidates all sessions, including the
        # session which initiated the reset. Sign in again with the new password.
        self.assertIsNone(self.auth.identity(token))
        new_session = self.auth.login("replacement owner passphrase")
        self.assertTrue(self.auth.validate(new_session))
        self.assertFalse(self.auth.identity(new_session)["mfa_enabled"])

    def test_mfa_setup_requires_password_expires_and_can_be_disabled(self):
        token = self.auth.setup("correct horse battery staple")
        with self.assertRaisesRegex(PermissionError, "Password verification"):
            self.auth.begin_mfa_setup(token, "wrong password here", now=1_800_000_000)
        pending = self.auth.begin_mfa_setup(token, "correct horse battery staple", now=1_800_000_000)
        with self.assertRaisesRegex(ValueError, "expired"):
            self.auth.confirm_mfa_setup(
                token, "correct horse battery staple",
                AuthManager._totp_code(pending["secret"], at=1_800_000_000),
                now=1_800_000_901,
            )
        pending = self.auth.begin_mfa_setup(token, "correct horse battery staple", now=1_800_000_000)
        code = AuthManager._totp_code(pending["secret"], at=1_800_000_000)
        self.auth.confirm_mfa_setup(token, "correct horse battery staple", code, now=1_800_000_000)
        with self.assertRaisesRegex(PermissionError, "Password verification"):
            self.auth.disable_mfa(token, "incorrect password", code, now=1_800_000_000)
        self.assertFalse(self.auth.disable_mfa(
            token, "correct horse battery staple", code, now=1_800_000_000,
        )["mfa_enabled"])
        self.assertFalse(self.auth.identity(token)["mfa_enabled"])

    def test_password_file_v3_migrates_to_mfa_capable_v4_without_enabling_mfa(self):
        token = self.auth.setup("correct horse battery staple")
        self.auth.create_user(token, "legacy.user", "legacy user password", "viewer")
        saved = json.loads(Path(self.auth_path).read_text(encoding="utf-8"))
        saved["version"] = 3
        for user in saved["users"]:
            for field in (
                "mfa_secret_encrypted", "mfa_pending_secret_encrypted",
                "mfa_pending_created_at", "mfa_recovery_hashes",
            ):
                user.pop(field, None)
        Path(self.auth_path).write_text(json.dumps(saved), encoding="utf-8")
        migrated = AuthManager(path=self.auth_path)
        user_token = migrated.login("legacy user password", "legacy.user")
        self.assertFalse(migrated.identity(user_token)["mfa_enabled"])
        migrated_state = json.loads(Path(self.auth_path).read_text(encoding="utf-8"))
        self.assertEqual(migrated_state["version"], 4)
        self.assertTrue(all(user["mfa_secret_encrypted"] is None for user in migrated_state["users"]))

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
        self.assertNotIn("mfa_secret", rendered)
        self.assertNotIn("recovery_hash", rendered)
        with self.assertRaises(ValueError):
            self.auth.create_user(owner, "bad", "short", "viewer")
        with self.assertRaises(ValueError):
            self.auth.create_user(owner, "bad name", "valid password secure", "viewer")
        with self.assertRaises(ValueError):
            self.auth.create_user(owner, "viewer2", "valid password secure", "superuser")


if __name__ == "__main__":
    unittest.main()
