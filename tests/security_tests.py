"""
SimpliBank – Security Tests
=============================
Validates the security posture of the banking system.

Coverage:
    1. Unauthorised access is blocked (no token)
    2. Token misuse after logout is rejected
    3. Brute-force protection locks account after 5 consecutive failures
    4. Passwords are stored hashed – never as plaintext
    5. Secure hashing replaces a deliberately vulnerable login pattern

Run:
    python -m pytest security_tests.py -v
    -- or --
    python security_tests.py
"""

import hashlib
import unittest

from banking_system import (
    Bank,
    UserAuth,
    AuthenticationError,
    InvalidInputError,
)


# ══════════════════════════════════════════════
# 1. Unauthorised Access Blocking
# ══════════════════════════════════════════════

class TestUnauthorisedAccess(unittest.TestCase):
    """
    Ensure that every sensitive operation rejects invalid / missing tokens.
    """

    def setUp(self):
        self.bank = Bank()
        self.bank.register_user("alice", "AlicePass1!")
        self.alice_tok = self.bank.login("alice", "AlicePass1!")

    def test_get_balance_requires_valid_token(self):
        """get_balance() with a random string must raise AuthenticationError."""
        with self.assertRaises(AuthenticationError):
            self.bank.get_balance("RANDOM_FAKE_TOKEN_XYZ")

    def test_deposit_requires_valid_token(self):
        """deposit() with an invalid token must raise AuthenticationError."""
        with self.assertRaises(AuthenticationError):
            self.bank.deposit("INVALID_TOKEN", 500.0)

    def test_transfer_requires_valid_token(self):
        """transfer() with an invalid token must raise AuthenticationError."""
        self.bank.register_user("bob", "BobPass123!")
        with self.assertRaises(AuthenticationError):
            self.bank.transfer("INVALID_TOKEN", "bob", 100.0)

    def test_transaction_history_requires_valid_token(self):
        """get_transaction_history() with an invalid token must raise."""
        with self.assertRaises(AuthenticationError):
            self.bank.get_transaction_history("INVALID_TOKEN")

    def test_empty_string_token_is_rejected(self):
        """An empty-string token must be rejected as invalid."""
        with self.assertRaises(AuthenticationError):
            self.bank.get_balance("")


# ══════════════════════════════════════════════
# 2. Token Misuse After Logout
# ══════════════════════════════════════════════

class TestTokenMisuseAfterLogout(unittest.TestCase):
    """
    Verify that a token cannot be replayed after the session ends.
    """

    def setUp(self):
        self.bank = Bank()
        self.bank.register_user("alice", "AlicePass1!")
        self.token = self.bank.login("alice", "AlicePass1!")

    def test_used_token_rejected_after_logout(self):
        """Token should be invalid immediately after logout."""
        self.bank.logout(self.token)
        with self.assertRaises(AuthenticationError):
            self.bank.get_balance(self.token)

    def test_transfer_blocked_after_logout(self):
        """transfer() should be blocked when the sender's token is revoked."""
        self.bank.register_user("bob", "BobPass123!")
        self.bank.deposit(self.token, 500.0)
        self.bank.logout(self.token)
        with self.assertRaises(AuthenticationError):
            self.bank.transfer(self.token, "bob", 100.0)

    def test_double_logout_raises_authentication_error(self):
        """Attempting to logout a token twice must raise AuthenticationError."""
        self.bank.logout(self.token)
        with self.assertRaises(AuthenticationError):
            self.bank.logout(self.token)

    def test_new_login_produces_fresh_token(self):
        """After logout, a new login must produce a different, valid token."""
        self.bank.logout(self.token)
        new_token = self.bank.login("alice", "AlicePass1!")

        # Old token rejected
        with self.assertRaises(AuthenticationError):
            self.bank.get_balance(self.token)

        # New token accepted
        balance = self.bank.get_balance(new_token)
        self.assertIsNotNone(balance)


# ══════════════════════════════════════════════
# 3. Brute-Force Protection
# ══════════════════════════════════════════════

class TestBruteForceProtection(unittest.TestCase):
    """
    Verify that accounts are locked after MAX_FAILED_ATTEMPTS bad passwords.
    """

    def setUp(self):
        self.bank = Bank()
        self.bank.register_user("victim", "VictimPass1")

    def _fail_login(self, n: int):
        """Attempt n failed logins against 'victim' account."""
        for _ in range(n):
            try:
                self.bank.login("victim", "WRONG_PASSWORD")
            except AuthenticationError:
                pass

    def test_four_failures_do_not_lock(self):
        """Four wrong passwords should not lock the account."""
        self._fail_login(4)
        # Correct password must still work
        token = self.bank.login("victim", "VictimPass1")
        self.assertIsNotNone(token)

    def test_five_failures_lock_account(self):
        """Five wrong passwords must lock the account permanently."""
        self._fail_login(5)
        with self.assertRaises(AuthenticationError):
            self.bank.login("victim", "VictimPass1")

    def test_correct_password_after_lock_still_blocked(self):
        """Even the correct password must be rejected once account is locked."""
        self._fail_login(5)
        with self.assertRaises(AuthenticationError):
            self.bank.login("victim", "VictimPass1")

    def test_account_locks_on_exactly_fifth_attempt(self):
        """Lock should trigger on exactly the 5th failed attempt."""
        self._fail_login(4)
        # 5th wrong → should lock and raise
        with self.assertRaises(AuthenticationError):
            self.bank.login("victim", "WRONG_PASSWORD")
        # Now locked
        user_rec = self.bank.auth.get_user_record("victim")
        self.assertTrue(user_rec["locked"])

    def test_lock_flag_is_set_in_user_record(self):
        """The internal user record must show locked=True after 5 failures."""
        self._fail_login(5)
        user_rec = self.bank.auth.get_user_record("victim")
        self.assertTrue(user_rec["locked"])


# ══════════════════════════════════════════════
# 4. Password Hashing (never plaintext)
# ══════════════════════════════════════════════

class TestPasswordHashing(unittest.TestCase):
    """
    Verify that passwords are stored securely and never as plaintext.
    """

    def setUp(self):
        self.auth = UserAuth()

    def test_stored_hash_differs_from_plaintext(self):
        """The stored hash must NOT equal the original password string."""
        self.auth.register("alice", "MySuperSecret")
        record = self.auth.get_user_record("alice")
        self.assertNotEqual(record["hash"], "MySuperSecret")

    def test_each_user_has_unique_salt(self):
        """Two users with the same password must have different salts."""
        self.auth.register("user1", "SamePassword1")
        self.auth.register("user2", "SamePassword1")
        rec1 = self.auth.get_user_record("user1")
        rec2 = self.auth.get_user_record("user2")
        self.assertNotEqual(rec1["salt"], rec2["salt"])

    def test_same_password_different_users_different_hashes(self):
        """
        Two users with identical passwords must have different hashes
        due to per-user salting.
        """
        self.auth.register("user_a", "SamePassword1")
        self.auth.register("user_b", "SamePassword1")
        rec_a = self.auth.get_user_record("user_a")
        rec_b = self.auth.get_user_record("user_b")
        self.assertNotEqual(rec_a["hash"], rec_b["hash"])

    def test_hash_is_hex_string(self):
        """The stored hash should be a valid hexadecimal SHA-256 digest."""
        self.auth.register("bob", "BobSecure99")
        record = self.auth.get_user_record("bob")
        stored_hash = record["hash"]
        # SHA-256 hex digest is always 64 characters
        self.assertEqual(len(stored_hash), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in stored_hash))

    def test_password_not_recoverable_from_record(self):
        """A brute-force check: common passwords should not match the stored hash."""
        plaintext = "password1"
        self.auth.register("charlie", plaintext)
        record = self.auth.get_user_record("charlie")
        common_guesses = ["password", "password1", "123456", "charlie"]
        for guess in common_guesses:
            self.assertNotEqual(record["hash"], guess)


# ══════════════════════════════════════════════
# 5. Secure vs Vulnerable Login Implementation
# ══════════════════════════════════════════════

class VulnerableAuth:
    """
    ⚠️  DELIBERATELY INSECURE reference implementation.
    Stores passwords in plaintext – included here ONLY to demonstrate
    what NOT to do, and to contrast against SecureAuth below.
    """

    def __init__(self):
        self._users: dict[str, str] = {}  # {username: plaintext_password}

    def register(self, username: str, password: str) -> None:
        # ❌ VULNERABILITY: password saved as plaintext
        self._users[username] = password

    def login(self, username: str, password: str) -> bool:
        # ❌ VULNERABILITY: direct plaintext comparison
        return self._users.get(username) == password


class SecureAuth:
    """
    ✅  SECURE replacement for VulnerableAuth.
    Uses SHA-256 + per-user random salt.  Mirrors the approach used
    in the production UserAuth class in banking_system.py.
    """

    def __init__(self):
        # {username: {"hash": str, "salt": str}}
        self._users: dict[str, dict] = {}

    @staticmethod
    def _hash(password: str, salt: str) -> str:
        return hashlib.sha256((salt + password).encode()).hexdigest()

    def register(self, username: str, password: str) -> None:
        import secrets
        salt = secrets.token_hex(16)
        self._users[username] = {
            "hash": self._hash(password, salt),
            "salt": salt,
        }

    def login(self, username: str, password: str) -> bool:
        if username not in self._users:
            return False
        record = self._users[username]
        return self._hash(password, record["salt"]) == record["hash"]


class TestSecureVsVulnerableLogin(unittest.TestCase):
    """
    Demonstrates that VulnerableAuth exposes plaintext passwords while
    SecureAuth stores only hashed credentials.
    """

    def test_vulnerable_stores_plaintext(self):
        """VulnerableAuth stores the password exactly as provided."""
        vuln = VulnerableAuth()
        vuln.register("alice", "secret123")
        # Internal dict holds the plaintext directly
        self.assertEqual(vuln._users["alice"], "secret123")

    def test_secure_does_not_store_plaintext(self):
        """SecureAuth must never store the password in plaintext."""
        secure = SecureAuth()
        secure.register("alice", "secret123")
        record = secure._users["alice"]
        self.assertNotEqual(record["hash"], "secret123")
        self.assertIn("salt", record)

    def test_secure_login_accepts_correct_password(self):
        """SecureAuth.login() must return True for the correct password."""
        secure = SecureAuth()
        secure.register("bob", "mypassword")
        self.assertTrue(secure.login("bob", "mypassword"))

    def test_secure_login_rejects_wrong_password(self):
        """SecureAuth.login() must return False for an incorrect password."""
        secure = SecureAuth()
        secure.register("bob", "mypassword")
        self.assertFalse(secure.login("bob", "wrongpassword"))

    def test_secure_hashes_differ_per_user(self):
        """Same password registered by two users must produce different hashes."""
        secure = SecureAuth()
        secure.register("user1", "commonpass")
        secure.register("user2", "commonpass")
        self.assertNotEqual(
            secure._users["user1"]["hash"],
            secure._users["user2"]["hash"],
        )


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)
