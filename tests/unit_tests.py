"""
SimpliBank – Unit Tests
========================
Tests individual classes in complete isolation.

Coverage:
    Account  : deposit, withdraw, balance, history, invalid inputs
    UserAuth : register, login, logout, token validation, brute-force lock

Run:
    python -m pytest unit_tests.py -v
    -- or --
    python unit_tests.py
"""

import unittest

from backend.models import (
    Account,
    AuthenticationError,
    InsufficientFundsError,
    InvalidInputError,
)
from backend.auth import UserAuth


# ══════════════════════════════════════════════
# Account Unit Tests
# ══════════════════════════════════════════════

class TestAccountDeposit(unittest.TestCase):
    """Tests for Account.deposit()"""

    def setUp(self):
        """Create a fresh account before every test."""
        self.account = Account(owner="alice", initial_balance=0.0)

    # ── Happy-path ───────────────────────────

    def test_deposit_increases_balance(self):
        """A valid deposit must increase the balance by the exact amount."""
        self.account.deposit(500.0)
        self.assertEqual(self.account.get_balance(), 500.0)

    def test_multiple_deposits_accumulate(self):
        """Multiple deposits should accumulate correctly."""
        self.account.deposit(200.0)
        self.account.deposit(300.0)
        self.assertEqual(self.account.get_balance(), 500.0)

    def test_deposit_returns_new_balance(self):
        """deposit() should return the updated balance."""
        new_balance = self.account.deposit(150.0)
        self.assertEqual(new_balance, 150.0)

    def test_deposit_records_transaction(self):
        """Each deposit should add one entry to the history."""
        self.account.deposit(100.0)
        history = self.account.get_history()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["type"], "deposit")
        self.assertEqual(history[0]["amount"], 100.0)

    # ── Error cases ──────────────────────────

    def test_deposit_negative_amount_raises_invalid_input(self):
        """Depositing a negative amount must raise InvalidInputError."""
        with self.assertRaises(InvalidInputError):
            self.account.deposit(-50.0)

    def test_deposit_zero_raises_invalid_input(self):
        """Depositing zero must raise InvalidInputError."""
        with self.assertRaises(InvalidInputError):
            self.account.deposit(0)

    def test_deposit_does_not_change_balance_on_error(self):
        """Balance must remain unchanged after a failed deposit attempt."""
        try:
            self.account.deposit(-100.0)
        except InvalidInputError:
            pass
        self.assertEqual(self.account.get_balance(), 0.0)


class TestAccountWithdraw(unittest.TestCase):
    """Tests for Account.withdraw()"""

    def setUp(self):
        self.account = Account(owner="bob", initial_balance=1000.0)

    # ── Happy-path ───────────────────────────

    def test_withdraw_decreases_balance(self):
        """A valid withdrawal must decrease the balance by the exact amount."""
        self.account.withdraw(400.0)
        self.assertEqual(self.account.get_balance(), 600.0)

    def test_withdraw_returns_new_balance(self):
        """withdraw() should return the updated balance."""
        result = self.account.withdraw(250.0)
        self.assertEqual(result, 750.0)

    def test_withdraw_full_balance(self):
        """Withdrawing the exact balance should leave zero."""
        self.account.withdraw(1000.0)
        self.assertEqual(self.account.get_balance(), 0.0)

    def test_withdraw_records_transaction(self):
        """Each withdrawal should add one entry to the history."""
        self.account.withdraw(100.0)
        history = self.account.get_history()
        # history[0] is the 'initial deposit'; history[1] is the withdrawal
        withdrawal_entries = [tx for tx in history if tx["type"] == "withdrawal"]
        self.assertEqual(len(withdrawal_entries), 1)
        self.assertEqual(withdrawal_entries[0]["amount"], 100.0)

    # ── Error cases ──────────────────────────

    def test_withdraw_more_than_balance_raises_insufficient_funds(self):
        """Overdraft attempt must raise InsufficientFundsError."""
        with self.assertRaises(InsufficientFundsError):
            self.account.withdraw(2000.0)

    def test_withdraw_negative_amount_raises_invalid_input(self):
        """Withdrawing a negative amount must raise InvalidInputError."""
        with self.assertRaises(InvalidInputError):
            self.account.withdraw(-100.0)

    def test_withdraw_zero_raises_invalid_input(self):
        """Withdrawing zero must raise InvalidInputError."""
        with self.assertRaises(InvalidInputError):
            self.account.withdraw(0)

    def test_balance_unchanged_after_failed_withdrawal(self):
        """Balance must remain unchanged after an overdraft attempt."""
        try:
            self.account.withdraw(9999.0)
        except InsufficientFundsError:
            pass
        self.assertEqual(self.account.get_balance(), 1000.0)


class TestAccountInitialisation(unittest.TestCase):
    """Tests for Account.__init__()"""

    def test_negative_initial_balance_raises_invalid_input(self):
        """Creating an account with a negative balance must raise InvalidInputError."""
        with self.assertRaises(InvalidInputError):
            Account(owner="eve", initial_balance=-500.0)

    def test_zero_initial_balance_is_valid(self):
        """Zero is a valid initial balance."""
        acc = Account(owner="charlie", initial_balance=0.0)
        self.assertEqual(acc.get_balance(), 0.0)

    def test_positive_initial_balance_is_stored(self):
        """A positive initial balance should be stored correctly."""
        acc = Account(owner="diana", initial_balance=750.0)
        self.assertEqual(acc.get_balance(), 750.0)

    def test_initial_balance_creates_history_entry(self):
        """A non-zero initial balance should create one history record."""
        acc = Account(owner="frank", initial_balance=200.0)
        history = acc.get_history()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["type"], "initial deposit")


class TestAccountTransactionHistory(unittest.TestCase):
    """Tests for Account transaction history integrity."""

    def setUp(self):
        self.account = Account(owner="grace", initial_balance=500.0)

    def test_history_is_ordered_chronologically(self):
        """Transactions should appear in the order they were made."""
        self.account.deposit(100.0)
        self.account.withdraw(50.0)
        history = self.account.get_history()
        types = [tx["type"] for tx in history]
        self.assertEqual(types, ["initial deposit", "deposit", "withdrawal"])

    def test_history_returns_copy_not_reference(self):
        """Mutating the returned history list must not affect internal state."""
        history = self.account.get_history()
        history.clear()
        self.assertGreater(len(self.account.get_history()), 0)

    def test_balance_after_field_is_accurate(self):
        """Each history entry's balance_after should match the running balance."""
        self.account.deposit(200.0)   # balance → 700
        self.account.withdraw(100.0)  # balance → 600
        history = self.account.get_history()
        self.assertEqual(history[-1]["balance_after"], 600.0)


# ══════════════════════════════════════════════
# UserAuth Unit Tests
# ══════════════════════════════════════════════

class TestUserAuthRegister(unittest.TestCase):
    """Tests for UserAuth.register()"""

    def setUp(self):
        self.auth = UserAuth()

    def test_register_new_user_succeeds(self):
        """Registering a fresh username should not raise."""
        self.auth.register("alice", "securepass")  # Should not raise

    def test_duplicate_username_raises_invalid_input(self):
        """Registering the same username twice must raise InvalidInputError."""
        self.auth.register("bob", "password123")
        with self.assertRaises(InvalidInputError):
            self.auth.register("bob", "different_pass")

    def test_short_password_raises_invalid_input(self):
        """A password shorter than 8 characters must raise InvalidInputError."""
        with self.assertRaises(InvalidInputError):
            self.auth.register("charlie", "short")

    def test_password_exactly_8_chars_is_accepted(self):
        """A password of exactly 8 characters should be accepted."""
        self.auth.register("diana", "12345678")  # Should not raise

    def test_password_stored_as_hash_not_plaintext(self):
        """The stored password must NOT equal the plaintext version."""
        self.auth.register("eve", "supersecret")
        record = self.auth.get_user_record("eve")
        self.assertNotEqual(record["hash"], "supersecret")
        self.assertIn("salt", record)


class TestUserAuthLogin(unittest.TestCase):
    """Tests for UserAuth.login()"""

    def setUp(self):
        self.auth = UserAuth()
        self.auth.register("alice", "password123")

    def test_correct_credentials_return_token(self):
        """A valid login should return a non-empty token string."""
        token = self.auth.login("alice", "password123")
        self.assertIsInstance(token, str)
        self.assertGreater(len(token), 0)

    def test_wrong_password_raises_authentication_error(self):
        """An incorrect password must raise AuthenticationError."""
        with self.assertRaises(AuthenticationError):
            self.auth.login("alice", "wrongpassword")

    def test_unknown_username_raises_invalid_input(self):
        """Logging in with an unregistered username must raise InvalidInputError."""
        with self.assertRaises(InvalidInputError):
            self.auth.login("nobody", "password123")

    def test_token_is_unique_per_session(self):
        """Each successful login should produce a different token."""
        token1 = self.auth.login("alice", "password123")
        self.auth.logout(token1)
        token2 = self.auth.login("alice", "password123")
        self.assertNotEqual(token1, token2)


class TestUserAuthLogout(unittest.TestCase):
    """Tests for UserAuth.logout()"""

    def setUp(self):
        self.auth = UserAuth()
        self.auth.register("alice", "password123")
        self.token = self.auth.login("alice", "password123")

    def test_logout_invalidates_token(self):
        """After logout, is_authenticated() must return False."""
        self.auth.logout(self.token)
        self.assertFalse(self.auth.is_authenticated(self.token))

    def test_logout_with_invalid_token_raises_authentication_error(self):
        """Logging out with a bogus token must raise AuthenticationError."""
        with self.assertRaises(AuthenticationError):
            self.auth.logout("fake-token-xyz")

    def test_double_logout_raises_authentication_error(self):
        """Attempting to logout twice with the same token must raise."""
        self.auth.logout(self.token)
        with self.assertRaises(AuthenticationError):
            self.auth.logout(self.token)


class TestUserAuthBruteForce(unittest.TestCase):
    """Tests for brute-force protection in UserAuth.login()"""

    def setUp(self):
        self.auth = UserAuth()
        self.auth.register("victim", "safepassword")

    def test_account_locks_after_five_failed_attempts(self):
        """The account must be locked after 5 consecutive wrong-password attempts."""
        for _ in range(4):
            with self.assertRaises(AuthenticationError):
                self.auth.login("victim", "wrongpassword")

        # 5th attempt – should lock and raise
        with self.assertRaises(AuthenticationError):
            self.auth.login("victim", "wrongpassword")

        # Subsequent correct password is still blocked
        with self.assertRaises(AuthenticationError):
            self.auth.login("victim", "safepassword")

    def test_correct_login_resets_failure_counter(self):
        """A successful login should reset the failed-attempt counter."""
        # 3 wrong attempts
        for _ in range(3):
            with self.assertRaises(AuthenticationError):
                self.auth.login("victim", "wrong")

        # Correct login resets counter and returns token
        token = self.auth.login("victim", "safepassword")
        self.auth.logout(token)

        # Account should still be usable
        record = self.auth.get_user_record("victim")
        self.assertEqual(record["failed"], 0)
        self.assertFalse(record["locked"])


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)
