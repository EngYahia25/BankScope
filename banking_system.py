import hashlib
import secrets
from datetime import datetime
import time
import unittest

"""
BankScope - Models
==================
Core domain classes and custom exceptions for the banking system.
"""



# ──────────────────────────────────────────────
# Custom Exceptions
# ──────────────────────────────────────────────

class InvalidInputError(Exception):
    """Raised when a method receives an invalid / unexpected argument."""
    pass


class InsufficientFundsError(Exception):
    """Raised when a withdrawal amount exceeds the current account balance."""
    pass


class AuthenticationError(Exception):
    """Raised when a token is invalid, expired, or the account is locked."""
    pass


# ──────────────────────────────────────────────
# Account Class
# ──────────────────────────────────────────────

class Account:
    """
    Represents a single bank account.
    """

    def __init__(self, owner: str, initial_balance: float = 0.0):
        if initial_balance < 0:
            raise InvalidInputError(
                f"Initial balance cannot be negative. Got: {initial_balance}"
            )
        self.owner = owner
        self._balance = float(initial_balance)
        self._history: list[dict] = []

        if initial_balance > 0:
            self._record("initial deposit", initial_balance, self._balance)

    def _record(self, tx_type: str, amount: float, balance_after: float) -> None:
        """Append a transaction record to the history list."""
        self._history.append({
            "type"         : tx_type,
            "amount"       : amount,
            "balance_after": balance_after,
            "timestamp"    : datetime.utcnow().isoformat(),
        })

    def deposit(self, amount: float) -> float:
        if amount <= 0:
            raise InvalidInputError(
                f"Deposit amount must be positive. Got: {amount}"
            )
        self._balance += amount
        self._record("deposit", amount, self._balance)
        return self._balance

    def withdraw(self, amount: float) -> float:
        if amount <= 0:
            raise InvalidInputError(
                f"Withdrawal amount must be positive. Got: {amount}"
            )
        if amount > self._balance:
            raise InsufficientFundsError(
                f"Insufficient funds. Balance: {self._balance}, Requested: {amount}"
            )
        self._balance -= amount
        self._record("withdrawal", amount, self._balance)
        return self._balance

    def get_balance(self) -> float:
        return self._balance

    def get_history(self) -> list[dict]:
        return list(self._history)


"""
BankScope - Auth
================
Handles user registration, login, session management, and security.
"""





MAX_FAILED_ATTEMPTS = 5

class UserAuth:
    """
    Handles user registration, login, logout, and session management.
    """

    def __init__(self):
        # {username: {"hash": str, "salt": str, "locked": bool, "failed": int}}
        self._users: dict[str, dict] = {}
        # {token: username} – active sessions
        self._sessions: dict[str, str] = {}

    @staticmethod
    def _hash_password(password: str, salt: str) -> str:
        return hashlib.sha256((salt + password).encode()).hexdigest()

    @staticmethod
    def _generate_salt() -> str:
        return secrets.token_hex(16)

    @staticmethod
    def _generate_token() -> str:
        return secrets.token_hex(32)

    def register(self, username: str, password: str) -> None:
        if username in self._users:
            raise InvalidInputError(f"Username '{username}' is already taken.")
        if len(password) < 8:
            raise InvalidInputError("Password must be at least 8 characters long.")

        salt = self._generate_salt()
        pwd_hash = self._hash_password(password, salt)

        self._users[username] = {
            "hash"  : pwd_hash,
            "salt"  : salt,
            "locked": False,
            "failed": 0,
        }

    def login(self, username: str, password: str) -> str:
        if username not in self._users:
            raise InvalidInputError(f"User '{username}' not found.")

        user = self._users[username]

        if user["locked"]:
            raise AuthenticationError(
                f"Account '{username}' is locked after too many failed attempts."
            )

        expected_hash = self._hash_password(password, user["salt"])
        if expected_hash != user["hash"]:
            user["failed"] += 1
            if user["failed"] >= MAX_FAILED_ATTEMPTS:
                user["locked"] = True
                raise AuthenticationError(
                    f"Account '{username}' is now locked after {MAX_FAILED_ATTEMPTS} failed login attempts."
                )
            raise AuthenticationError(
                f"Incorrect password for '{username}'. Attempts remaining: {MAX_FAILED_ATTEMPTS - user['failed']}"
            )

        user["failed"] = 0
        token = self._generate_token()
        self._sessions[token] = username
        return token

    def logout(self, token: str) -> None:
        if token not in self._sessions:
            raise AuthenticationError("Invalid or already-expired session token.")
        del self._sessions[token]

    def is_authenticated(self, token: str) -> bool:
        return token in self._sessions

    def get_username(self, token: str) -> str:
        if token not in self._sessions:
            raise AuthenticationError("Invalid or expired session token.")
        return self._sessions[token]

    def get_user_record(self, username: str) -> dict:
        if username not in self._users:
            raise InvalidInputError(f"User '{username}' not found.")
        return self._users[username]


"""
BankScope - Services
====================
The Bank facade that orchestrates Auth and Account operations.
"""




class Bank:
    """
    High-level banking facade that combines UserAuth and Account management.
    """

    def __init__(self):
        self._auth     = UserAuth()
        # {username: Account}
        self._accounts : dict[str, Account] = {}

    # ── User management ─────────────────────────

    def register_user(self, username: str, password: str,
                      initial_balance: float = 0.0) -> None:
        self._auth.register(username, password)
        self._accounts[username] = Account(username, initial_balance)

    def login(self, username: str, password: str) -> str:
        return self._auth.login(username, password)

    def logout(self, token: str) -> None:
        self._auth.logout(token)

    # ── Account operations ───────────────────────

    def _require_auth(self, token: str) -> str:
        if not self._auth.is_authenticated(token):
            raise AuthenticationError("Access denied: invalid or expired token.")
        return self._auth.get_username(token)

    def get_balance(self, token: str) -> float:
        username = self._require_auth(token)
        return self._accounts[username].get_balance()

    def deposit(self, token: str, amount: float) -> float:
        username = self._require_auth(token)
        return self._accounts[username].deposit(amount)

    def withdraw(self, token: str, amount: float) -> float:
        username = self._require_auth(token)
        return self._accounts[username].withdraw(amount)

    def transfer(self, from_token: str, to_username: str, amount: float) -> None:
        from_username = self._require_auth(from_token)
        if to_username not in self._accounts:
            raise InvalidInputError(f"Recipient '{to_username}' does not exist.")
        
        self._accounts[from_username].withdraw(amount)
        self._accounts[to_username].deposit(amount)

    def get_transaction_history(self, token: str) -> list[dict]:
        username = self._require_auth(token)
        return self._accounts[username].get_history()

    def get_account(self, username: str) -> Account:
        if username not in self._accounts:
            raise InvalidInputError(f"Account for '{username}' not found.")
        return self._accounts[username]

    @property
    def auth(self) -> UserAuth:
        return self._auth


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



"""
SimpliBank – Integration Tests
================================
Verifies interactions between Account, UserAuth, and Bank as a system.

Run:
    python -m pytest integration_tests.py -v
    -- or --
    python integration_tests.py
"""







# ─── Helper ────────────────────────────────────────────────────────────────────

def make_bank():
    """Return a Bank with alice ($1000) and bob ($500) already logged in."""
    bank = Bank()
    bank.register_user("alice", "alice_pass1", initial_balance=1000.0)
    bank.register_user("bob",   "bob_pass123", initial_balance=500.0)
    alice_tok = bank.login("alice", "alice_pass1")
    bob_tok   = bank.login("bob",   "bob_pass123")
    return bank, alice_tok, bob_tok


# ══════════════════════════════════════════════
# Register → Login → Balance
# ══════════════════════════════════════════════

class TestRegisterLoginBalance(unittest.TestCase):

    def setUp(self):
        self.bank = Bank()

    def test_register_and_login_returns_token(self):
        self.bank.register_user("carol", "carol_pass")
        token = self.bank.login("carol", "carol_pass")
        self.assertIsInstance(token, str)
        self.assertTrue(len(token) > 0)

    def test_initial_balance_correct_after_login(self):
        self.bank.register_user("dave", "dave_pass1", initial_balance=250.0)
        token = self.bank.login("dave", "dave_pass1")
        self.assertEqual(self.bank.get_balance(token), 250.0)

    def test_zero_initial_balance_default(self):
        self.bank.register_user("eve", "eve_passXX")
        token = self.bank.login("eve", "eve_passXX")
        self.assertEqual(self.bank.get_balance(token), 0.0)

    def test_duplicate_registration_raises(self):
        self.bank.register_user("frank", "frank_pass")
        with self.assertRaises(InvalidInputError):
            self.bank.register_user("frank", "other_pass")


# ══════════════════════════════════════════════
# Transfer between users
# ══════════════════════════════════════════════

class TestTransferIntegration(unittest.TestCase):

    def setUp(self):
        self.bank, self.alice_tok, self.bob_tok = make_bank()

    def test_transfer_reduces_sender_balance(self):
        self.bank.transfer(self.alice_tok, "bob", 400.0)
        self.assertEqual(self.bank.get_balance(self.alice_tok), 600.0)

    def test_transfer_increases_recipient_balance(self):
        self.bank.transfer(self.alice_tok, "bob", 400.0)
        self.assertEqual(self.bank.get_balance(self.bob_tok), 900.0)

    def test_total_money_conserved_after_transfer(self):
        before = (self.bank.get_balance(self.alice_tok) +
                  self.bank.get_balance(self.bob_tok))
        self.bank.transfer(self.alice_tok, "bob", 300.0)
        after = (self.bank.get_balance(self.alice_tok) +
                 self.bank.get_balance(self.bob_tok))
        self.assertEqual(before, after)

    def test_transfer_insufficient_funds_raises(self):
        with self.assertRaises(InsufficientFundsError):
            self.bank.transfer(self.alice_tok, "bob", 5000.0)

    def test_failed_transfer_leaves_balances_unchanged(self):
        alice_b = self.bank.get_balance(self.alice_tok)
        bob_b   = self.bank.get_balance(self.bob_tok)
        try:
            self.bank.transfer(self.alice_tok, "bob", 9999.0)
        except InsufficientFundsError:
            pass
        self.assertEqual(self.bank.get_balance(self.alice_tok), alice_b)
        self.assertEqual(self.bank.get_balance(self.bob_tok),   bob_b)

    def test_transfer_to_nonexistent_user_raises(self):
        with self.assertRaises(InvalidInputError):
            self.bank.transfer(self.alice_tok, "ghost", 100.0)


# ══════════════════════════════════════════════
# Token Enforcement
# ══════════════════════════════════════════════

class TestAuthenticationEnforcement(unittest.TestCase):

    def setUp(self):
        self.bank, self.alice_tok, self.bob_tok = make_bank()

    def test_invalid_token_blocks_balance(self):
        with self.assertRaises(AuthenticationError):
            self.bank.get_balance("bad-token")

    def test_invalid_token_blocks_transfer(self):
        with self.assertRaises(AuthenticationError):
            self.bank.transfer("bad-token", "bob", 100.0)

    def test_expired_token_blocked_after_logout(self):
        self.bank.logout(self.alice_tok)
        with self.assertRaises(AuthenticationError):
            self.bank.get_balance(self.alice_tok)


# ══════════════════════════════════════════════
# Full Alice & Bob Workflow
# ══════════════════════════════════════════════

class TestAliceBobWorkflow(unittest.TestCase):
    """
    Steps:
      1. Create alice & bob (balance $0)
      2. Deposit $1000 to alice
      3. Transfer $400 alice → bob
      4. Verify final balances
      5. Verify transaction history
    """

    def setUp(self):
        self.bank = Bank()
        self.bank.register_user("alice", "alice_pass1")
        self.bank.register_user("bob",   "bob_pass123")
        self.alice_tok = self.bank.login("alice", "alice_pass1")
        self.bob_tok   = self.bank.login("bob",   "bob_pass123")

    def test_deposit_and_transfer_correct_balances(self):
        self.bank.deposit(self.alice_tok, 1000.0)
        self.bank.transfer(self.alice_tok, "bob", 400.0)
        self.assertEqual(self.bank.get_balance(self.alice_tok), 600.0)
        self.assertEqual(self.bank.get_balance(self.bob_tok),   400.0)

    def test_alice_history_has_deposit_and_withdrawal(self):
        self.bank.deposit(self.alice_tok, 1000.0)
        self.bank.transfer(self.alice_tok, "bob", 400.0)
        types = [tx["type"] for tx in
                 self.bank.get_transaction_history(self.alice_tok)]
        self.assertIn("deposit",    types)
        self.assertIn("withdrawal", types)

    def test_bob_history_has_incoming_deposit(self):
        self.bank.deposit(self.alice_tok, 1000.0)
        self.bank.transfer(self.alice_tok, "bob", 400.0)
        types = [tx["type"] for tx in
                 self.bank.get_transaction_history(self.bob_tok)]
        self.assertIn("deposit", types)

    def test_full_end_to_end(self):
        """Comprehensive single-test coverage of the entire workflow."""
        self.bank.deposit(self.alice_tok, 1000.0)
        self.bank.transfer(self.alice_tok, "bob", 400.0)

        self.assertEqual(self.bank.get_balance(self.alice_tok), 600.0)
        self.assertEqual(self.bank.get_balance(self.bob_tok),   400.0)

        alice_hist = self.bank.get_transaction_history(self.alice_tok)
        bob_hist   = self.bank.get_transaction_history(self.bob_tok)

        self.assertTrue(any(tx["amount"] == 1000.0 for tx in alice_hist))
        self.assertTrue(any(tx["amount"] ==  400.0 for tx in alice_hist))
        self.assertTrue(any(tx["amount"] ==  400.0 for tx in bob_hist))




"""
SimpliBank – System Tests
==========================
Full end-to-end user journeys that exercise the entire banking system
as a black box, simulating realistic multi-user scenarios.

Coverage:
    - Two-user registration → deposit → transfer → balance verification → logout
    - Chain transfer:  A → B → C  with full balance consistency checks

Run:
    python -m pytest system_tests.py -v
    -- or --
    python system_tests.py
"""







# ══════════════════════════════════════════════
# System Test: Two-User Journey
# ══════════════════════════════════════════════

class TestTwoUserJourney(unittest.TestCase):
    """
    Simulates a realistic journey for two bank customers:
        Alice – deposits funds and sends a transfer.
        Bob   – receives the transfer and checks his balance.
    """

    def setUp(self):
        """Initialise bank and register both users fresh for every test."""
        self.bank = Bank()

        # Registration
        self.bank.register_user("alice", "AlicePass1!")
        self.bank.register_user("bob",   "BobPass123!")

        # Login – obtain session tokens
        self.alice_tok = self.bank.login("alice", "AlicePass1!")
        self.bob_tok   = self.bank.login("bob",   "BobPass123!")

    def test_users_start_with_zero_balance(self):
        """Freshly registered users must have a $0 balance."""
        self.assertEqual(self.bank.get_balance(self.alice_tok), 0.0)
        self.assertEqual(self.bank.get_balance(self.bob_tok),   0.0)

    def test_alice_deposits_funds(self):
        """Alice deposits $2,000; her balance should reflect that."""
        self.bank.deposit(self.alice_tok, 2000.0)
        self.assertEqual(self.bank.get_balance(self.alice_tok), 2000.0)

    def test_alice_transfers_to_bob(self):
        """After depositing, Alice transfers $800 to Bob."""
        self.bank.deposit(self.alice_tok, 2000.0)
        self.bank.transfer(self.alice_tok, "bob", 800.0)

        self.assertEqual(self.bank.get_balance(self.alice_tok), 1200.0)
        self.assertEqual(self.bank.get_balance(self.bob_tok),    800.0)

    def test_total_system_money_is_conserved(self):
        """The sum of all balances must not change after any transfer."""
        self.bank.deposit(self.alice_tok, 2000.0)
        self.bank.deposit(self.bob_tok,   500.0)

        total_before = (self.bank.get_balance(self.alice_tok) +
                        self.bank.get_balance(self.bob_tok))

        self.bank.transfer(self.alice_tok, "bob", 600.0)

        total_after = (self.bank.get_balance(self.alice_tok) +
                       self.bank.get_balance(self.bob_tok))

        self.assertEqual(total_before, total_after)

    def test_alice_cannot_overdraft(self):
        """Attempting an overdraft must be blocked."""
        self.bank.deposit(self.alice_tok, 100.0)
        with self.assertRaises(InsufficientFundsError):
            self.bank.transfer(self.alice_tok, "bob", 999.0)

    def test_logout_invalidates_session(self):
        """After logout, the token must be rejected by any operation."""
        self.bank.logout(self.alice_tok)
        with self.assertRaises(AuthenticationError):
            self.bank.get_balance(self.alice_tok)

    def test_bob_can_still_operate_after_alice_logs_out(self):
        """Bob's session must remain active after Alice logs out."""
        self.bank.deposit(self.alice_tok, 500.0)
        self.bank.transfer(self.alice_tok, "bob", 200.0)
        self.bank.logout(self.alice_tok)

        # Bob's session should still work
        self.assertEqual(self.bank.get_balance(self.bob_tok), 200.0)

    def test_full_two_user_journey(self):
        """
        Complete system-level journey:
          1. Alice deposits $1,500
          2. Alice transfers $600 to Bob
          3. Verify balances: Alice=$900, Bob=$600
          4. Alice logs out – her token is rejected
          5. Bob's session remains valid
        """
        # Step 1 – deposit
        self.bank.deposit(self.alice_tok, 1500.0)

        # Step 2 – transfer
        self.bank.transfer(self.alice_tok, "bob", 600.0)

        # Step 3 – verify
        self.assertEqual(self.bank.get_balance(self.alice_tok), 900.0)
        self.assertEqual(self.bank.get_balance(self.bob_tok),   600.0)

        # Step 4 – Alice logs out
        self.bank.logout(self.alice_tok)
        with self.assertRaises(AuthenticationError):
            self.bank.get_balance(self.alice_tok)

        # Step 5 – Bob still active
        self.assertEqual(self.bank.get_balance(self.bob_tok), 600.0)


# ══════════════════════════════════════════════
# System Test: Chain Transfer  A → B → C
# ══════════════════════════════════════════════

class TestChainTransfer(unittest.TestCase):
    """
    Simulates a chain of transfers:
        Alice deposits $3,000
        Alice → Bob  : $1,000
        Bob   → Carol: $500

    Verifies that each account balance is exactly correct and that
    the total money in the system is conserved throughout.
    """

    def setUp(self):
        self.bank = Bank()

        self.bank.register_user("alice", "AlicePass1!")
        self.bank.register_user("bob",   "BobPass123!")
        self.bank.register_user("carol", "CarolPass9!")

        self.alice_tok = self.bank.login("alice", "AlicePass1!")
        self.bob_tok   = self.bank.login("bob",   "BobPass123!")
        self.carol_tok = self.bank.login("carol", "CarolPass9!")

    def test_chain_balances_after_transfers(self):
        """
        After Alice→Bob ($1000) and Bob→Carol ($500):
            Alice = $2,000  |  Bob = $500  |  Carol = $500
        """
        self.bank.deposit(self.alice_tok, 3000.0)
        self.bank.transfer(self.alice_tok, "bob",   1000.0)
        self.bank.transfer(self.bob_tok,   "carol",  500.0)

        self.assertEqual(self.bank.get_balance(self.alice_tok), 2000.0)
        self.assertEqual(self.bank.get_balance(self.bob_tok),    500.0)
        self.assertEqual(self.bank.get_balance(self.carol_tok),  500.0)

    def test_chain_total_money_conserved(self):
        """Sum of all three balances must equal the original deposit amount."""
        self.bank.deposit(self.alice_tok, 3000.0)
        total_before = 3000.0

        self.bank.transfer(self.alice_tok, "bob",   1000.0)
        self.bank.transfer(self.bob_tok,   "carol",  500.0)

        total_after = (self.bank.get_balance(self.alice_tok) +
                       self.bank.get_balance(self.bob_tok) +
                       self.bank.get_balance(self.carol_tok))

        self.assertEqual(total_before, total_after)

    def test_chain_transaction_histories_are_consistent(self):
        """Each account's history must contain only its own transactions."""
        self.bank.deposit(self.alice_tok, 3000.0)
        self.bank.transfer(self.alice_tok, "bob",   1000.0)
        self.bank.transfer(self.bob_tok,   "carol",  500.0)

        alice_hist = self.bank.get_transaction_history(self.alice_tok)
        bob_hist   = self.bank.get_transaction_history(self.bob_tok)
        carol_hist = self.bank.get_transaction_history(self.carol_tok)

        # Alice: deposit $3000 + withdrawal $1000
        alice_amounts = {tx["amount"] for tx in alice_hist}
        self.assertIn(3000.0, alice_amounts)
        self.assertIn(1000.0, alice_amounts)

        # Bob: deposit $1000 + withdrawal $500
        bob_amounts = {tx["amount"] for tx in bob_hist}
        self.assertIn(1000.0, bob_amounts)
        self.assertIn( 500.0, bob_amounts)

        # Carol: deposit $500 only
        carol_amounts = {tx["amount"] for tx in carol_hist}
        self.assertIn(500.0, carol_amounts)

    def test_chain_bob_cannot_over_transfer(self):
        """Bob can only forward what he received; overdraft must be blocked."""
        self.bank.deposit(self.alice_tok, 1000.0)
        self.bank.transfer(self.alice_tok, "bob", 200.0)

        with self.assertRaises(InsufficientFundsError):
            self.bank.transfer(self.bob_tok, "carol", 500.0)

    def test_all_users_logout_successfully(self):
        """All three users should be able to log out without errors."""
        self.bank.logout(self.alice_tok)
        self.bank.logout(self.bob_tok)
        self.bank.logout(self.carol_tok)

        for tok in (self.alice_tok, self.bob_tok, self.carol_tok):
            with self.assertRaises(AuthenticationError):
                self.bank.get_balance(tok)


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────



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



"""

SimpliBank – Performance Tests

================================

Measures throughput and latency of the banking system under load.

Benchmarks:
    1. Register 1,000 users   – total time < 5 s, prints average per-user time
    2. Perform   500 transfers – total time < 3 s, verifies zero money lost

Run:
    python performance_tests.py          (detailed console output)
    python -m pytest performance_tests.py -v -s
"""








# ──────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────

NUM_USERS            = 1_000   # Users to register in the bulk test
NUM_TRANSFERS        = 500     # Transfers to perform in the bulk test
INITIAL_DEPOSIT      = 1_000.0 # Starting balance for each performance-test user
TRANSFER_AMOUNT      = 10.0    # Amount per individual transfer
MAX_REGISTER_SECONDS = 5.0     # SLA: 1 000 registrations in < 5 s
MAX_TRANSFER_SECONDS = 3.0     # SLA: 500 transfers in < 3 s


# ──────────────────────────────────────────────
# Helper utilities
# ──────────────────────────────────────────────

def _timer(fn):
    """Execute fn() and return (result, elapsed_seconds)."""
    start  = time.perf_counter()
    result = fn()
    return result, time.perf_counter() - start


def _build_funded_bank(num_users: int, deposit: float = INITIAL_DEPOSIT):
    """
    Create a Bank, register `num_users` accounts, deposit `deposit` into
    each, and return (bank, list_of_tokens).
    """
    bank   = Bank()
    tokens = []
    for i in range(num_users):
        username = f"user_{i:05d}"
        password = f"Pass_{i:05d}!"
        bank.register_user(username, password)
        tok = bank.login(username, password)
        bank.deposit(tok, deposit)
        tokens.append(tok)
    return bank, tokens


# ══════════════════════════════════════════════
# Performance Test 1: Bulk User Registration
# ══════════════════════════════════════════════

class TestBulkRegistration(unittest.TestCase):
    """
    Register 1,000 unique users and verify the operation completes
    within the 5-second SLA.
    """

    def test_register_1000_users_within_5_seconds(self):
        """1,000 registrations must complete in under 5 seconds."""
        bank = Bank()

        def register_all():
            for i in range(NUM_USERS):
                username = f"perf_user_{i:05d}"
                password = f"PerfPass_{i:05d}!"
                bank.register_user(username, password)

        _, elapsed = _timer(register_all)

        avg_ms = (elapsed / NUM_USERS) * 1000

        print(f"\n[Registration Benchmark]")
        print(f"  Users registered : {NUM_USERS:,}")
        print(f"  Total time       : {elapsed:.4f} s")
        print(f"  Average per user : {avg_ms:.4f} ms")
        print(f"  SLA threshold    : {MAX_REGISTER_SECONDS} s")
        sla_status = "[PASS]" if elapsed < MAX_REGISTER_SECONDS else "[FAIL]"
        print(f"  SLA status       : {sla_status}")

        self.assertLess(
            elapsed, MAX_REGISTER_SECONDS,
            msg=(
                f"Registration of {NUM_USERS} users took {elapsed:.3f} s "
                f"which exceeds the {MAX_REGISTER_SECONDS} s SLA."
            ),
        )

    def test_all_registered_users_can_login(self):
        """Every registered user must be able to log in successfully."""
        bank = Bank()
        credentials = []

        for i in range(100):   # subset of 100 for login validation speed
            username = f"login_perf_{i:04d}"
            password = f"LoginPass_{i:04d}!"
            bank.register_user(username, password)
            credentials.append((username, password))

        _, elapsed = _timer(lambda: [bank.login(u, p) for u, p in credentials])

        print(f"\n[Login Benchmark]")
        print(f"  Users logged in : {len(credentials)}")
        print(f"  Total time      : {elapsed:.4f} s")

        # Soft assertion: should be very fast
        self.assertLess(elapsed, 2.0,
                        f"100 logins took {elapsed:.3f} s (expected < 2 s).")

    def test_average_registration_time_reported(self):
        """
        Registers 200 users and asserts the per-user average is < 5 ms.
        This is a sanity check that each registration is O(1) in practice.
        """
        bank    = Bank()
        sample  = 200

        def register_sample():
            for i in range(sample):
                bank.register_user(f"sample_{i:04d}", f"SamplePass{i:04d}!")

        _, elapsed = _timer(register_sample)
        avg_ms = (elapsed / sample) * 1000

        print(f"\n[Average Registration Time]")
        print(f"  Sample size      : {sample}")
        print(f"  Total time       : {elapsed:.4f} s")
        print(f"  Average per user : {avg_ms:.4f} ms")

        self.assertLess(avg_ms, 5.0,
                        f"Average registration time {avg_ms:.3f} ms exceeds 5 ms.")


# ══════════════════════════════════════════════
# Performance Test 2: Bulk Transfers
# ══════════════════════════════════════════════

class TestBulkTransfers(unittest.TestCase):
    """
    Execute 500 transfers between two accounts and verify:
        • Total wall-clock time < 3 seconds (SLA)
        • Zero money is created or destroyed (conservation law)
    """

    def setUp(self):
        """
        Pre-build a bank with two well-funded users so the transfer
        benchmark itself is not contaminated by setup time.
        """
        self.bank = Bank()

        # Sender: needs to survive 500 × TRANSFER_AMOUNT without overdraft
        sender_balance   = NUM_TRANSFERS * TRANSFER_AMOUNT + 100.0
        receiver_balance = 0.0

        self.bank.register_user("sender",   "SenderPass1!", sender_balance)
        self.bank.register_user("receiver", "RecvPass123!", receiver_balance)

        self.sender_tok   = self.bank.login("sender",   "SenderPass1!")
        self.receiver_tok = self.bank.login("receiver", "RecvPass123!")

        self.initial_total = (
            self.bank.get_balance(self.sender_tok) +
            self.bank.get_balance(self.receiver_tok)
        )

    def test_500_transfers_within_3_seconds(self):
        """500 transfers must complete in under 3 seconds."""

        def do_transfers():
            for _ in range(NUM_TRANSFERS):
                self.bank.transfer(self.sender_tok, "receiver", TRANSFER_AMOUNT)

        _, elapsed = _timer(do_transfers)

        avg_ms = (elapsed / NUM_TRANSFERS) * 1000

        print(f"\n[Transfer Benchmark]")
        print(f"  Transfers executed : {NUM_TRANSFERS:,}")
        print(f"  Transfer amount    : ${TRANSFER_AMOUNT:.2f} each")
        print(f"  Total time         : {elapsed:.4f} s")
        print(f"  Average per xfer   : {avg_ms:.4f} ms")
        print(f"  SLA threshold      : {MAX_TRANSFER_SECONDS} s")
        sla_status = "[PASS]" if elapsed < MAX_TRANSFER_SECONDS else "[FAIL]"
        print(f"  SLA status         : {sla_status}")

        self.assertLess(
            elapsed, MAX_TRANSFER_SECONDS,
            msg=(
                f"{NUM_TRANSFERS} transfers took {elapsed:.3f} s "
                f"which exceeds the {MAX_TRANSFER_SECONDS} s SLA."
            ),
        )

    def test_no_money_lost_during_bulk_transfers(self):
        """The total balance across all accounts must not change."""
        for _ in range(NUM_TRANSFERS):
            self.bank.transfer(self.sender_tok, "receiver", TRANSFER_AMOUNT)

        final_total = (
            self.bank.get_balance(self.sender_tok) +
            self.bank.get_balance(self.receiver_tok)
        )

        self.assertAlmostEqual(
            self.initial_total, final_total, places=6,
            msg=(
                f"Money was lost! Before: ${self.initial_total:.2f}, "
                f"After: ${final_total:.2f}"
            ),
        )

    def test_final_balances_are_arithmetically_correct(self):
        """Sender and receiver balances must match expected arithmetic."""
        for _ in range(NUM_TRANSFERS):
            self.bank.transfer(self.sender_tok, "receiver", TRANSFER_AMOUNT)

        moved         = NUM_TRANSFERS * TRANSFER_AMOUNT
        sender_bal    = self.bank.get_balance(self.sender_tok)
        receiver_bal  = self.bank.get_balance(self.receiver_tok)

        expected_sender   = self.initial_total - moved
        expected_receiver = moved

        self.assertAlmostEqual(sender_bal,   expected_sender,   places=6)
        self.assertAlmostEqual(receiver_bal, expected_receiver, places=6)


# ══════════════════════════════════════════════
# Performance Test 3: Mixed Workload
# ══════════════════════════════════════════════

class TestMixedWorkload(unittest.TestCase):
    """
    Simulates a realistic mixed workload:
        • 50 users register
        • Each deposits a random amount
        • Round-robin transfers between adjacent users
        • Verifies system consistency at the end
    """

    MIXED_USERS    = 50
    MIXED_DEPOSIT  = 500.0
    MIXED_TRANSFER = 20.0

    def test_mixed_workload_consistency(self):
        """
        After a round-robin transfer cycle, no money should appear or vanish.
        """
        bank   = Bank()
        tokens = []

        # Register + deposit
        for i in range(self.MIXED_USERS):
            un = f"mix_{i:03d}"
            pw = f"MixPass{i:03d}!"
            bank.register_user(un, pw, self.MIXED_DEPOSIT)
            tokens.append(bank.login(un, pw))

        total_before = self.MIXED_USERS * self.MIXED_DEPOSIT

        # Round-robin: user[i] → user[(i+1) % N]
        def run_round_robin():
            for i, tok in enumerate(tokens):
                recipient_name = f"mix_{(i + 1) % self.MIXED_USERS:03d}"
                try:
                    bank.transfer(tok, recipient_name, self.MIXED_TRANSFER)
                except InsufficientFundsError:
                    pass  # Skip if insufficient funds (edge case in round-robin)

        _, elapsed = _timer(run_round_robin)

        # Sum all balances
        total_after = sum(bank.get_balance(tok) for tok in tokens)

        print(f"\n[Mixed Workload Benchmark]")
        print(f"  Users            : {self.MIXED_USERS}")
        print(f"  Round-robin xfers: {self.MIXED_USERS}")
        print(f"  Total time       : {elapsed:.4f} s")
        print(f"  Balance before   : ${total_before:.2f}")
        print(f"  Balance after    : ${total_after:.2f}")

        self.assertAlmostEqual(
            total_before, total_after, places=4,
            msg="Money conservation violated in mixed workload test.",
        )


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

if __name__ == "__main__":
    # Run with verbose console output when executed directly
    loader = unittest.TestLoader()
    suite  = loader.loadTestsFromModule(__import__("__main__"))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)


