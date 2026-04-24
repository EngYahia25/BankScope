"""
SimpliBank Online Banking System
=================================
Core module containing the banking system's domain classes and custom exceptions.

Classes:
    - InvalidInputError     : Raised on bad/invalid input
    - InsufficientFundsError: Raised when withdrawal exceeds balance
    - AuthenticationError   : Raised on auth / token failures
    - Account               : Manages deposits, withdrawals, and history
    - UserAuth              : Handles registration, login, sessions, brute-force lock
    - Bank                  : Facade combining Account + UserAuth
"""

import hashlib
import os
import secrets
import time
from datetime import datetime


# ──────────────────────────────────────────────
# Custom Exceptions
# ──────────────────────────────────────────────

class InvalidInputError(Exception):
    """Raised when a method receives an invalid / unexpected argument."""


class InsufficientFundsError(Exception):
    """Raised when a withdrawal amount exceeds the current account balance."""


class AuthenticationError(Exception):
    """Raised when a token is invalid, expired, or the account is locked."""


# ──────────────────────────────────────────────
# Account Class
# ──────────────────────────────────────────────

class Account:
    """
    Represents a single bank account.

    Attributes:
        owner   (str)  : Account owner's username.
        _balance(float): Current account balance (private).
        _history(list) : Ordered list of transaction records.
    """

    def __init__(self, owner: str, initial_balance: float = 0.0):
        """
        Initialise an Account.

        Args:
            owner          : Username of the account holder.
            initial_balance: Starting balance (must be >= 0).

        Raises:
            InvalidInputError: If initial_balance is negative.
        """
        if initial_balance < 0:
            raise InvalidInputError(
                f"Initial balance cannot be negative. Got: {initial_balance}"
            )
        self.owner = owner
        self._balance = float(initial_balance)
        self._history: list[dict] = []

        if initial_balance > 0:
            self._record("initial deposit", initial_balance, self._balance)

    # ── Private helpers ─────────────────────────

    def _record(self, tx_type: str, amount: float, balance_after: float) -> None:
        """Append a transaction record to the history list."""
        self._history.append({
            "type"         : tx_type,
            "amount"       : amount,
            "balance_after": balance_after,
            "timestamp"    : datetime.utcnow().isoformat(),
        })

    # ── Public API ──────────────────────────────

    def deposit(self, amount: float) -> float:
        """
        Deposit money into the account.

        Args:
            amount: Positive amount to deposit.

        Returns:
            New balance after the deposit.

        Raises:
            InvalidInputError: If amount <= 0.
        """
        if amount <= 0:
            raise InvalidInputError(
                f"Deposit amount must be positive. Got: {amount}"
            )
        self._balance += amount
        self._record("deposit", amount, self._balance)
        return self._balance

    def withdraw(self, amount: float) -> float:
        """
        Withdraw money from the account.

        Args:
            amount: Positive amount to withdraw.

        Returns:
            New balance after the withdrawal.

        Raises:
            InvalidInputError     : If amount <= 0.
            InsufficientFundsError: If amount > current balance.
        """
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
        """Return the current account balance."""
        return self._balance

    def get_history(self) -> list[dict]:
        """Return a copy of the transaction history list."""
        return list(self._history)


# ──────────────────────────────────────────────
# UserAuth Class
# ──────────────────────────────────────────────

MAX_FAILED_ATTEMPTS = 5   # Lock account after this many consecutive failures

class UserAuth:
    """
    Handles user registration, login, logout, and session management.

    Features:
        - Password hashing with SHA-256 + per-user salt (never stored in plaintext)
        - Cryptographically random session tokens
        - Brute-force protection: account locked after MAX_FAILED_ATTEMPTS failures
    """

    def __init__(self):
        # {username: {"hash": str, "salt": str, "locked": bool, "failed": int}}
        self._users: dict[str, dict] = {}
        # {token: username} – active sessions
        self._sessions: dict[str, str] = {}

    # ── Private helpers ─────────────────────────

    @staticmethod
    def _hash_password(password: str, salt: str) -> str:
        """Return a hex SHA-256 digest of (salt + password)."""
        return hashlib.sha256((salt + password).encode()).hexdigest()

    @staticmethod
    def _generate_salt() -> str:
        """Return a 16-byte cryptographically random hex salt."""
        return secrets.token_hex(16)

    @staticmethod
    def _generate_token() -> str:
        """Return a cryptographically random 32-byte hex session token."""
        return secrets.token_hex(32)

    # ── Public API ──────────────────────────────

    def register(self, username: str, password: str) -> None:
        """
        Register a new user.

        Args:
            username: Unique username string.
            password: Password (minimum 8 characters).

        Raises:
            InvalidInputError: If username already exists or password is too short.
        """
        if username in self._users:
            raise InvalidInputError(
                f"Username '{username}' is already taken."
            )
        if len(password) < 8:
            raise InvalidInputError(
                "Password must be at least 8 characters long."
            )

        salt = self._generate_salt()
        pwd_hash = self._hash_password(password, salt)

        self._users[username] = {
            "hash"  : pwd_hash,
            "salt"  : salt,
            "locked": False,
            "failed": 0,
        }

    def login(self, username: str, password: str) -> str:
        """
        Authenticate a user and return a session token.

        Args:
            username: Registered username.
            password: Plaintext password.

        Returns:
            A session token string.

        Raises:
            AuthenticationError: If credentials are wrong or the account is locked.
            InvalidInputError  : If the username does not exist.
        """
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
                    f"Account '{username}' is now locked after {MAX_FAILED_ATTEMPTS} "
                    "failed login attempts."
                )
            raise AuthenticationError(
                f"Incorrect password for '{username}'. "
                f"Attempts remaining: {MAX_FAILED_ATTEMPTS - user['failed']}"
            )

        # Successful login — reset failure counter and issue token
        user["failed"] = 0
        token = self._generate_token()
        self._sessions[token] = username
        return token

    def logout(self, token: str) -> None:
        """
        Invalidate a session token.

        Args:
            token: Active session token.

        Raises:
            AuthenticationError: If the token is not found / already invalid.
        """
        if token not in self._sessions:
            raise AuthenticationError("Invalid or already-expired session token.")
        del self._sessions[token]

    def is_authenticated(self, token: str) -> bool:
        """
        Check whether a session token is currently active.

        Args:
            token: Session token to validate.

        Returns:
            True if the token is valid, False otherwise.
        """
        return token in self._sessions

    def get_username(self, token: str) -> str:
        """
        Resolve a token back to a username.

        Args:
            token: Active session token.

        Returns:
            The username associated with the token.

        Raises:
            AuthenticationError: If the token is invalid.
        """
        if token not in self._sessions:
            raise AuthenticationError("Invalid or expired session token.")
        return self._sessions[token]

    def get_user_record(self, username: str) -> dict:
        """Return the internal record for a username (used by tests)."""
        if username not in self._users:
            raise InvalidInputError(f"User '{username}' not found.")
        return self._users[username]


# ──────────────────────────────────────────────
# Bank Class  (Facade)
# ──────────────────────────────────────────────

class Bank:
    """
    High-level banking facade that combines UserAuth and Account management.

    Each registered user automatically gets one Account associated with them.
    All mutating operations require a valid session token.
    """

    def __init__(self):
        self._auth     = UserAuth()
        # {username: Account}
        self._accounts : dict[str, Account] = {}

    # ── User management ─────────────────────────

    def register_user(self, username: str, password: str,
                      initial_balance: float = 0.0) -> None:
        """
        Register a new user and create their bank account.

        Args:
            username       : Unique username.
            password       : Password (>= 8 chars).
            initial_balance: Starting balance (default 0).

        Raises:
            InvalidInputError: Propagated from UserAuth or Account.
        """
        self._auth.register(username, password)
        self._accounts[username] = Account(username, initial_balance)

    def login(self, username: str, password: str) -> str:
        """
        Authenticate a user.

        Returns:
            Session token.

        Raises:
            AuthenticationError / InvalidInputError: Propagated from UserAuth.
        """
        return self._auth.login(username, password)

    def logout(self, token: str) -> None:
        """Invalidate the given session token."""
        self._auth.logout(token)

    # ── Account operations ───────────────────────

    def _require_auth(self, token: str) -> str:
        """
        Validate token and return the associated username.

        Raises:
            AuthenticationError: If token is invalid.
        """
        if not self._auth.is_authenticated(token):
            raise AuthenticationError("Access denied: invalid or expired token.")
        return self._auth.get_username(token)

    def get_balance(self, token: str) -> float:
        """
        Get the balance for the authenticated user.

        Args:
            token: Valid session token.

        Returns:
            Current balance.

        Raises:
            AuthenticationError: If token is invalid.
        """
        username = self._require_auth(token)
        return self._accounts[username].get_balance()

    def deposit(self, token: str, amount: float) -> float:
        """Deposit money for the authenticated user."""
        username = self._require_auth(token)
        return self._accounts[username].deposit(amount)

    def transfer(self, from_token: str, to_username: str, amount: float) -> None:
        """
        Transfer funds from the authenticated user to another user.

        Args:
            from_token : Session token of the sender.
            to_username: Username of the recipient.
            amount     : Positive amount to transfer.

        Raises:
            AuthenticationError  : If from_token is invalid.
            InvalidInputError    : If to_username doesn't exist.
            InsufficientFundsError: If sender has insufficient funds.
        """
        from_username = self._require_auth(from_token)

        if to_username not in self._accounts:
            raise InvalidInputError(f"Recipient '{to_username}' does not exist.")

        # Atomic-style: withdraw first, then deposit
        self._accounts[from_username].withdraw(amount)
        self._accounts[to_username].deposit(amount)

    def get_transaction_history(self, token: str) -> list[dict]:
        """Return the transaction history for the authenticated user."""
        username = self._require_auth(token)
        return self._accounts[username].get_history()


    def get_account(self, username: str) -> Account:
        """Direct account lookup (used internally and by tests)."""
        if username not in self._accounts:
            raise InvalidInputError(f"Account for '{username}' not found.")
        return self._accounts[username]


    @property
    def auth(self) -> UserAuth:
        """Expose the internal UserAuth instance (used by security tests)."""
        return self._auth
