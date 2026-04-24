"""
BankScope - Models
==================
Core domain classes and custom exceptions for the banking system.
"""

from datetime import datetime

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
