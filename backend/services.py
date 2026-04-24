"""
BankScope - Services
====================
The Bank facade that orchestrates Auth and Account operations.
"""

from .models import Account, AuthenticationError, InvalidInputError
from .auth import UserAuth

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
