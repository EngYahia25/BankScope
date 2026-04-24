"""
BankScope - Auth
================
Handles user registration, login, session management, and security.
"""

import hashlib
import secrets
from .models import AuthenticationError, InvalidInputError

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
