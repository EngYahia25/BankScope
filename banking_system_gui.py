import hashlib
import secrets
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

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


"""
BankScope - Auth
================
Handles user registration, login, session management, and security.
"""

import hashlib
import secrets


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



class BankingGUI:
    def __init__(self, root):
        self.bank = Bank()
        self.root = root
        self.root.title("SimpliBank")
        self.root.geometry("600x500")
        self.root.configure(bg="#f4f6f9")
        self.current_token = None
        self.current_username = None

        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TButton', font=('Helvetica', 10, 'bold'), foreground='white', background='#0056b3', padding=5)
        self.style.map('TButton', background=[('active', '#004494')])
        
        self.show_login_frame()

    def clear_frame(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_login_frame(self):
        self.clear_frame()
        self.current_token = None
        self.current_username = None

        frame = tk.Frame(self.root, bg="#f4f6f9")
        frame.pack(expand=True)

        tk.Label(frame, text="Welcome to SimpliBank", font=("Helvetica", 18, "bold"), bg="#f4f6f9", fg="#333").pack(pady=20)

        tk.Label(frame, text="Username:", font=("Helvetica", 12), bg="#f4f6f9").pack()
        self.username_entry = ttk.Entry(frame, font=("Helvetica", 12))
        self.username_entry.pack(pady=5)

        tk.Label(frame, text="Password:", font=("Helvetica", 12), bg="#f4f6f9").pack()
        self.password_entry = ttk.Entry(frame, show="*", font=("Helvetica", 12))
        self.password_entry.pack(pady=5)

        btn_frame = tk.Frame(frame, bg="#f4f6f9")
        btn_frame.pack(pady=20)

        ttk.Button(btn_frame, text="Login", command=self.login).grid(row=0, column=0, padx=10)
        ttk.Button(btn_frame, text="Register", command=self.register).grid(row=0, column=1, padx=10)

    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Username and Password cannot be empty.")
            return

        try:
            self.current_token = self.bank.login(username, password)
            self.current_username = username
            self.show_dashboard()
        except Exception as e:
            messagebox.showerror("Login Failed", str(e))

    def register(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Username and Password cannot be empty.")
            return

        try:
            self.bank.register_user(username, password, 0.0)
            messagebox.showinfo("Success", "Registration successful. You can now login.")
        except Exception as e:
            messagebox.showerror("Registration Failed", str(e))

    def show_dashboard(self):
        self.clear_frame()

        frame = tk.Frame(self.root, bg="#f4f6f9")
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        header = tk.Frame(frame, bg="#f4f6f9")
        header.pack(fill=tk.X, pady=10)
        
        tk.Label(header, text=f"Dashboard: {self.current_username}", font=("Helvetica", 16, "bold"), bg="#f4f6f9").pack(side=tk.LEFT)
        ttk.Button(header, text="Logout", command=self.show_login_frame).pack(side=tk.RIGHT)

        self.balance_label = tk.Label(frame, text="Balance: $0.00", font=("Helvetica", 14), bg="#f4f6f9", fg="#28a745")
        self.balance_label.pack(pady=10)
        self.update_balance()

        btn_frame = tk.Frame(frame, bg="#f4f6f9")
        btn_frame.pack(pady=20)

        ttk.Button(btn_frame, text="Deposit", command=self.deposit).grid(row=0, column=0, padx=10, pady=10)
        ttk.Button(btn_frame, text="Withdraw", command=self.withdraw).grid(row=0, column=1, padx=10, pady=10)
        ttk.Button(btn_frame, text="Transfer", command=self.transfer).grid(row=1, column=0, padx=10, pady=10)
        ttk.Button(btn_frame, text="History", command=self.history).grid(row=1, column=1, padx=10, pady=10)

    def update_balance(self):
        try:
            bal = self.bank.get_balance(self.current_token)
            self.balance_label.config(text=f"Balance: ${bal:.2f}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def deposit(self):
        amount = simpledialog.askfloat("Deposit", "Enter amount to deposit:")
        if amount is not None:
            try:
                self.bank.deposit(self.current_token, amount)
                self.update_balance()
                messagebox.showinfo("Success", f"${amount:.2f} deposited successfully.")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def withdraw(self):
        amount = simpledialog.askfloat("Withdraw", "Enter amount to withdraw:")
        if amount is not None:
            try:
                self.bank.withdraw(self.current_token, amount)
                self.update_balance()
                messagebox.showinfo("Success", f"${amount:.2f} withdrawn successfully.")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def transfer(self):
        to_user = simpledialog.askstring("Transfer", "Enter recipient username:")
        if to_user:
            amount = simpledialog.askfloat("Transfer", f"Enter amount to transfer to {to_user}:")
            if amount is not None:
                try:
                    self.bank.transfer(self.current_token, to_user, amount)
                    self.update_balance()
                    messagebox.showinfo("Success", f"${amount:.2f} transferred to {to_user} successfully.")
                except Exception as e:
                    messagebox.showerror("Error", str(e))

    def history(self):
        try:
            hist = self.bank.get_transaction_history(self.current_token)
            hist_str = "\n".join([f"{tx['type'].capitalize()}: ${tx['amount']:.2f} -> Bal: ${tx['balance_after']:.2f}" for tx in hist])
            if not hist_str:
                hist_str = "No transactions found."
            messagebox.showinfo("Transaction History", hist_str)
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = BankingGUI(root)
    root.mainloop()
