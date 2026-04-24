"""
SimpliBank – Integration Tests
================================
Verifies interactions between Account, UserAuth, and Bank as a system.

Run:
    python -m pytest integration_tests.py -v
    -- or --
    python integration_tests.py
"""

import unittest

from banking_system import (
    Bank,
    AuthenticationError,
    InsufficientFundsError,
    InvalidInputError,
)


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
