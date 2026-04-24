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

import unittest

from banking_system import (
    Bank,
    AuthenticationError,
    InsufficientFundsError,
    InvalidInputError,
)


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

if __name__ == "__main__":
    unittest.main(verbosity=2)
