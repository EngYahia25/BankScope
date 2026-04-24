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

import time
import unittest

from backend.services import Bank
from backend.models import (
    InsufficientFundsError,
    InvalidInputError,
)


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
