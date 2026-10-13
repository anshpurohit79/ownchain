"""Tests for the Account-Based Ledger (nonce-aware, replay-protecting).

Standard-library unittest only. All wallets are test-only in-memory keys and
all fixtures are deterministic.
"""

import unittest

from core.block import Block, genesis_block
from core.chain import Chain
from core.exceptions import (
    InsufficientFundsError,
    InvalidChainError,
    InvalidNonceError,
    InvalidSignatureError,
    InvalidTransactionError,
    WrongChainError,
)
from core.ledger import Ledger, LedgerState, _process_transaction
from core.signed_transaction import encode_base64url
from core.transaction import Transaction
from core.validation import MAX_NEXT_NONCE, MAX_NONCE
from core.wallet import Wallet


CHAIN_ID = "ownchain-devnet-1"
OTHER_CHAIN_ID = "ownchain-devnet-2"

# Test-only in-memory wallets. Never real keys.
ALICE = Wallet.generate()
BOB = Wallet.generate()
CHARLIE = Wallet.generate()
MALLORY = Wallet.generate()


def sign(wallet, recipient_address, amount, nonce, chain_id=CHAIN_ID):
    """Return a signed-transaction dict with an explicit nonce and chain id."""
    tx = Transaction(
        sender=wallet.address, recipient=recipient_address, amount=amount
    )
    return wallet.sign_transaction(
        tx, nonce=nonce, chain_id=chain_id
    ).to_dict()


def build_chain(blocks_txs):
    """Build a Chain from a list of per-block signed-transaction lists."""
    genesis = genesis_block()
    chain = Chain(genesis)
    prev = genesis.block_hash
    for i, txs in enumerate(blocks_txs, start=1):
        block = Block(
            index=i,
            timestamp=f"2021-01-{i + 1:02d}T00:00:00Z",
            prev_hash=prev,
            transactions=list(txs),
        )
        chain._blocks.append(block)
        prev = block.block_hash
    return chain


# Deterministic happy-path fixture.
BOOTSTRAP = {ALICE.address: 10, BOB.address: 1, CHARLIE.address: 0}
HAPPY_TXS = [
    [sign(ALICE, BOB.address, 2, nonce=0), sign(BOB, CHARLIE.address, 1, nonce=0)],
    [sign(CHARLIE, ALICE.address, 1, nonce=0)],
]


class TestLedgerStateConstruction(unittest.TestCase):
    def test_accepts_valid_mappings(self):
        state = LedgerState({ALICE.address: 5}, {ALICE.address: 2})
        self.assertEqual(state.balance(ALICE.address), 5)
        self.assertEqual(state.next_nonce(ALICE.address), 2)

    def test_omits_zero_balances_and_zero_nonces(self):
        state = LedgerState({ALICE.address: 0, BOB.address: 3}, {BOB.address: 0})
        self.assertEqual(list(state.iter_balances()), [(BOB.address, 3)])
        self.assertEqual(list(state.iter_next_nonces()), [])
        self.assertEqual(state.balance(ALICE.address), 0)
        self.assertEqual(state.next_nonce(BOB.address), 0)

    def test_accepts_max_next_nonce(self):
        state = LedgerState({}, {ALICE.address: MAX_NEXT_NONCE})
        self.assertEqual(state.next_nonce(ALICE.address), MAX_NEXT_NONCE)

    def test_rejects_non_mapping(self):
        with self.assertRaises(TypeError):
            LedgerState([ALICE.address], {})
        with self.assertRaises(TypeError):
            LedgerState({}, [ALICE.address])

    def test_rejects_invalid_address_keys(self):
        with self.assertRaises(ValueError):
            LedgerState({"alice": 1}, {})
        with self.assertRaises(ValueError):
            LedgerState({}, {"alice": 1})

    def test_rejects_non_int_balances(self):
        for bad in (True, 1.0, 1.5, "1", None):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    LedgerState({ALICE.address: bad}, {})

    def test_rejects_negative_balance(self):
        with self.assertRaises(ValueError):
            LedgerState({ALICE.address: -1}, {})

    def test_rejects_out_of_range_next_nonce(self):
        with self.assertRaises(ValueError):
            LedgerState({}, {ALICE.address: MAX_NEXT_NONCE + 1})
        with self.assertRaises(ValueError):
            LedgerState({}, {ALICE.address: -1})

    def test_rejects_non_int_next_nonce(self):
        with self.assertRaises(TypeError):
            LedgerState({}, {ALICE.address: True})

    def test_defensive_copy_of_inputs(self):
        balances = {ALICE.address: 5}
        nonces = {ALICE.address: 1}
        state = LedgerState(balances, nonces)
        balances[ALICE.address] = 999
        nonces[ALICE.address] = 999
        self.assertEqual(state.balance(ALICE.address), 5)
        self.assertEqual(state.next_nonce(ALICE.address), 1)

    def test_is_deliberately_unhashable(self):
        state = LedgerState({ALICE.address: 1}, {})
        self.assertIsNone(LedgerState.__hash__)
        with self.assertRaises(TypeError):
            hash(state)


class TestLedgerStateAPI(unittest.TestCase):
    def setUp(self):
        self.state = LedgerState(
            {ALICE.address: 9, BOB.address: 2}, {ALICE.address: 1, BOB.address: 3}
        )

    def test_absent_address_returns_zero(self):
        self.assertEqual(self.state.balance(CHARLIE.address), 0)
        self.assertEqual(self.state.next_nonce(CHARLIE.address), 0)

    def test_invalid_lookup_raises_value_error(self):
        for bad in ("alice", "A" * 40, "a" * 39, 123, None):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self.state.balance(bad)
                with self.assertRaises(ValueError):
                    self.state.next_nonce(bad)

    def test_iterators_are_sorted(self):
        self.assertEqual(
            list(self.state.iter_balances()),
            sorted([(ALICE.address, 9), (BOB.address, 2)]),
        )
        self.assertEqual(
            list(self.state.iter_next_nonces()),
            sorted([(ALICE.address, 1), (BOB.address, 3)]),
        )

    def test_no_mutable_dict_exposed(self):
        # There is no public attribute returning the internal dict.
        for name in ("balances", "next_nonces"):
            self.assertFalse(hasattr(self.state, name))

    def test_equality_by_canonical_mappings(self):
        same = LedgerState(
            {BOB.address: 2, ALICE.address: 9}, {BOB.address: 3, ALICE.address: 1}
        )
        self.assertEqual(self.state, same)
        diff = LedgerState({ALICE.address: 9}, {ALICE.address: 1})
        self.assertNotEqual(self.state, diff)

    def test_equality_returns_notimplemented_for_other_types(self):
        self.assertIs(self.state.__eq__({}), NotImplemented)
        self.assertIs(self.state.__eq__("x"), NotImplemented)
        self.assertNotEqual(self.state, "x")


if __name__ == "__main__":
    unittest.main()


class TestLedgerConstruction(unittest.TestCase):
    def test_accepts_valid_configuration(self):
        ledger = Ledger({ALICE.address: 10, BOB.address: 0}, CHAIN_ID)
        self.assertEqual(ledger.chain_id, CHAIN_ID)

    def test_omits_zero_bootstrap_balances(self):
        ledger = Ledger({ALICE.address: 0}, CHAIN_ID)
        self.assertEqual(dict(ledger._initial_balances), {})

    def test_does_not_strip_or_normalize_addresses(self):
        # A padded-but-invalid address must be rejected, not silently fixed.
        with self.assertRaises(ValueError):
            Ledger({ALICE.address + " ": 10}, CHAIN_ID)

    def test_rejects_invalid_bootstrap_address(self):
        with self.assertRaises((TypeError, ValueError)):
            Ledger({"not-an-address": 10}, CHAIN_ID)

    def test_rejects_non_int_balance(self):
        with self.assertRaises((TypeError, ValueError)):
            Ledger({ALICE.address: 1.5}, CHAIN_ID)
        with self.assertRaises((TypeError, ValueError)):
            Ledger({ALICE.address: True}, CHAIN_ID)

    def test_rejects_negative_balance(self):
        with self.assertRaises((TypeError, ValueError)):
            Ledger({ALICE.address: -1}, CHAIN_ID)

    def test_rejects_invalid_chain_id(self):
        with self.assertRaises(ValueError):
            Ledger({ALICE.address: 10}, "Bad Chain")
        with self.assertRaises(ValueError):
            Ledger({ALICE.address: 10}, "")

    def test_copies_bootstrap_input(self):
        source = {ALICE.address: 10}
        ledger = Ledger(source, CHAIN_ID)
        source[ALICE.address] = 999
        self.assertEqual(dict(ledger._initial_balances), {ALICE.address: 10})

    def test_initial_configuration_unchanged_after_replay(self):
        ledger = Ledger(BOOTSTRAP, CHAIN_ID)
        snapshot = dict(ledger._initial_balances)
        ledger.replay(build_chain(HAPPY_TXS))
        self.assertEqual(dict(ledger._initial_balances), snapshot)


class TestReplayHappyPath(unittest.TestCase):
    def setUp(self):
        self.ledger = Ledger(BOOTSTRAP, CHAIN_ID)
        self.chain = build_chain(HAPPY_TXS)

    def test_replay_returns_ledger_state(self):
        state = self.ledger.replay(self.chain)
        self.assertIsInstance(state, LedgerState)

    def test_final_balances(self):
        state = self.ledger.replay(self.chain)
        # BOOTSTRAP: ALICE=10, BOB=1, CHARLIE=0
        # ALICE->BOB 2 (ALICE 8, BOB 3); BOB->CHARLIE 1 (BOB 2, CHARLIE 1);
        # CHARLIE->ALICE 1 (CHARLIE 0 -> omitted, ALICE 9)
        self.assertEqual(state.balance(ALICE.address), 9)
        self.assertEqual(state.balance(BOB.address), 2)
        self.assertEqual(state.balance(CHARLIE.address), 0)

    def test_final_next_nonces(self):
        state = self.ledger.replay(self.chain)
        self.assertEqual(state.next_nonce(ALICE.address), 1)
        self.assertEqual(state.next_nonce(BOB.address), 1)
        self.assertEqual(state.next_nonce(CHARLIE.address), 1)

    def test_sequential_nonces_zero_one_two(self):
        txs = [
            [
                sign(ALICE, BOB.address, 1, nonce=0),
                sign(ALICE, BOB.address, 1, nonce=1),
                sign(ALICE, BOB.address, 1, nonce=2),
            ]
        ]
        state = Ledger({ALICE.address: 10}, CHAIN_ID).replay(build_chain(txs))
        self.assertEqual(state.next_nonce(ALICE.address), 3)
        self.assertEqual(state.balance(BOB.address), 3)

    def test_independent_nonce_sequences_two_senders(self):
        txs = [
            [sign(ALICE, BOB.address, 1, nonce=0), sign(BOB, ALICE.address, 1, nonce=0)],
            [sign(ALICE, BOB.address, 1, nonce=1)],
        ]
        state = Ledger({ALICE.address: 10, BOB.address: 10}, CHAIN_ID).replay(
            build_chain(txs)
        )
        self.assertEqual(state.next_nonce(ALICE.address), 2)
        self.assertEqual(state.next_nonce(BOB.address), 1)

    def test_spend_funds_received_earlier_in_same_replay(self):
        # ALICE sends to BOB, then BOB spends what he just received.
        txs = [
            [sign(ALICE, BOB.address, 5, nonce=0), sign(BOB, CHARLIE.address, 5, nonce=0)],
        ]
        state = Ledger({ALICE.address: 10}, CHAIN_ID).replay(build_chain(txs))
        self.assertEqual(state.balance(CHARLIE.address), 5)
        self.assertEqual(state.balance(BOB.address), 0)

    def test_nonce_continuity_across_block_boundaries(self):
        txs = [
            [sign(ALICE, BOB.address, 1, nonce=0)],
            [sign(ALICE, BOB.address, 1, nonce=1)],
        ]
        state = Ledger({ALICE.address: 10}, CHAIN_ID).replay(build_chain(txs))
        self.assertEqual(state.next_nonce(ALICE.address), 2)

    def test_replay_twice_same_instance_equal_states(self):
        s1 = self.ledger.replay(self.chain)
        s2 = self.ledger.replay(self.chain)
        self.assertEqual(s1, s2)


class TestNonceEnforcement(unittest.TestCase):
    def _replay(self, txs):
        ledger = Ledger({ALICE.address: 100}, CHAIN_ID)
        return ledger.replay(build_chain(txs))

    def test_duplicate_nonce_rejected(self):
        tx = sign(ALICE, BOB.address, 1, nonce=0)
        with self.assertRaises(InvalidNonceError):
            self._replay([[tx, dict(tx)]])

    def test_skipped_nonce_rejected(self):
        with self.assertRaises(InvalidNonceError):
            self._replay([[sign(ALICE, BOB.address, 1, nonce=1)]])

    def test_out_of_order_nonce_rejected(self):
        with self.assertRaises(InvalidNonceError):
            self._replay(
                [
                    [sign(ALICE, BOB.address, 1, nonce=1), sign(ALICE, BOB.address, 1, nonce=0)],
                ]
            )

    def test_stale_nonce_after_receiving_refund_rejected(self):
        # ALICE spends everything (nonce 0), receives a refund, then replays her
        # old nonce-0 transaction. The replayed nonce must be rejected.
        spend_all = sign(ALICE, BOB.address, 10, nonce=0)
        refund = sign(BOB, ALICE.address, 10, nonce=0)
        txs = [[spend_all, refund, dict(spend_all)]]
        with self.assertRaises(InvalidNonceError):
            self._replay(txs)

    def test_accepting_max_nonce_advances_to_max_next_nonce(self):
        # A nonce of MAX_NONCE is signable; reaching it via full replay would
        # require 2**64-1 prior transactions, so drive the shared processing
        # rule directly with the sender's working next-nonce already at
        # MAX_NONCE (as if every earlier nonce had been consumed).
        record = sign(ALICE, BOB.address, 1, nonce=MAX_NONCE)
        balances = {ALICE.address: 100}
        next_nonces = {ALICE.address: MAX_NONCE}
        _process_transaction(record, balances, next_nonces, CHAIN_ID)
        self.assertEqual(next_nonces[ALICE.address], MAX_NEXT_NONCE)

    def test_no_subsequent_transaction_valid_after_max_next_nonce(self):
        # Once the next expected nonce is MAX_NEXT_NONCE, the only nonce that
        # could be accepted is MAX_NEXT_NONCE itself -- but the wallet refuses
        # to sign a nonce above MAX_NONCE, so no valid subsequent transaction
        # can be produced. Assert both halves of that guarantee.
        with self.assertRaises(InvalidTransactionError):
            sign(ALICE, BOB.address, 1, nonce=MAX_NEXT_NONCE)
        # And any record whose nonce is below the expected MAX_NEXT_NONCE is
        # rejected as an out-of-order/stale nonce.
        record = sign(ALICE, BOB.address, 1, nonce=MAX_NONCE)
        balances = {ALICE.address: 100}
        next_nonces = {ALICE.address: MAX_NEXT_NONCE}
        with self.assertRaises(InvalidNonceError):
            _process_transaction(record, balances, next_nonces, CHAIN_ID)



class TestChainIdEnforcement(unittest.TestCase):
    def test_valid_transaction_for_another_chain_rejected(self):
        tx = sign(ALICE, BOB.address, 1, nonce=0, chain_id=OTHER_CHAIN_ID)
        with self.assertRaises(WrongChainError):
            Ledger({ALICE.address: 100}, CHAIN_ID).replay(build_chain([[tx]]))

    def test_ledger_configured_for_other_chain_accepts_its_txs(self):
        tx = sign(ALICE, BOB.address, 1, nonce=0, chain_id=OTHER_CHAIN_ID)
        state = Ledger({ALICE.address: 100}, OTHER_CHAIN_ID).replay(
            build_chain([[tx]])
        )
        self.assertEqual(state.balance(BOB.address), 1)

    def test_nonce_alteration_without_resigning_fails_signature(self):
        # Changing the nonce changes the signed payload; the stored signature
        # no longer matches, so this is a signature failure, not a nonce error.
        tx = sign(ALICE, BOB.address, 1, nonce=0)
        tampered = dict(tx)
        tampered["nonce"] = 1
        with self.assertRaises(InvalidSignatureError):
            Ledger({ALICE.address: 100}, CHAIN_ID).replay(build_chain([[tampered]]))

    def test_chain_id_alteration_without_resigning_fails_signature(self):
        tx = sign(ALICE, BOB.address, 1, nonce=0)
        tampered = dict(tx)
        tampered["chain_id"] = OTHER_CHAIN_ID
        with self.assertRaises(InvalidSignatureError):
            Ledger({ALICE.address: 100}, CHAIN_ID).replay(build_chain([[tampered]]))


class TestReplayAtomicityAndInvariants(unittest.TestCase):
    """All-or-nothing replay, supply conservation, nonce accounting, and the
    shared ``_process_transaction`` rule leaving its working mappings untouched
    on every failure type."""

    # ---- _process_transaction: no mutation on any failure type ----------
    def _assert_unchanged(self, record, balances, next_nonces, chain_id, exc):
        b_copy = dict(balances)
        n_copy = dict(next_nonces)
        with self.assertRaises(exc):
            _process_transaction(record, balances, next_nonces, chain_id)
        self.assertEqual(balances, b_copy)
        self.assertEqual(next_nonces, n_copy)

    def test_malformed_record_leaves_mappings_unchanged(self):
        self._assert_unchanged(
            {"sender": ALICE.address}, {ALICE.address: 100}, {}, CHAIN_ID,
            InvalidTransactionError,
        )

    def test_invalid_signature_leaves_mappings_unchanged(self):
        record = sign(ALICE, BOB.address, 5, nonce=0)
        tampered = dict(record)
        tampered["amount"] = 999  # signed payload no longer matches
        self._assert_unchanged(
            tampered, {ALICE.address: 100}, {}, CHAIN_ID,
            InvalidSignatureError,
        )

    def test_wrong_chain_leaves_mappings_unchanged(self):
        record = sign(ALICE, BOB.address, 5, nonce=0, chain_id=OTHER_CHAIN_ID)
        self._assert_unchanged(
            record, {ALICE.address: 100}, {}, CHAIN_ID, WrongChainError,
        )

    def test_bad_nonce_leaves_mappings_unchanged(self):
        record = sign(ALICE, BOB.address, 5, nonce=0)
        self._assert_unchanged(
            record, {ALICE.address: 100}, {ALICE.address: 5}, CHAIN_ID,
            InvalidNonceError,
        )

    def test_insufficient_funds_leaves_mappings_unchanged(self):
        record = sign(ALICE, BOB.address, 500, nonce=0)
        self._assert_unchanged(
            record, {ALICE.address: 100}, {}, CHAIN_ID,
            InsufficientFundsError,
        )

    def test_success_mutates_mappings(self):
        record = sign(ALICE, BOB.address, 5, nonce=0)
        balances = {ALICE.address: 100}
        next_nonces = {}
        _process_transaction(record, balances, next_nonces, CHAIN_ID)
        self.assertEqual(balances[ALICE.address], 95)
        self.assertEqual(balances[BOB.address], 5)
        self.assertEqual(next_nonces[ALICE.address], 1)

    # ---- Invalid chain refused -----------------------------------------
    def test_invalid_chain_raises(self):
        ledger = Ledger(BOOTSTRAP, CHAIN_ID)
        chain = build_chain(HAPPY_TXS)
        # Break a hash link so Chain.validate() returns False.
        chain._blocks[2].prev_hash = "0" * 64
        with self.assertRaises(InvalidChainError):
            ledger.replay(chain)

    # ---- Failed replay leaves no partial state -------------------------
    def test_failed_replay_does_not_contaminate_later_replay(self):
        ledger = Ledger(BOOTSTRAP, CHAIN_ID)
        pristine = ledger.replay(build_chain(HAPPY_TXS))
        bad = build_chain([[sign(ALICE, BOB.address, 1, nonce=7)]])
        with self.assertRaises(InvalidNonceError):
            ledger.replay(bad)
        # A subsequent successful replay must be identical to the pristine one.
        after = ledger.replay(build_chain(HAPPY_TXS))
        self.assertEqual(list(pristine.iter_balances()), list(after.iter_balances()))
        self.assertEqual(
            list(pristine.iter_next_nonces()), list(after.iter_next_nonces())
        )

    # ---- Supply conservation -------------------------------------------
    def test_supply_is_conserved(self):
        ledger = Ledger(BOOTSTRAP, CHAIN_ID)
        state = ledger.replay(build_chain(HAPPY_TXS))
        initial_total = sum(v for _, v in BOOTSTRAP.items() if v)
        final_total = sum(v for _, v in state.iter_balances())
        self.assertEqual(final_total, initial_total)

    # ---- Final next nonce equals accepted-transaction count ------------
    def test_final_next_nonce_equals_accepted_count(self):
        ledger = Ledger(BOOTSTRAP, CHAIN_ID)
        state = ledger.replay(build_chain(HAPPY_TXS))
        counts = {}
        for block_txs in HAPPY_TXS:
            for rec in block_txs:
                counts[rec["sender"]] = counts.get(rec["sender"], 0) + 1
        for sender, count in counts.items():
            self.assertEqual(state.next_nonce(sender), count)

    # ---- Self-transfer of the entire balance ---------------------------
    def test_self_transfer_entire_balance_advances_nonce_only(self):
        ledger = Ledger({ALICE.address: 100}, CHAIN_ID)
        chain = build_chain([[sign(ALICE, ALICE.address, 100, nonce=0)]])
        state = ledger.replay(chain)
        self.assertEqual(state.balance(ALICE.address), 100)
        self.assertEqual(state.next_nonce(ALICE.address), 1)

    # ---- Previously returned state is not mutated by later replays -----
    def test_previously_returned_state_unchanged_after_later_replay(self):
        ledger = Ledger(BOOTSTRAP, CHAIN_ID)
        state1 = ledger.replay(build_chain(HAPPY_TXS))
        snapshot_balances = list(state1.iter_balances())
        snapshot_nonces = list(state1.iter_next_nonces())
        # Replay a different chain on the same instance.
        other = build_chain([[sign(ALICE, CHARLIE.address, 3, nonce=0)]])
        ledger.replay(other)
        self.assertEqual(list(state1.iter_balances()), snapshot_balances)
        self.assertEqual(list(state1.iter_next_nonces()), snapshot_nonces)
