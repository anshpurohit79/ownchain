"""Tests for the Account-Based Ledger (signed-transaction era). Stdlib unittest only."""

import unittest

from core.block import Block, genesis_block
from core.chain import Chain
from core.exceptions import (
    InsufficientFundsError,
    InvalidChainError,
    InvalidSignatureError,
    InvalidTransactionError,
)
from core.ledger import Ledger
from core.transaction import Transaction
from core.wallet import Wallet


# Test-only in-memory wallets. Never real keys.
ALICE = Wallet.generate()
BOB = Wallet.generate()
CHARLIE = Wallet.generate()
MALLORY = Wallet.generate()


def sign(wallet, recipient_address, amount):
    """Produce a signed transaction dict ready for Block.transactions."""
    tx = Transaction(sender=wallet.address, recipient=recipient_address,
                     amount=amount)
    return wallet.sign_transaction(tx).to_dict()


def make_chain():
    """Valid chain: genesis + two blocks of signed transfers."""
    genesis = genesis_block()
    b1 = Block(
        index=1,
        timestamp='2021-01-02T00:00:00Z',
        prev_hash=genesis.block_hash,
        transactions=[
            sign(ALICE, BOB.address, 2),
            sign(BOB, CHARLIE.address, 1),
        ],
    )
    b2 = Block(
        index=2,
        timestamp='2021-01-03T00:00:00Z',
        prev_hash=b1.block_hash,
        transactions=[
            sign(CHARLIE, ALICE.address, 1),
        ],
    )
    chain = Chain(genesis)
    chain._blocks.append(b1)
    chain._blocks.append(b2)
    return chain


def make_invalid_chain():
    """Chain that fails Chain.validate() (tampered genesis snapshot)."""
    chain = make_chain()
    chain.blocks[0].block_hash = '0' * 64
    return chain


BOOTSTRAP = {ALICE.address: 10, BOB.address: 1, CHARLIE.address: 0}
EXPECTED_FINAL = {ALICE.address: 9, BOB.address: 2, CHARLIE.address: 0}


class TestLedgerConstruction(unittest.TestCase):
    def test_valid_bootstrap(self):
        ledger = Ledger(dict(BOOTSTRAP))
        self.assertEqual(ledger._initial_balances, BOOTSTRAP)

    def test_bootstrap_is_copied(self):
        original = dict(BOOTSTRAP)
        ledger = Ledger(original)
        original[ALICE.address] = 999
        self.assertEqual(ledger._initial_balances[ALICE.address], 10)

    def test_bootstrap_accepts_zero(self):
        ledger = Ledger({ALICE.address: 0})
        self.assertEqual(ledger._initial_balances[ALICE.address], 0)

    def test_bootstrap_rejects_negative(self):
        with self.assertRaises(ValueError):
            Ledger({ALICE.address: -1})

    def test_bootstrap_rejects_non_int(self):
        for bad in (True, False, 1.0, 1.5, '1', None):
            with self.subTest(bad=bad):
                with self.assertRaises(TypeError):
                    Ledger({ALICE.address: bad})

    def test_bootstrap_rejects_non_address_keys(self):
        # Labels like 'alice' no longer conform to the address scheme.
        with self.assertRaises(ValueError):
            Ledger({'alice': 10})

    def test_bootstrap_rejects_empty_key(self):
        with self.assertRaises(ValueError):
            Ledger({'  ': 1})

    def test_bootstrap_rejects_duplicate_after_normalization(self):
        padded = '  ' + ALICE.address + '  '
        with self.assertRaises(ValueError):
            Ledger({ALICE.address: 1, padded: 2})


class TestLedgerReplaySuccess(unittest.TestCase):
    def setUp(self):
        self.ledger = Ledger(dict(BOOTSTRAP))
        self.chain = make_chain()

    def test_valid_signed_transfers_update_balances(self):
        self.assertEqual(self.ledger.replay(self.chain), EXPECTED_FINAL)

    def test_transactions_processed_in_order(self):
        final = self.ledger.replay(self.chain)
        # alice -2, bob +2-1, charlie +1-1
        self.assertEqual(final[ALICE.address], 9)
        self.assertEqual(final[BOB.address], 2)
        self.assertEqual(final[CHARLIE.address], 0)

    def test_later_spend_of_received_funds(self):
        # charlie spends what bob sent in block 1, inside block 2.
        final = self.ledger.replay(self.chain)
        self.assertEqual(final, EXPECTED_FINAL)

    def test_self_transfer_requires_funds_but_keeps_balance(self):
        genesis = genesis_block()
        b1 = Block(
            index=1,
            timestamp='2021-01-02T00:00:00Z',
            prev_hash=genesis.block_hash,
            transactions=[sign(ALICE, ALICE.address, 2)],
        )
        b2 = Block(
            index=2,
            timestamp='2021-01-03T00:00:00Z',
            prev_hash=b1.block_hash,
            transactions=[sign(ALICE, BOB.address, 1)],
        )
        chain = Chain(genesis)
        chain._blocks.append(b1)
        chain._blocks.append(b2)
        ledger = Ledger({ALICE.address: 10})
        final = ledger.replay(chain)
        self.assertEqual(final[ALICE.address], 9)
        self.assertEqual(final[BOB.address], 1)

    def test_self_transfer_insufficient_funds_fails(self):
        genesis = genesis_block()
        b1 = Block(
            index=1,
            timestamp='2021-01-02T00:00:00Z',
            prev_hash=genesis.block_hash,
            transactions=[sign(ALICE, ALICE.address, 999)],
        )
        chain = Chain(genesis)
        chain._blocks.append(b1)
        ledger = Ledger({ALICE.address: 10})
        with self.assertRaises(InsufficientFundsError):
            ledger.replay(chain)

    def test_unknown_recipient_can_receive(self):
        genesis = genesis_block()
        b1 = Block(
            index=1,
            timestamp='2021-01-02T00:00:00Z',
            prev_hash=genesis.block_hash,
            transactions=[sign(ALICE, MALLORY.address, 3)],
        )
        chain = Chain(genesis)
        chain._blocks.append(b1)
        ledger = Ledger({ALICE.address: 10})
        final = ledger.replay(chain)
        self.assertEqual(final[MALLORY.address], 3)

    def test_unknown_sender_cannot_spend(self):
        genesis = genesis_block()
        b1 = Block(
            index=1,
            timestamp='2021-01-02T00:00:00Z',
            prev_hash=genesis.block_hash,
            transactions=[sign(MALLORY, ALICE.address, 1)],
        )
        chain = Chain(genesis)
        chain._blocks.append(b1)
        ledger = Ledger({ALICE.address: 10})
        with self.assertRaises(InsufficientFundsError):
            ledger.replay(chain)

    def test_result_is_a_separate_snapshot(self):
        ledger = Ledger({ALICE.address: 10})
        result = ledger.replay(make_chain())
        result[MALLORY.address] = 999
        self.assertEqual(ledger._initial_balances[ALICE.address], 10)
        self.assertNotIn(MALLORY.address, ledger._initial_balances)


class TestLedgerReplayFailure(unittest.TestCase):
    def setUp(self):
        self.ledger = Ledger(dict(BOOTSTRAP))
        self.chain = make_chain()

    def _single_tx_chain(self, wallet, recipient, amount):
        chain = Chain(genesis_block())
        b1 = Block(
            index=1,
            timestamp='2021-01-02T00:00:00Z',
            prev_hash=chain.blocks[0].block_hash,
            transactions=[sign(wallet, recipient, amount)],
        )
        chain._blocks.append(b1)
        return chain

    def test_insufficient_funds_raises(self):
        chain = self._single_tx_chain(BOB, ALICE.address, 999)
        with self.assertRaises(InsufficientFundsError):
            self.ledger.replay(chain)

    def test_overspend_within_block(self):
        genesis = genesis_block()
        b1 = Block(
            index=1,
            timestamp='2021-01-02T00:00:00Z',
            prev_hash=genesis.block_hash,
            transactions=[
                sign(ALICE, BOB.address, 6),
                sign(ALICE, CHARLIE.address, 6),  # alice only has 10
            ],
        )
        chain = Chain(genesis)
        chain._blocks.append(b1)
        with self.assertRaises(InsufficientFundsError):
            self.ledger.replay(chain)
        # Bootstrap untouched after failure.
        self.assertEqual(self.ledger._initial_balances, BOOTSTRAP)

    def test_unsigned_dict_rejected(self):
        genesis = genesis_block()
        b1 = Block(
            index=1,
            timestamp='2021-01-02T00:00:00Z',
            prev_hash=genesis.block_hash,
            transactions=[
                {'sender': ALICE.address, 'recipient': BOB.address, 'amount': 2},
            ],
        )
        chain = Chain(genesis)
        chain._blocks.append(b1)
        with self.assertRaises(InvalidTransactionError):
            self.ledger.replay(chain)

    def test_invalid_signature_rejected(self):
        # Mallory signs a transfer that claims Alice as sender: address
        # mismatch -> InvalidTransactionError, not a balance change.
        genesis = genesis_block()
        forged = Transaction(sender=ALICE.address, recipient=BOB.address, amount=5)
        # Build a dict with mallory's key but alice's claimed sender.
        payload_bytes = None
        from core.signed_transaction import canonical_payload
        payload_bytes = canonical_payload(
            sender=ALICE.address,
            recipient=BOB.address,
            amount=5,
            public_key_bytes=MALLORY.public_key_bytes,
        )
        from core.signed_transaction import encode_base64url
        bad = {
            'sender': ALICE.address,
            'recipient': BOB.address,
            'amount': 5,
            'public_key': encode_base64url(MALLORY.public_key_bytes),
            'signature': encode_base64url(
                MALLORY._private_key.sign(payload_bytes)
            ),
        }
        b1 = Block(
            index=1,
            timestamp='2021-01-02T00:00:00Z',
            prev_hash=genesis.block_hash,
            transactions=[bad],
        )
        chain = Chain(genesis)
        chain._blocks.append(b1)
        with self.assertRaises(InvalidTransactionError):
            self.ledger.replay(chain)

    def test_bit_flipped_signature_rejected(self):
        good = sign(ALICE, BOB.address, 5)
        import base64
        sig = base64.urlsafe_b64decode(good['signature'] + '==')
        flipped = bytes([b ^ 0x01 for b in sig])
        from core.signed_transaction import encode_base64url
        good['signature'] = encode_base64url(flipped)
        genesis = genesis_block()
        b1 = Block(
            index=1,
            timestamp='2021-01-02T00:00:00Z',
            prev_hash=genesis.block_hash,
            transactions=[good],
        )
        chain = Chain(genesis)
        chain._blocks.append(b1)
        with self.assertRaises(InvalidSignatureError):
            self.ledger.replay(chain)

    def test_malformed_transaction_raises(self):
        genesis = genesis_block()
        b1 = Block(
            index=1,
            timestamp='2021-01-02T00:00:00Z',
            prev_hash=genesis.block_hash,
            transactions=[{'sender': ALICE.address}],  # missing fields
        )
        chain = Chain(genesis)
        chain._blocks.append(b1)
        with self.assertRaises(InvalidTransactionError):
            self.ledger.replay(chain)

    def test_invalid_chain_raises(self):
        with self.assertRaises(InvalidChainError):
            self.ledger.replay(make_invalid_chain())

    def test_failed_replay_then_successful_replay(self):
        bad_chain = self._single_tx_chain(BOB, ALICE.address, 999)
        with self.assertRaises(InsufficientFundsError):
            self.ledger.replay(bad_chain)
        # Later successful replay is unaffected by the earlier failure.
        self.assertEqual(self.ledger.replay(self.chain), EXPECTED_FINAL)

    def test_failed_replay_leaves_bootstrap_untouched(self):
        original = dict(self.ledger._initial_balances)
        bad_chain = self._single_tx_chain(BOB, ALICE.address, 999)
        with self.assertRaises(InsufficientFundsError):
            self.ledger.replay(bad_chain)
        self.assertEqual(self.ledger._initial_balances, original)

    def test_replay_twice_is_deterministic(self):
        first = self.ledger.replay(self.chain)
        second = self.ledger.replay(self.chain)
        self.assertEqual(first, second)
        self.assertEqual(first, EXPECTED_FINAL)


class TestLedgerBlockIntegration(unittest.TestCase):
    def test_signed_dict_hashes_inside_block(self):
        # The signed dict must be storable and hashable by Block as-is.
        genesis = genesis_block()
        tx = sign(ALICE, BOB.address, 2)
        b1 = Block(
            index=1,
            timestamp='2021-01-02T00:00:00Z',
            prev_hash=genesis.block_hash,
            transactions=[tx],
        )
        self.assertEqual(b1.transactions, [tx])
        self.assertEqual(len(b1.block_hash), 64)
        self.assertTrue(b1.verify())
        chain = Chain(genesis)
        chain._blocks.append(b1)
        ledger = Ledger({ALICE.address: 10, BOB.address: 0})
        final = ledger.replay(chain)
        self.assertEqual(final, {ALICE.address: 8, BOB.address: 2})


if __name__ == '__main__':
    unittest.main()
