"""Tests for the Chain component. Standard library unittest only."""

import hashlib
import json
import unittest

from core.block import (
    GENESIS_INDEX,
    GENESIS_PREV_HASH,
    GENESIS_TIMESTAMP,
    Block,
    genesis_block,
)
from core.chain import Chain


class TestChainInitialization(unittest.TestCase):
    def test_valid_genesis_creates_chain(self):
        genesis = genesis_block()
        chain = Chain(genesis)
        self.assertIs(chain.blocks[0], genesis)
        self.assertEqual(len(chain.blocks), 1)
        self.assertTrue(chain.validate())

    def test_invalid_genesis_index(self):
        with self.assertRaises(ValueError):
            Chain(Block(index=1, timestamp=GENESIS_TIMESTAMP,
                        prev_hash=GENESIS_PREV_HASH, transactions=[]))

    def test_invalid_genesis_timestamp(self):
        with self.assertRaises(ValueError):
            Chain(Block(index=0, timestamp="2022-01-01T00:00:00Z",
                        prev_hash=GENESIS_PREV_HASH, transactions=[]))

    def test_invalid_genesis_prev_hash(self):
        with self.assertRaises(ValueError):
            Chain(Block(index=0, timestamp=GENESIS_TIMESTAMP,
                        prev_hash="1" * 64, transactions=[]))

    def test_invalid_genesis_transactions(self):
        with self.assertRaises(ValueError):
            Chain(Block(index=0, timestamp=GENESIS_TIMESTAMP,
                        prev_hash=GENESIS_PREV_HASH,
                        transactions=[{"bad": True}]))

    def test_invalid_genesis_hash(self):
        # Fields correct, but stored snapshot corrupted.
        genesis = genesis_block()
        genesis.block_hash = "0" * 64
        with self.assertRaises(ValueError):
            Chain(genesis)


class TestChainAppending(unittest.TestCase):
    def test_append_sequence_and_links(self):
        chain = Chain(genesis_block())
        b1 = chain.append(
            timestamp="2021-01-02T00:00:00Z",
            transactions=[{"sender": "alice", "amount": 5}])
        b2 = chain.append(
            timestamp="2021-01-03T00:00:00Z",
            transactions=[{"sender": "bob", "amount": 3}])
        self.assertEqual([b.index for b in chain.blocks], [0, 1, 2])
        self.assertEqual(b1.prev_hash, chain.blocks[0].block_hash)
        self.assertEqual(b2.prev_hash, b1.block_hash)
        self.assertTrue(chain.validate())

    def test_append_index_uses_chain_length(self):
        chain = Chain(genesis_block())
        first = chain.append(timestamp="2021-01-02T00:00:00Z",
                             transactions=[])
        second = chain.append(timestamp="2021-01-03T00:00:00Z",
                              transactions=[])
        self.assertEqual(first.index, 1)
        self.assertEqual(second.index, 2)

    def test_append_refuses_invalid_chain(self):
        chain = Chain(genesis_block())
        chain.blocks[0].timestamp = "tampered"  # corrupt chain in memory
        # Recompute the stored snapshot so the block itself still verifies.
        chain.blocks[0].block_hash = chain.blocks[0].calculate_hash()
        # The chain now fails its own rule, but block 0 itself still verifies.
        self.assertFalse(chain.validate())
        self.assertTrue(chain.blocks[0].verify())
        with self.assertRaises(RuntimeError):
            chain.append(timestamp="2021-01-04T00:00:00Z",
                         transactions=[])

    def test_append_uses_previous_block_stored_hash(self):
        chain = Chain(genesis_block())
        b1 = chain.append(timestamp="2021-01-02T00:00:00Z",
                          transactions=[{"a": 1}])
        b2 = chain.append(timestamp="2021-01-03T00:00:00Z",
                          transactions=[{"a": 2}])
        self.assertEqual(b2.prev_hash, b1.block_hash)
        # Tamper with b1's contents, then restore its snapshot.
        b1.timestamp = "2021-01-02T00:00:00Z"
        b1.block_hash = b1.calculate_hash()
        self.assertTrue(b1.verify())
        self.assertTrue(chain.validate())


class TestChainImmutability(unittest.TestCase):
    def test_transactions_list_isolation_outer(self):
        """Mutating the caller's list after append must not touch the block.

        Block does a shallow copy of the outer list, so this must be tested
        at the outer level. Nested dicts are intentionally not protected and
        are documented as a known limitation.
        """
        tx = [{"sender": "alice", "amount": 5}]
        b = Block(index=1, timestamp="2021-01-02T00:00:00Z",
                  prev_hash="0" * 64, transactions=tx)
        tx.append({"added": "after"})  # mutate original list only
        self.assertEqual(b.transactions, [{"sender": "alice", "amount": 5}])
        self.assertTrue(b.verify())

    def test_chain_holds_own_list_copy(self):
        chain = Chain(genesis_block())
        tx = [{"sender": "alice", "amount": 5}]
        chain.append(timestamp="2021-01-02T00:00:00Z", transactions=tx)
        tx.append({"added": "after"})  # caller mutates the original list
        self.assertEqual(chain.blocks[1].transactions,
                         [{"sender": "alice", "amount": 5}])
        self.assertTrue(chain.validate())


class TestChainValidation(unittest.TestCase):
    def test_valid_chain_validates(self):
        chain = Chain(genesis_block())
        chain.append(timestamp="2021-01-02T00:00:00Z",
                     transactions=[{"a": 1}])
        chain.append(timestamp="2021-01-03T00:00:00Z",
                     transactions=[{"a": 2}])
        self.assertTrue(chain.validate())

    def test_broken_link_fails_validate_but_block_still_verifies(self):
        """A block's own hash is correct, but its prev_hash breaks the chain.

        Proof that chain validation inspects links and indices, not just
        each block's own self-verification.
        """
        chain = Chain(genesis_block())
        b1 = chain.append(timestamp="2021-01-02T00:00:00Z",
                          transactions=[{"a": 1}])
        b2 = chain.append(timestamp="2021-01-03T00:00:00Z",
                          transactions=[{"a": 2}])

        # Break the link from block 2 back to block 1.
        b2.prev_hash = "0" * 64

        # Recompute block 2's stored hash so its OWN contents are still valid.
        b2.block_hash = b2.calculate_hash()
        self.assertTrue(b2.verify())
        self.assertFalse(chain.validate())
        # The block is fine; the chain is broken at the link.
        self.assertTrue(chain.blocks[2].verify())

    def test_incorrect_index_fails_validate_but_block_still_verifies(self):
        """A block's own hash is correct, but its index is wrong.

        Proof that chain validation inspects position, not just per-block.
        """
        chain = Chain(genesis_block())
        chain.append(timestamp="2021-01-02T00:00:00Z",
                     transactions=[{"a": 1}])
        b2 = chain.append(timestamp="2021-01-03T00:00:00Z",
                          transactions=[{"a": 2}])

        b2.index = 99
        b2.block_hash = b2.calculate_hash()  # restore self-verification

        self.assertTrue(b2.verify())
        self.assertFalse(chain.validate())
        self.assertEqual(chain.blocks[2].index, 99)

    def test_tampered_block_fails_chain(self):
        chain = Chain(genesis_block())
        chain.append(timestamp="2021-01-02T00:00:00Z",
                     transactions=[{"a": 1}])
        chain.append(timestamp="2021-01-03T00:00:00Z",
                     transactions=[{"a": 2}])
        chain.blocks[1].timestamp = "2021-01-02T00:00:00Z2"
        self.assertFalse(chain.validate())
        self.assertFalse(chain.blocks[1].verify())

    def test_duplicate_genesis_fails(self):
        chain = Chain(genesis_block())
        dup = Block(index=0, timestamp="2021-01-02T00:00:00Z",
                    prev_hash="0" * 64, transactions=[])
        dup.block_hash = dup.calculate_hash()
        chain._blocks.append(dup)
        self.assertFalse(chain.validate())


class TestChainBlocksAccessor(unittest.TestCase):
    def test_blocks_is_tuple(self):
        chain = Chain(genesis_block())
        chain.append(timestamp="2021-01-02T00:00:00Z",
                     transactions=[])
        self.assertIsInstance(chain.blocks, tuple)

    def test_blocks_is_not_internal_list(self):
        chain = Chain(genesis_block())
        chain.append(timestamp="2021-01-02T00:00:00Z",
                     transactions=[])
        self.assertIsNot(chain.blocks, chain._blocks)

    def test_blocks_cannot_be_resized(self):
        chain = Chain(genesis_block())
        with self.assertRaises(AttributeError):
            chain.blocks.append(None)


class TestChainValidateReturnStrictBoolean(unittest.TestCase):
    def test_validate_returns_bool(self):
        chain = Chain(genesis_block())
        self.assertIsInstance(chain.validate(), bool)
        self.assertTrue(chain.validate())
        # Corrupt a link but keep the block itself valid.
        b1 = chain.append(timestamp="2021-01-02T00:00:00Z",
                          transactions=[{"a": 1}])
        b1.prev_hash = "0" * 64
        b1.block_hash = b1.calculate_hash()
        self.assertFalse(chain.validate())
        self.assertIsInstance(chain.validate(), bool)


class TestChainIndexMustBeExactInteger(unittest.TestCase):
    """Indices must be genuine ints, not bools or floats.

    ``bool`` is a subclass of ``int`` (``True == 1``, ``False == 0``) and
    ``1.0 == 1``, so equality-based index checks are unsound. Every index is
    now required to be a real ``int`` via ``is_exact_int``.
    """

    def test_genesis_rejects_boolean_false_index(self):
        with self.assertRaises(ValueError):
            Chain(Block(index=False, timestamp=GENESIS_TIMESTAMP,
                        prev_hash=GENESIS_PREV_HASH, transactions=[]))

    def test_genesis_rejects_boolean_true_index(self):
        with self.assertRaises(ValueError):
            Chain(Block(index=True, timestamp=GENESIS_TIMESTAMP,
                        prev_hash=GENESIS_PREV_HASH, transactions=[]))

    def test_genesis_rejects_float_zero_index(self):
        with self.assertRaises(ValueError):
            Chain(Block(index=0.0, timestamp=GENESIS_TIMESTAMP,
                        prev_hash=GENESIS_PREV_HASH, transactions=[]))

    def test_genesis_rejects_non_int_index(self):
        with self.assertRaises(ValueError):
            Chain(Block(index="0", timestamp=GENESIS_TIMESTAMP,
                        prev_hash=GENESIS_PREV_HASH, transactions=[]))

    def test_validate_rejects_boolean_true_index_after_genesis(self):
        chain = Chain(genesis_block())
        chain.append(timestamp="2021-01-02T00:00:00Z", transactions=[{"a": 1}])
        block = chain.blocks[1]
        block.index = True
        block.block_hash = block.calculate_hash()  # restore self-verification
        self.assertTrue(block.verify())
        self.assertFalse(chain.validate())

    def test_validate_rejects_boolean_false_index_at_genesis(self):
        chain = Chain(genesis_block())
        genesis = chain.blocks[0]
        genesis.index = False
        genesis.block_hash = genesis.calculate_hash()
        self.assertTrue(genesis.verify())
        self.assertFalse(chain.validate())

    def test_validate_rejects_float_index_after_genesis(self):
        chain = Chain(genesis_block())
        chain.append(timestamp="2021-01-02T00:00:00Z", transactions=[{"a": 1}])
        block = chain.blocks[1]
        block.index = 1.0
        block.block_hash = block.calculate_hash()
        self.assertTrue(block.verify())
        self.assertFalse(chain.validate())

    def test_validate_accepts_integer_indices(self):
        chain = Chain(genesis_block())
        chain.append(timestamp="2021-01-02T00:00:00Z", transactions=[{"a": 1}])
        chain.append(timestamp="2021-01-03T00:00:00Z", transactions=[{"a": 2}])
        self.assertTrue(chain.validate())

    def test_append_produces_exact_integer_indices(self):
        chain = Chain(genesis_block())
        chain.append(timestamp="2021-01-02T00:00:00Z", transactions=[])
        chain.append(timestamp="2021-01-03T00:00:00Z", transactions=[])
        for block in chain.blocks:
            self.assertIs(type(block.index), int)


class TestChainTransactionContainerMustBeList(unittest.TestCase):
    """``Block.transactions`` must be a plain list.

    ``Block.__init__`` normalizes its input to a list, so a non-list container
    can only appear via post-construction mutation of the public attribute. A
    generator reproduces its hash inside ``to_dict`` (which calls
    ``list(...)``) and is then consumed, silently dropping every transaction,
    so the container type must be checked *before* ``verify()``.
    """

    def test_genesis_constructor_rejects_generator_container(self):
        # Regression guard: a generator reaching genesis.transactions (only
        # possible via post-construction mutation) must be rejected WITHOUT
        # being consumed. The constructor rejects on container type before any
        # empty-list comparison or hashing could iterate it.
        genesis = genesis_block()
        gen = (t for t in [{"sender": "alice", "amount": 5}])
        genesis.transactions = gen  # post-construction substitution
        with self.assertRaises(ValueError):
            Chain(genesis)
        # The generator was never consumed, so it still yields its one item.
        self.assertEqual(list(gen), [{"sender": "alice", "amount": 5}])

    def test_genesis_constructor_rejects_list_subclass_container(self):
        class MyList(list):
            pass

        genesis = genesis_block()
        genesis.transactions = MyList()  # equals [] but is not a plain list
        with self.assertRaises(ValueError):
            Chain(genesis)

    def test_validate_rejects_generator_container_after_genesis(self):
        chain = Chain(genesis_block())
        chain.append(timestamp="2021-01-02T00:00:00Z", transactions=[{"a": 1}])
        block = chain.blocks[1]
        block.transactions = (t for t in [{"a": 1}])
        self.assertFalse(chain.validate())

    def test_validate_rejects_generator_without_consuming_it(self):
        # Decisive ordering assertion: the container check runs before verify(),
        # so a generator is rejected while still intact (never silently skipped).
        chain = Chain(genesis_block())
        chain.append(timestamp="2021-01-02T00:00:00Z", transactions=[{"a": 1}])
        block = chain.blocks[1]
        block.transactions = (t for t in [{"a": 1}])
        self.assertFalse(chain.validate())
        self.assertEqual(len(list(block.transactions)), 1)

    def test_validate_rejects_generator_container_at_genesis(self):
        chain = Chain(genesis_block())
        chain.blocks[0].transactions = (t for t in [])
        self.assertFalse(chain.validate())

    def test_validate_rejects_list_subclass_container_after_genesis(self):
        class MyList(list):
            pass

        chain = Chain(genesis_block())
        chain.append(timestamp="2021-01-02T00:00:00Z", transactions=[{"a": 1}])
        block = chain.blocks[1]
        block.transactions = MyList([{"a": 1}])
        block.block_hash = block.calculate_hash()
        self.assertTrue(block.verify())
        self.assertFalse(chain.validate())

    def test_validate_accepts_list_container(self):
        chain = Chain(genesis_block())
        chain.append(timestamp="2021-01-02T00:00:00Z", transactions=[{"a": 1}])
        self.assertTrue(chain.validate())
