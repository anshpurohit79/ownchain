"""Tests for the Block component. Standard library unittest only."""

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


def make_block(**overrides):
    """Build a deterministic block; override any field via kwargs."""
    fields = {
        "index": 1,
        "timestamp": "2021-01-01T00:00:00Z",
        "prev_hash": "0" * 64,
        "transactions": [],
    }
    fields.update(overrides)
    return Block(**fields)


class TestGenesisBlock(unittest.TestCase):
    def test_genesis_fields(self):
        g = genesis_block()
        self.assertEqual(g.index, 0)
        self.assertEqual(g.index, GENESIS_INDEX)
        self.assertEqual(g.timestamp, "2021-01-01T00:00:00Z")
        self.assertEqual(g.timestamp, GENESIS_TIMESTAMP)
        self.assertEqual(g.prev_hash, "0" * 64)
        self.assertEqual(g.prev_hash, GENESIS_PREV_HASH)
        self.assertEqual(g.transactions, [])
        # Stored hash matches a fresh calculation at creation.
        self.assertEqual(g.block_hash, g.calculate_hash())
        self.assertTrue(g.verify())


class TestDeterminism(unittest.TestCase):
    def test_identical_blocks_have_identical_hashes(self):
        a = make_block()
        b = make_block()
        self.assertEqual(a.block_hash, b.block_hash)
        self.assertEqual(a.to_bytes(), b.to_bytes())

    def test_hash_matches_independent_computation(self):
        b = make_block()
        expected_payload = {"index": 1, "prev_hash": "0" * 64,
                            "timestamp": "2021-01-01T00:00:00Z",
                            "transactions": []}
        expected_bytes = json.dumps(
            expected_payload, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
        self.assertEqual(b.to_bytes(), expected_bytes)
        self.assertEqual(
            b.block_hash, hashlib.sha256(expected_bytes).hexdigest())

    def test_serialization_is_compact_and_sorted(self):
        b = make_block(index=2, transactions=[{"b": 2, "a": 1}])
        raw = b.to_bytes().decode("utf-8")
        # Compact: no ": " or ", " with spaces.
        self.assertNotIn(": ", raw)
        self.assertNotIn(", ", raw)
        # Sorted keys: "a" appears before "b" inside the transaction dict.
        self.assertLess(raw.index('"a"'), raw.index('"b"'))
        # Stored hash excluded from hashed payload.
        self.assertNotIn("block_hash", raw)

    def test_rejects_non_standard_floats(self):
        with self.assertRaises(ValueError):
            make_block(transactions=[float("nan")]).to_bytes()
        with self.assertRaises(ValueError):
            make_block(transactions=[float("inf")]).to_bytes()


class TestFieldMutation(unittest.TestCase):
    def test_changing_each_field_changes_hash_and_fails_verify(self):
        mutations = {
            "index": 999,
            "timestamp": "2022-06-06T06:06:06Z",
            "prev_hash": "a" * 64,
            "transactions": [{"sender": "alice", "amount": 5}],
        }
        for field, new_value in mutations.items():
            with self.subTest(field=field):
                b = make_block()
                original_snapshot = b.block_hash
                setattr(b, field, new_value)
                # Stored snapshot is frozen; fresh hash moved.
                self.assertEqual(b.block_hash, original_snapshot)
                self.assertNotEqual(b.calculate_hash(), original_snapshot)
                self.assertFalse(b.verify())

    def test_constructor_copies_outer_transactions_list(self):
        mine = []
        b = Block(index=1, timestamp="2021-01-01T00:00:00Z",
                  prev_hash="0" * 64, transactions=mine)
        mine.append({"x": 1})  # mutate caller's list after construction
        self.assertEqual(b.transactions, [])  # block unaffected
        self.assertTrue(b.verify())


class TestTamperDetection(unittest.TestCase):
    def test_tamper_after_creation_is_detected(self):
        b = make_block()
        self.assertTrue(b.verify())
        original = b.block_hash

        b.timestamp = "tampered!"  # simulate attacker editing contents

        self.assertEqual(b.block_hash, original)  # snapshot unchanged
        self.assertNotEqual(b.calculate_hash(), original)  # contents moved
        self.assertFalse(b.verify())  # mismatch => tamper detected

    def test_pristine_copy_still_verifies(self):
        b = make_block()
        pristine = make_block()  # same contents, never touched
        b.timestamp = "tampered!"
        self.assertFalse(b.verify())
        self.assertTrue(pristine.verify())

    def test_corrupted_snapshot_fails_verify(self):
        b = make_block()
        b.block_hash = "0" * 64  # contents intact, snapshot overwritten
        self.assertFalse(b.verify())


if __name__ == "__main__":
    unittest.main()
