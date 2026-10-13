"""Tests for the Transaction component. Standard library unittest only."""

import unittest

import json

from core.transaction import Transaction


class TestTransactionConstruction(unittest.TestCase):
    def test_valid_transaction(self):
        tx = Transaction('alice', 'bob', 5)
        self.assertEqual(tx.sender, 'alice')
        self.assertEqual(tx.recipient, 'bob')
        self.assertEqual(tx.amount, 5)

    def test_whitespace_is_stripped(self):
        tx = Transaction('  alice  ', '  bob  ', 9)
        self.assertEqual(tx.sender, 'alice')
        self.assertEqual(tx.recipient, 'bob')
        self.assertEqual(tx.amount, 9)

    def test_amount_must_be_positive_int(self):
        for bad in (0, -1, -10**6):
            with self.subTest(amount=bad):
                with self.assertRaises(ValueError):
                    Transaction('alice', 'bob', bad)

    def test_amount_must_not_be_bool(self):
        for bad in (True, False):
            with self.subTest(amount=bad):
                with self.assertRaises(ValueError):
                    Transaction('alice', 'bob', bad)

    def test_amount_must_not_be_float(self):
        for bad in (1.0, 1.5, 5.0, 0.5, -1.0):
            with self.subTest(amount=bad):
                with self.assertRaises(ValueError):
                    Transaction('alice', 'bob', bad)

    def test_amount_must_not_be_string(self):
        for bad in ('5', '1', '0', '-1', '1.5'):
            with self.subTest(amount=bad):
                with self.assertRaises(ValueError):
                    Transaction('alice', 'bob', bad)

    def test_amount_must_not_be_none_other_type(self):
        for bad in (None, 3.0, 3.5, 3+0j, [5], {'a': 5}, object()):
            with self.subTest(amount=bad):
                with self.assertRaises(ValueError):
                    Transaction('alice', 'bob', bad)

    def test_sender_must_be_string(self):
        for bad in (123, 1.5, True, None, ['alice'], {'a': 1}):
            with self.subTest(sender=bad):
                with self.assertRaises(ValueError):
                    Transaction(bad, 'bob', 1)

    def test_recipient_must_be_string(self):
        for bad in (123, 1.5, True, None, ['bob'], {'a': 1}):
            with self.subTest(recipient=bad):
                with self.assertRaises(ValueError):
                    Transaction('alice', bad, 1)

    def test_whitespace_only_rejected(self):
        for bad in ('   ', '\t', '\n', '  \t '):
            with self.subTest(value=bad):
                with self.assertRaises(ValueError):
                    Transaction(bad, 'bob', 1)
                with self.assertRaises(ValueError):
                    Transaction('alice', bad, 1)


class TestTransactionDeterminism(unittest.TestCase):
    def test_to_dict_returns_fresh_json_compatible_dict(self):
        tx = Transaction(' alice ', 'bob', 5)
        d = tx.to_dict()
        self.assertEqual(d, {'amount': 5, 'recipient': 'bob', 'sender': 'alice'})
        self.assertIsInstance(d, dict)
        self.assertIsNot(d, tx.to_dict())
        for v in d.values():
            self.assertTrue(isinstance(v, (str, int)))

    def test_to_bytes_is_deterministic(self):
        tx = Transaction('alice', 'bob', 5)
        self.assertEqual(tx.to_bytes(), b'{"amount":5,"recipient":"bob","sender":"alice"}')
        self.assertEqual(tx.to_bytes(), tx.to_bytes())

    def test_to_dict_round_trip_matches_to_bytes(self):
        tx = Transaction(' alice ', 'bob', 5)
        self.assertEqual(
            tx.to_dict(),
            {'amount': 5, 'recipient': 'bob', 'sender': 'alice'},
        )

    def test_json_serializes_without_error(self):
        tx = Transaction('a', 'b', 1)
        self.assertEqual(
            json.dumps(tx.to_dict(), sort_keys=True, separators=(',', ':')),
            '{"amount":1,"recipient":"b","sender":"a"}',
        )


class TestTransactionEquality(unittest.TestCase):
    def test_equal_transactions(self):
        a = Transaction('alice', 'bob', 5)
        b = Transaction('alice', 'bob', 5)
        self.assertEqual(a, b)
        self.assertTrue(a == b)
        self.assertFalse(a != b)

    def test_unequal_transactions(self):
        a = Transaction('alice', 'bob', 5)
        b = Transaction('alice', 'carol', 5)
        c = Transaction('alice', 'bob', 6)
        self.assertNotEqual(a, b)
        self.assertNotEqual(a, c)

    def test_not_equal_non_transaction(self):
        a = Transaction('alice', 'bob', 5)
        self.assertNotEqual(a, {'amount': 5, 'recipient': 'bob', 'sender': 'alice'})
        self.assertNotEqual(a, 'Transaction')
        self.assertNotEqual(a, 123)


class TestTransactionReadonlyAttributes(unittest.TestCase):
    def test_attributes_are_read_only(self):
        tx = Transaction('alice', 'bob', 5)
        for attr in ('sender', 'recipient', 'amount'):
            with self.subTest(attr=attr):
                with self.assertRaises(AttributeError):
                    setattr(tx, attr, 'hacked')

    def test_values_are_stored_as_given(self):
        tx = Transaction('alice', 'bob', 5)
        self.assertEqual(tx.sender, 'alice')
        self.assertEqual(tx.recipient, 'bob')
        self.assertEqual(tx.amount, 5)


class TestTransactionSelfTransfer(unittest.TestCase):
    def test_self_transfer_is_structural_valid(self):
        tx = Transaction('alice', 'alice', 1)
        self.assertEqual(tx.sender, 'alice')
        self.assertEqual(tx.recipient, 'alice')
        self.assertEqual(tx.amount, 1)


class TestTransactionIntegrationWithBlock(unittest.TestCase):
    def setUp(self):
        import hashlib
        import json
        from core.block import Block, genesis_block

        self.hashlib = hashlib
        self.json = json
        self.Block = Block
        self.genesis_block = genesis_block

    def _block_hash_for_transaction(self, tx):
        parent = self.genesis_block()
        payload = {
            'index': 1,
            'prev_hash': parent.block_hash,
            'timestamp': '2021-01-02T00:00:00Z',
            'transactions': [tx.to_dict()],
        }
        raw = self.json.dumps(
            payload,
            sort_keys=True,
            separators=(',', ':'),
            allow_nan=False,
        ).encode('utf-8')
        return self.hashlib.sha256(raw).hexdigest()


if __name__ == '__main__':
    unittest.main()
