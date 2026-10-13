"""Tests for the Wallet component. Standard library unittest only."""

import unittest

from core.ledger import InvalidSignatureError
from core.signed_transaction import SignedTransaction
from core.transaction import Transaction
from core.wallet import Wallet


class TestWalletGeneration(unittest.TestCase):
    def test_generate_creates_public_info(self):
        wallet = Wallet.generate()
        self.assertEqual(len(wallet.address), 40)
        self.assertTrue(all(c in "0123456789abcdef" for c in wallet.address))
        self.assertEqual(len(wallet.public_key_bytes), 32)

    def test_same_public_key_same_address(self):
        a = Wallet.generate()
        b = Wallet.generate()
        self.assertNotEqual(a.public_key_bytes, b.public_key_bytes)
        self.assertNotEqual(a.address, b.address)


class TestWalletSigning(unittest.TestCase):
    def setUp(self):
        self.alice = Wallet.generate()
        self.bob = Wallet.generate()
        tx = Transaction(
            sender=self.alice.address,
            recipient=self.bob.address,
            amount=5,
        )
        self.st = self.alice.sign_transaction(tx)

    def test_sign_transaction_returns_signed_record(self):
        self.assertIsInstance(self.st, SignedTransaction)
        self.assertEqual(self.st.sender, self.alice.address)
        self.assertEqual(self.st.recipient, self.bob.address)
        self.assertEqual(self.st.amount, 5)

    def test_verify_returns_true_for_valid_record(self):
        self.assertTrue(self.st.verify())
        self.st.verify_strict()  # must not raise

    def test_signing_uses_embedded_public_key(self):
        self.st.verify_strict()


class TestWalletAuthorization(unittest.TestCase):
    def setUp(self):
        self.alice = Wallet.generate()
        self.bob = Wallet.generate()

    def test_wallet_refuses_non_own_sender(self):
        from core.transaction import Transaction
        other = Transaction(
            sender=self.bob.address,
            recipient=self.alice.address,
            amount=1,
        )
        with self.assertRaises(Exception):
            self.alice.sign_transaction(other)

    def test_wallet_refuses_invalid_recipient(self):
        from core.transaction import Transaction
        bad = Transaction(
            sender=self.alice.address,
            recipient="not-a-valid-address",
            amount=1,
        )
        with self.assertRaises(Exception):
            self.alice.sign_transaction(bad)

    def test_transaction_sender_must_match_wallet(self):
        from core.transaction import Transaction
        with self.assertRaises(Exception):
            self.alice.sign_transaction(
                Transaction(
                    sender=self.bob.address,
                    recipient=self.alice.address,
                    amount=1,
                )
            )
