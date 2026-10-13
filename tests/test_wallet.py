"""Tests for the Wallet component. Standard library unittest only."""

import unittest

from core.exceptions import InvalidSignatureError, InvalidTransactionError
from core.signed_transaction import SignedTransaction
from core.transaction import Transaction
from core.validation import DEFAULT_CHAIN_ID, MAX_NONCE
from core.wallet import Wallet


class TestWalletGeneration(unittest.TestCase):
    def test_generate_creates_public_info(self):
        wallet = Wallet.generate()
        self.assertEqual(len(wallet.address), 40)
        self.assertTrue(all(c in "0123456789abcdef" for c in wallet.address))
        self.assertEqual(len(wallet.public_key_bytes), 32)

    def test_distinct_wallets_distinct_keys(self):
        a = Wallet.generate()
        b = Wallet.generate()
        self.assertNotEqual(a.public_key_bytes, b.public_key_bytes)
        self.assertNotEqual(a.address, b.address)


class TestWalletSigning(unittest.TestCase):
    def setUp(self):
        self.alice = Wallet.generate()
        self.bob = Wallet.generate()
        self.chain_id = DEFAULT_CHAIN_ID
        tx = Transaction(
            sender=self.alice.address,
            recipient=self.bob.address,
            amount=5,
        )
        self.st = self.alice.sign_transaction(
            tx, nonce=0, chain_id=self.chain_id
        )

    def test_sign_transaction_returns_signed_record(self):
        self.assertIsInstance(self.st, SignedTransaction)
        self.assertEqual(self.st.sender, self.alice.address)
        self.assertEqual(self.st.recipient, self.bob.address)
        self.assertEqual(self.st.amount, 5)
        self.assertEqual(self.st.nonce, 0)
        self.assertEqual(self.st.chain_id, self.chain_id)

    def test_verify_returns_true_for_valid_record(self):
        self.assertTrue(self.st.verify())
        self.st.verify_strict()  # must not raise

    def test_nonce_and_chain_id_bound_into_record(self):
        # The signature is only valid for the exact nonce and chain id used
        # at signing time; both are carried on the record.
        self.assertEqual(self.st.nonce, 0)
        self.assertEqual(self.st.chain_id, DEFAULT_CHAIN_ID)
        self.assertTrue(self.st.verify())

    def test_serialized_record_has_all_seven_fields(self):
        self.assertEqual(
            set(self.st.to_dict().keys()),
            {
                "sender",
                "recipient",
                "amount",
                "nonce",
                "chain_id",
                "public_key",
                "signature",
            },
        )


class TestWalletNonceChainBinding(unittest.TestCase):
    def setUp(self):
        self.alice = Wallet.generate()
        self.bob = Wallet.generate()
        tx = Transaction(
            sender=self.alice.address,
            recipient=self.bob.address,
            amount=5,
        )
        self.st = self.alice.sign_transaction(
            tx, nonce=0, chain_id=DEFAULT_CHAIN_ID
        )

    def _rebuild_with(self, *, nonce, chain_id):
        """Reuse the real signature but change one bound field."""
        return SignedTransaction.from_fields(
            sender=self.st.sender,
            recipient=self.st.recipient,
            amount=self.st.amount,
            nonce=nonce,
            chain_id=chain_id,
            public_key_bytes=self.st.public_key_bytes,
            signature_bytes=self.st.signature_bytes,
        )

    def test_changing_nonce_invalidates_signature(self):
        tampered = self._rebuild_with(nonce=1, chain_id=self.st.chain_id)
        self.assertFalse(tampered.verify())
        with self.assertRaises(InvalidSignatureError):
            tampered.verify_strict()

    def test_changing_chain_id_invalidates_signature(self):
        tampered = self._rebuild_with(
            nonce=self.st.nonce, chain_id="other-chain-1"
        )
        self.assertFalse(tampered.verify())
        with self.assertRaises(InvalidSignatureError):
            tampered.verify_strict()


class TestWalletAuthorization(unittest.TestCase):
    def setUp(self):
        self.alice = Wallet.generate()
        self.bob = Wallet.generate()

    def _tx(self, sender, recipient):
        return Transaction(sender=sender, recipient=recipient, amount=1)

    def test_wallet_refuses_non_own_sender(self):
        other = self._tx(self.bob.address, self.alice.address)
        with self.assertRaises(InvalidTransactionError):
            self.alice.sign_transaction(other, nonce=0, chain_id=DEFAULT_CHAIN_ID)

    def test_wallet_refuses_invalid_recipient(self):
        bad = self._tx(self.alice.address, "not-a-valid-address")
        with self.assertRaises(InvalidTransactionError):
            self.alice.sign_transaction(bad, nonce=0, chain_id=DEFAULT_CHAIN_ID)

    def test_wallet_refuses_invalid_nonce(self):
        tx = self._tx(self.alice.address, self.bob.address)
        for bad_nonce in (-1, MAX_NONCE + 1, True, 1.5, "0", None):
            with self.subTest(nonce=bad_nonce):
                with self.assertRaises(InvalidTransactionError):
                    self.alice.sign_transaction(
                        tx, nonce=bad_nonce, chain_id=DEFAULT_CHAIN_ID
                    )

    def test_wallet_refuses_invalid_chain_id(self):
        tx = self._tx(self.alice.address, self.bob.address)
        for bad_chain in ("", "BAD CHAIN", "-leading", "has space", "x" * 65, None):
            with self.subTest(chain_id=bad_chain):
                with self.assertRaises(InvalidTransactionError):
                    self.alice.sign_transaction(tx, nonce=0, chain_id=bad_chain)


class TestWalletSecurity(unittest.TestCase):
    def setUp(self):
        self.alice = Wallet.generate()
        tx = Transaction(
            sender=self.alice.address,
            recipient=self.alice.address,
            amount=5,
        )
        self.st = self.alice.sign_transaction(
            tx, nonce=0, chain_id=DEFAULT_CHAIN_ID
        )

    def test_private_key_not_in_serialization(self):
        blob = self.st.to_dict()
        text = repr(blob) + repr(self.st) + self.st.to_bytes().decode("utf-8")
        priv = self.alice._private_key.private_bytes_raw()
        self.assertNotIn(priv, text.encode("utf-8", errors="ignore"))
        self.assertNotIn(priv.hex(), text)

    def test_repr_excludes_private_key(self):
        text = repr(self.alice)
        priv = self.alice._private_key.private_bytes_raw()
        self.assertNotIn(priv, text.encode("utf-8", errors="ignore"))
        self.assertNotIn(priv.hex(), text)
        self.assertIn(self.alice.address, text)
