"""Tests for the SignedTransaction component. Standard library unittest only."""

import base64
import json
import unittest

from core.signed_transaction import (
    SignedTransaction,
    canonical_payload,
    decode_base64url,
    encode_base64url,
    is_valid_address,
)
from core.exceptions import InvalidSignatureError, InvalidTransactionError
from core.transaction import Transaction
from core.wallet import Wallet


def make_signed(wallet: Wallet, recipient: str, amount: int) -> SignedTransaction:
    """Helper: build a correctly signed record for *wallet*."""
    payload = canonical_payload(
        sender=wallet.address,
        recipient=recipient,
        amount=amount,
        public_key_bytes=wallet.public_key_bytes,
    )
    return SignedTransaction.from_fields(
        sender=wallet.address,
        recipient=recipient,
        amount=amount,
        public_key_bytes=wallet.public_key_bytes,
        signature_bytes=wallet._private_key.sign(payload),
    )


class TestAddressValidation(unittest.TestCase):
    def test_valid_address(self):
        self.assertTrue(is_valid_address("a" * 40))

    def test_invalid_length(self):
        self.assertFalse(is_valid_address("a" * 39))
        self.assertFalse(is_valid_address("a" * 41))
        self.assertFalse(is_valid_address(""))

    def test_invalid_characters(self):
        self.assertFalse(is_valid_address("G" * 40))
        self.assertFalse(is_valid_address("A" * 40))  # uppercase rejected

    def test_non_string(self):
        self.assertFalse(is_valid_address(123))
        self.assertFalse(is_valid_address(None))


class TestBase64urlRoundTrip(unittest.TestCase):
    def test_round_trip_32_bytes(self):
        raw = bytes(range(32))
        enc = encode_base64url(raw)
        self.assertEqual(enc, enc.rstrip("="))
        self.assertEqual(decode_base64url(enc, 32), raw)

    def test_rejects_padding(self):
        enc = encode_base64url(bytes(31)) + "="
        with self.assertRaises(InvalidTransactionError):
            decode_base64url(enc, 32)

    def test_rejects_bad_chars(self):
        with self.assertRaises(InvalidTransactionError):
            decode_base64url("!!!!not-base64!!!!", 32)

    def test_rejects_wrong_length(self):
        enc = encode_base64url(bytes(16))
        with self.assertRaises(InvalidTransactionError):
            decode_base64url(enc, 32)

    def test_rejects_noncanonical_trailing_bits(self):
        # A base64url string can carry non-significant trailing bits. The
        # lenient stdlib decoder accepts such input and yields the same raw
        # bytes, but re-encoding produces a different (canonical) string.
        # Our strict decoder must reject the non-canonical form.
        raw = bytes(range(32))
        canonical = encode_base64url(raw)
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        noncanonical = None
        for ch in alphabet:
            candidate = canonical[:-1] + ch
            padded = candidate + "=" * (-len(candidate) % 4)
            try:
                decoded = base64.urlsafe_b64decode(padded)
            except Exception:
                continue
            if decoded == raw and candidate != canonical:
                noncanonical = candidate
                break
        # Sanity: such a variant exists for this input (verified empirically).
        self.assertIsNotNone(noncanonical)
        # The lenient decoder accepts it and maps to the same bytes.
        self.assertEqual(
            base64.urlsafe_b64decode(noncanonical + "=" * (-len(noncanonical) % 4)),
            raw,
        )
        # Our strict decoder rejects it as non-canonical.
        with self.assertRaises(InvalidTransactionError):
            decode_base64url(noncanonical, 32)


class TestConstructionValidation(unittest.TestCase):
    def setUp(self):
        self.wallet = Wallet.generate()
        self.st = make_signed(self.wallet, self.wallet.address, 5)

    def test_valid_record_accepted(self):
        self.assertEqual(self.st.sender, self.wallet.address)
        self.assertEqual(self.st.amount, 5)

    def test_rejects_invalid_sender(self):
        with self.assertRaises(InvalidTransactionError):
            SignedTransaction.from_fields(
                sender="not-an-address",
                recipient=self.wallet.address,
                amount=5,
                public_key_bytes=self.wallet.public_key_bytes,
                signature_bytes=self.st.signature_bytes,
            )

    def test_rejects_invalid_amount(self):
        for bad in (True, False, 1.5, "5", 0, -3):
            with self.subTest(amount=bad):
                with self.assertRaises(InvalidTransactionError):
                    SignedTransaction.from_fields(
                        sender=self.wallet.address,
                        recipient=self.wallet.address,
                        amount=bad,
                        public_key_bytes=self.wallet.public_key_bytes,
                        signature_bytes=self.st.signature_bytes,
                    )

    def test_rejects_wrong_public_key_length(self):
        with self.assertRaises(InvalidTransactionError):
            SignedTransaction.from_fields(
                sender=self.wallet.address,
                recipient=self.wallet.address,
                amount=5,
                public_key_bytes=b"\x00" * 31,
                signature_bytes=self.st.signature_bytes,
            )

    def test_rejects_wrong_signature_length(self):
        with self.assertRaises(InvalidTransactionError):
            SignedTransaction.from_fields(
                sender=self.wallet.address,
                recipient=self.wallet.address,
                amount=5,
                public_key_bytes=self.wallet.public_key_bytes,
                signature_bytes=b"\x00" * 63,
            )


class TestVerification(unittest.TestCase):
    def setUp(self):
        self.alice = Wallet.generate()
        self.bob = Wallet.generate()
        self.st = make_signed(self.alice, self.bob.address, 5)

    def test_valid_record_verifies(self):
        self.assertTrue(self.st.verify())
        self.st.verify_strict()  # must not raise

    def test_altered_amount_fails(self):
        st = make_signed(self.alice, self.bob.address, 6)  # different amount
        # Signature was for amount=5; rebuild record with amount 6 but old sig.
        forged = SignedTransaction.from_fields(
            sender=self.alice.address,
            recipient=self.bob.address,
            amount=6,
            public_key_bytes=self.alice.public_key_bytes,
            signature_bytes=self.st.signature_bytes,
        )
        self.assertFalse(forged.verify())
        with self.assertRaises(InvalidSignatureError):
            forged.verify_strict()

    def test_altered_recipient_fails(self):
        forged = SignedTransaction.from_fields(
            sender=self.alice.address,
            recipient=self.alice.address,  # changed from bob
            amount=5,
            public_key_bytes=self.alice.public_key_bytes,
            signature_bytes=self.st.signature_bytes,
        )
        self.assertFalse(forged.verify())
        with self.assertRaises(InvalidSignatureError):
            forged.verify_strict()

    def test_sender_mismatch_raises_transaction_error(self):
        # Bob's address claimed with Alice's key: address mismatch, not sig.
        forged = SignedTransaction.from_fields(
            sender=self.bob.address,
            recipient=self.bob.address,
            amount=5,
            public_key_bytes=self.alice.public_key_bytes,
            signature_bytes=self.st.signature_bytes,
        )
        self.assertFalse(forged.verify())
        with self.assertRaises(InvalidTransactionError):
            forged.verify_strict()

    def test_bit_flipped_signature_fails(self):
        flipped = bytes([b ^ 0x01 for b in self.st.signature_bytes])
        forged = SignedTransaction.from_fields(
            sender=self.alice.address,
            recipient=self.bob.address,
            amount=5,
            public_key_bytes=self.alice.public_key_bytes,
            signature_bytes=flipped,
        )
        self.assertFalse(forged.verify())
        with self.assertRaises(InvalidSignatureError):
            forged.verify_strict()

    def test_different_wallet_cannot_forge_alice(self):
        mallory = Wallet.generate()
        payload = canonical_payload(
            sender=self.alice.address,
            recipient=self.bob.address,
            amount=5,
            public_key_bytes=mallory.public_key_bytes,
        )
        forged = SignedTransaction.from_fields(
            sender=self.alice.address,  # claims alice
            recipient=self.bob.address,
            amount=5,
            public_key_bytes=mallory.public_key_bytes,
            signature_bytes=mallory._private_key.sign(payload),
        )
        self.assertFalse(forged.verify())
        with self.assertRaises(InvalidTransactionError):
            forged.verify_strict()


class TestSerialization(unittest.TestCase):
    def setUp(self):
        self.wallet = Wallet.generate()
        self.st = make_signed(self.wallet, self.wallet.address, 5)

    def test_dict_has_exact_fields(self):
        self.assertEqual(
            set(self.st.to_dict().keys()),
            {"sender", "recipient", "amount", "public_key", "signature"},
        )

    def test_dict_is_json_compatible(self):
        import json

        d = self.st.to_dict()
        json.dumps(d, sort_keys=True, separators=(",", ":"), allow_nan=False)
        self.assertIsInstance(d["amount"], int)

    def test_bytes_deterministic_and_compact(self):
        raw = self.st.to_bytes()
        self.assertEqual(raw, self.st.to_bytes())
        text = raw.decode("utf-8")
        self.assertNotIn(": ", text)
        self.assertNotIn(", ", text)

    def test_no_private_key_in_serialization(self):
        # The private key bytes must never appear in any serialized form.
        blob = self.st.to_dict()
        text = repr(blob) + repr(self.st) + self.st.to_bytes().decode("utf-8")
        priv = self.wallet._private_key.private_bytes_raw()
        self.assertNotIn(priv, text.encode("utf-8", errors="ignore"))
        self.assertNotIn(priv.hex(), text)

    def test_payload_excludes_signature_field(self):
        payload = self.st.payload_bytes().decode("utf-8")
        self.assertNotIn("signature", payload)
        self.assertIn("sender", payload)
        self.assertIn("public_key", payload)

    def test_payload_is_exact_canonical_representation(self):
        # The signed payload must be exactly sorted, compact UTF-8 JSON of
        # sender, recipient, integer amount, and base64url-encoded public
        # key, and nothing else. This pins the representation so signing and
        # verification can never drift apart.
        wallet = self.wallet
        recipient = self.wallet.address
        amount = 5
        expected = json.dumps(
            {
                "sender": wallet.address,
                "recipient": recipient,
                "amount": amount,
                "public_key": encode_base64url(wallet.public_key_bytes),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        actual = canonical_payload(
            sender=wallet.address,
            recipient=recipient,
            amount=amount,
            public_key_bytes=wallet.public_key_bytes,
        )
        self.assertEqual(actual, expected)

    def test_signer_and_verifier_use_identical_payload_bytes(self):
        # The payload a wallet signs must equal the payload a record
        # verifies. Both funnel through canonical_payload(...).
        wallet = Wallet.generate()
        tx = Transaction(wallet.address, wallet.address, 9)
        signed = wallet.sign_transaction(tx)
        self.assertEqual(
            signed.payload_bytes(),
            canonical_payload(
                sender=wallet.address,
                recipient=wallet.address,
                amount=9,
                public_key_bytes=wallet.public_key_bytes,
            ),
        )
        self.assertTrue(signed.verify())
