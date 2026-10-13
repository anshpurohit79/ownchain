"""Tests for the SignedTransaction component. Standard library unittest only.

Covers the shared validation primitives (core.validation), the domain-separated
signed-message format (nonce + chain_id added to the signed record), and a fixed
Ed25519 golden vector that was independently cross-checked with Go's standard
library.

Scope note (Milestone 6): this file builds signed records directly from a fixed
test-only Ed25519 key using the same ``signing_bytes`` helper the verifier uses,
so the golden vector and nonce/chain-id binding are pinned independently of any
wallet. The migrated ``Wallet.sign_transaction`` and ``Ledger.replay`` transfer
path is covered end-to-end in test_wallet.py and test_ledger.py.
"""

import hashlib
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.exceptions import InvalidSignatureError, InvalidTransactionError
from core.signed_transaction import (
    SignedTransaction,
    canonical_payload,
    decode_base64url,
    encode_base64url,
    signing_bytes,
)
from core.validation import (
    DEFAULT_CHAIN_ID,
    DOMAIN_PREFIX,
    MAX_NEXT_NONCE,
    MAX_NONCE,
    is_exact_int,
    is_positive_amount,
    is_valid_address,
    is_valid_chain_id,
    is_valid_nonce,
)


# ---- Fixed, test-only golden vector ---------------------------------------
# This seed is for deterministic cross-checked tests only. It is NOT a real
# wallet and must never be used to hold value.
SEED_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
EXPECTED_PUB_HEX = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
EXPECTED_ADDRESS = "56475aa75463474c0285df5dbf2bcab73da65135"
GOLDEN_RECIPIENT = "abababababababababababababababababababab"
GOLDEN_AMOUNT = 7
GOLDEN_NONCE = 0
GOLDEN_CHAIN_ID = "ownchain-devnet-1"
GOLDEN_PUB_B64URL = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"
EXPECTED_PAYLOAD = (
    '{"amount":7,"chain_id":"ownchain-devnet-1","nonce":0,'
    '"public_key":"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",'
    '"recipient":"abababababababababababababababababababab",'
    '"sender":"56475aa75463474c0285df5dbf2bcab73da65135"}'
)
EXPECTED_SIG_HEX = (
    "ef0c5382a22ca7620b8b6cb7d28e94271ad912b4d1caac2ad4f76590b7de3d8e"
    "5af5edc99dfebb510e394b66b1fce86953d76e4f8d376578e1df0d151cffa808"
)


def fixed_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEED_HEX))


def address_for(pub_bytes: bytes) -> str:
    return hashlib.sha256(pub_bytes).digest()[:20].hex()


def sign_record(
    priv: Ed25519PrivateKey,
    *,
    recipient: str,
    amount: int,
    nonce: int,
    chain_id: str,
    sender: str | None = None,
) -> SignedTransaction:
    """Build a correctly signed record exactly as the migrated wallet will.

    Uses ``signing_bytes`` (domain prefix + canonical payload) so signing and
    verification share identical bytes.
    """
    pub = priv.public_key().public_bytes_raw()
    if sender is None:
        sender = address_for(pub)
    payload = canonical_payload(
        sender=sender,
        recipient=recipient,
        amount=amount,
        nonce=nonce,
        chain_id=chain_id,
        public_key_bytes=pub,
    )
    return SignedTransaction.from_fields(
        sender=sender,
        recipient=recipient,
        amount=amount,
        nonce=nonce,
        chain_id=chain_id,
        public_key_bytes=pub,
        signature_bytes=priv.sign(signing_bytes(payload)),
    )


class TestGoldenVector(unittest.TestCase):
    """Pin the cross-checked Ed25519 golden vector literally."""

    def test_public_key_and_address(self):
        pub = fixed_key().public_key().public_bytes_raw()
        self.assertEqual(pub.hex(), EXPECTED_PUB_HEX)
        self.assertEqual(address_for(pub), EXPECTED_ADDRESS)
        self.assertEqual(encode_base64url(pub), GOLDEN_PUB_B64URL)

    def test_canonical_payload_matches_exactly(self):
        payload = canonical_payload(
            sender=EXPECTED_ADDRESS,
            recipient=GOLDEN_RECIPIENT,
            amount=GOLDEN_AMOUNT,
            nonce=GOLDEN_NONCE,
            chain_id=GOLDEN_CHAIN_ID,
            public_key_bytes=bytes.fromhex(EXPECTED_PUB_HEX),
        )
        self.assertEqual(payload.decode("utf-8"), EXPECTED_PAYLOAD)

    def test_signing_bytes_are_prefix_plus_payload(self):
        payload = canonical_payload(
            sender=EXPECTED_ADDRESS,
            recipient=GOLDEN_RECIPIENT,
            amount=GOLDEN_AMOUNT,
            nonce=GOLDEN_NONCE,
            chain_id=GOLDEN_CHAIN_ID,
            public_key_bytes=bytes.fromhex(EXPECTED_PUB_HEX),
        )
        message = signing_bytes(payload)
        self.assertTrue(message.startswith(DOMAIN_PREFIX))
        self.assertEqual(message, DOMAIN_PREFIX + payload)

    def test_signature_matches_and_verifies(self):
        st = sign_record(
            fixed_key(),
            recipient=GOLDEN_RECIPIENT,
            amount=GOLDEN_AMOUNT,
            nonce=GOLDEN_NONCE,
            chain_id=GOLDEN_CHAIN_ID,
        )
        self.assertEqual(st.signature_bytes.hex(), EXPECTED_SIG_HEX)
        self.assertTrue(st.verify())
        st.verify_strict()  # returns None on success


class TestDomainPrefix(unittest.TestCase):
    def test_prefix_is_exact_ascii_plus_single_nul(self):
        self.assertEqual(
            DOMAIN_PREFIX, b"OWNCHAIN:SIGNED-TRANSACTION:V1\x00"
        )
        self.assertEqual(DOMAIN_PREFIX.count(b"\x00"), 1)


class TestPayloadEncoding(unittest.TestCase):
    def test_payload_is_sorted_compact_utf8(self):
        st = sign_record(
            fixed_key(),
            recipient=GOLDEN_RECIPIENT,
            amount=1,
            nonce=0,
            chain_id=DEFAULT_CHAIN_ID,
        )
        raw = st.payload_bytes().decode("utf-8")
        self.assertNotIn(", ", raw)
        self.assertNotIn(": ", raw)
        # Keys must appear in sorted order in the JSON text.
        self.assertLess(raw.index('"amount"'), raw.index('"chain_id"'))
        self.assertLess(raw.index('"chain_id"'), raw.index('"nonce"'))
        self.assertLess(raw.index('"nonce"'), raw.index('"public_key"'))

    def test_payload_excludes_signature_field(self):
        st = sign_record(
            fixed_key(),
            recipient=GOLDEN_RECIPIENT,
            amount=1,
            nonce=0,
            chain_id=DEFAULT_CHAIN_ID,
        )
        self.assertNotIn("signature", st.payload_bytes().decode("utf-8"))

    def test_public_key_in_payload_is_base64url(self):
        st = sign_record(
            fixed_key(),
            recipient=GOLDEN_RECIPIENT,
            amount=1,
            nonce=0,
            chain_id=DEFAULT_CHAIN_ID,
        )
        self.assertEqual(st.public_key, encode_base64url(st.public_key_bytes))


class TestNonceValidation(unittest.TestCase):
    def test_nonzero_nonce_roundtrip(self):
        st = sign_record(
            fixed_key(),
            recipient=GOLDEN_RECIPIENT,
            amount=5,
            nonce=123456789,
            chain_id=DEFAULT_CHAIN_ID,
        )
        self.assertTrue(st.verify())
        self.assertEqual(st.nonce, 123456789)

    def test_max_nonce_is_accepted(self):
        st = sign_record(
            fixed_key(),
            recipient=GOLDEN_RECIPIENT,
            amount=5,
            nonce=MAX_NONCE,
            chain_id=DEFAULT_CHAIN_ID,
        )
        self.assertTrue(st.verify())

    def test_malformed_nonces_are_rejected(self):
        for bad in [-1, MAX_NONCE + 1, MAX_NEXT_NONCE, True, False, 1.0, "0", None]:
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidTransactionError):
                    SignedTransaction.from_fields(
                        sender=EXPECTED_ADDRESS,
                        recipient=GOLDEN_RECIPIENT,
                        amount=1,
                        nonce=bad,
                        chain_id=DEFAULT_CHAIN_ID,
                        public_key_bytes=bytes.fromhex(EXPECTED_PUB_HEX),
                        signature_bytes=bytes(64),
                    )


class TestChainIdValidation(unittest.TestCase):
    def test_alternate_valid_chain_id_roundtrip(self):
        st = sign_record(
            fixed_key(),
            recipient=GOLDEN_RECIPIENT,
            amount=5,
            nonce=0,
            chain_id="main.net_2-x",
        )
        self.assertTrue(st.verify())

    def test_malformed_chain_ids_are_rejected(self):
        for bad in ["", "BAD", "-lead", ".lead", "has space", "a" * 65, 1, None]:
            with self.subTest(bad=bad):
                with self.assertRaises(InvalidTransactionError):
                    SignedTransaction.from_fields(
                        sender=EXPECTED_ADDRESS,
                        recipient=GOLDEN_RECIPIENT,
                        amount=1,
                        nonce=0,
                        chain_id=bad,
                        public_key_bytes=bytes.fromhex(EXPECTED_PUB_HEX),
                        signature_bytes=bytes(64),
                    )


class TestSignatureFailureModes(unittest.TestCase):
    def _valid(self) -> SignedTransaction:
        return sign_record(
            fixed_key(),
            recipient=GOLDEN_RECIPIENT,
            amount=7,
            nonce=0,
            chain_id=DEFAULT_CHAIN_ID,
        )

    def test_changing_nonce_without_resigning_fails(self):
        st = self._valid()
        tampered = SignedTransaction.from_fields(
            sender=st.sender,
            recipient=st.recipient,
            amount=st.amount,
            nonce=st.nonce + 1,
            chain_id=st.chain_id,
            public_key_bytes=st.public_key_bytes,
            signature_bytes=st.signature_bytes,
        )
        self.assertFalse(tampered.verify())
        with self.assertRaises(InvalidSignatureError):
            tampered.verify_strict()

    def test_changing_chain_id_without_resigning_fails(self):
        st = self._valid()
        tampered = SignedTransaction.from_fields(
            sender=st.sender,
            recipient=st.recipient,
            amount=st.amount,
            nonce=st.nonce,
            chain_id="other-chain",
            public_key_bytes=st.public_key_bytes,
            signature_bytes=st.signature_bytes,
        )
        self.assertFalse(tampered.verify())
        with self.assertRaises(InvalidSignatureError):
            tampered.verify_strict()

    def test_corrupted_signature_fails(self):
        st = self._valid()
        bad_sig = bytes([st.signature_bytes[0] ^ 0xFF]) + st.signature_bytes[1:]
        tampered = SignedTransaction.from_fields(
            sender=st.sender,
            recipient=st.recipient,
            amount=st.amount,
            nonce=st.nonce,
            chain_id=st.chain_id,
            public_key_bytes=st.public_key_bytes,
            signature_bytes=bad_sig,
        )
        with self.assertRaises(InvalidSignatureError):
            tampered.verify_strict()

    def test_sender_key_mismatch_is_transaction_error(self):
        other = Ed25519PrivateKey.generate()
        # Claim the OTHER wallet's address but sign with the fixed key.
        st = sign_record(
            fixed_key(),
            sender=address_for(other.public_key().public_bytes_raw()),
            recipient=GOLDEN_RECIPIENT,
            amount=7,
            nonce=0,
            chain_id=DEFAULT_CHAIN_ID,
        )
        self.assertFalse(st.verify())
        with self.assertRaises(InvalidTransactionError):
            st.verify_strict()


class TestBase64UrlCanonical(unittest.TestCase):
    def test_encode_decode_roundtrip(self):
        raw = bytes(range(32))
        self.assertEqual(decode_base64url(encode_base64url(raw), 32), raw)

    def test_padded_input_is_rejected(self):
        # 32 bytes -> 44 chars unpadded; a padded form must be rejected.
        raw = bytes(32)
        canonical = encode_base64url(raw)
        padded = canonical + "="
        with self.assertRaises(InvalidTransactionError):
            decode_base64url(padded, 32)

    def test_standard_alphabet_plus_slash_is_rejected(self):
        # 0xFB 0xFF produces '+' and '/' under the standard alphabet.
        raw = b"\xfb\xff\xff" + bytes(29)
        std = __import__("base64").b64encode(raw).decode().rstrip("=")
        with self.assertRaises(InvalidTransactionError):
            decode_base64url(std, 32)

    def test_wrong_length_is_rejected(self):
        with self.assertRaises(InvalidTransactionError):
            decode_base64url(encode_base64url(bytes(64)), 32)


class TestSerialization(unittest.TestCase):
    def test_to_dict_has_exactly_seven_fields(self):
        st = sign_record(
            fixed_key(),
            recipient=GOLDEN_RECIPIENT,
            amount=7,
            nonce=3,
            chain_id=DEFAULT_CHAIN_ID,
        )
        self.assertEqual(
            set(st.to_dict().keys()),
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
        self.assertEqual(st.to_dict()["nonce"], 3)

    def test_repr_hides_nothing_public_but_no_private_key(self):
        st = sign_record(
            fixed_key(),
            recipient=GOLDEN_RECIPIENT,
            amount=7,
            nonce=0,
            chain_id=DEFAULT_CHAIN_ID,
        )
        text = repr(st)
        self.assertIn(EXPECTED_ADDRESS, text)
        self.assertNotIn("private", text.lower())


class TestValidationPredicates(unittest.TestCase):
    def test_is_valid_address(self):
        self.assertTrue(is_valid_address(EXPECTED_ADDRESS))
        self.assertFalse(is_valid_address(""))
        self.assertFalse(is_valid_address(EXPECTED_ADDRESS.upper()))
        self.assertFalse(is_valid_address(EXPECTED_ADDRESS[:-1]))
        self.assertFalse(is_valid_address("g" + EXPECTED_ADDRESS[1:]))

    def test_is_exact_int_rejects_bool(self):
        self.assertTrue(is_exact_int(5))
        self.assertFalse(is_exact_int(True))
        self.assertFalse(is_exact_int(False))
        self.assertFalse(is_exact_int(5.0))

    def test_is_positive_amount(self):
        self.assertTrue(is_positive_amount(1))
        self.assertFalse(is_positive_amount(0))
        self.assertFalse(is_positive_amount(-1))
        self.assertFalse(is_positive_amount(True))
        self.assertFalse(is_positive_amount(1.0))

    def test_is_valid_nonce(self):
        self.assertTrue(is_valid_nonce(0))
        self.assertTrue(is_valid_nonce(MAX_NONCE))
        self.assertFalse(is_valid_nonce(MAX_NONCE + 1))
        self.assertFalse(is_valid_nonce(True))

    def test_is_valid_chain_id(self):
        self.assertTrue(is_valid_chain_id(DEFAULT_CHAIN_ID))
        self.assertTrue(is_valid_chain_id("a"))
        self.assertFalse(is_valid_chain_id(""))
        self.assertFalse(is_valid_chain_id("A"))
        self.assertFalse(is_valid_chain_id("-a"))
        self.assertFalse(is_valid_chain_id("a" * 65))


if __name__ == "__main__":
    unittest.main()
