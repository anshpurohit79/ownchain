"""Ed25519 wallet: key generation, address derivation, transaction signing.

A ``Wallet`` owns one Ed25519 key pair and signs ``Transaction`` records
into ``SignedTransaction`` records. It exposes public information only:
the account address and the public key bytes. The private key object stays
inside the instance and is never serialized, logged, or exported.

Address derivation (deterministic):

    address = SHA-256(public_key_bytes).digest()[:20].hex()

which is exactly 40 lowercase hexadecimal characters.

Security exclusions (deliberate):
- No nonces / replay protection: a valid signed transaction can be
  replayed and applied more than once.
- No private-key encryption, persistence, or recovery phrases.
- No issuance, fees, mining, networking, or consensus.
- Signatures prove control of a key, not trustworthiness. This prototype
  is not ready for real funds.
"""

import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.exceptions import InvalidTransactionError
from core.signed_transaction import (
    SignedTransaction,
    canonical_payload,
    is_valid_address,
)
from core.transaction import Transaction


class Wallet:
    """A minimal Ed25519 wallet with a stable address."""

    def __init__(self, private_key: Ed25519PrivateKey):
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self._public_key_bytes = self._public_key.public_bytes_raw()
        self._address = hashlib.sha256(self._public_key_bytes).digest()[:20].hex()

    @classmethod
    def generate(cls) -> "Wallet":
        """Create a fresh wallet with a new Ed25519 key pair."""
        return cls(Ed25519PrivateKey.generate())

    @property
    def address(self) -> str:
        """40-character lowercase hex account address."""
        return self._address

    @property
    def public_key_bytes(self) -> bytes:
        """Raw Ed25519 public key (32 bytes). Public information only."""
        return self._public_key_bytes

    @property
    def public_key_hex(self) -> str:
        """Raw public key as 64 lowercase hex characters."""
        return self._public_key_bytes.hex()

    def sign_transaction(self, transaction: Transaction) -> SignedTransaction:
        """Sign *transaction* and return a ``SignedTransaction``.

        Refuses to sign when the transaction does not claim this wallet's
        own address as sender, or when the recipient is not a valid address.
        """
        if transaction.sender != self.address:
            raise InvalidTransactionError(
                f"wallet {self.address!r} cannot sign a transaction "
                f"from sender {transaction.sender!r}"
            )
        if not is_valid_address(transaction.recipient):
            raise InvalidTransactionError(
                f"recipient {transaction.recipient!r} is not a valid address"
            )
        payload = canonical_payload(
            sender=transaction.sender,
            recipient=transaction.recipient,
            amount=transaction.amount,
            public_key_bytes=self._public_key_bytes,
        )
        signature = self._private_key.sign(payload)
        return SignedTransaction.from_fields(
            sender=transaction.sender,
            recipient=transaction.recipient,
            amount=transaction.amount,
            public_key_bytes=self._public_key_bytes,
            signature_bytes=signature,
        )

    def __repr__(self) -> str:
        # Address and public key only; the private key never appears.
        return f"Wallet(address={self._address!r})"
