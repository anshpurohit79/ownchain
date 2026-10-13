"""Signed transaction representation for the educational cryptocurrency.

A ``SignedTransaction`` is the authoritative, verifiable payment record that
travels through ``Block.transactions`` and through the ledger pipeline.

It contains exactly these fields:

    sender, recipient, amount, public_key, signature

The signature is over a canonical payload containing exactly:

    sender, recipient, amount, public_key

Within that payload, ``public_key`` is encoded as canonical UNPADDED
base64url, identical to the ``public_key`` serialization field. The signature
itself is excluded from the payload so the record is never self-referential.

Canonical encodings
-------------------
- JSON payload: sorted keys, compact separators, UTF-8 bytes.
- sender / recipient: exactly 40 lowercase hexadecimal characters.
- public_key: UNPADDED base64url of exactly 32 raw Ed25519 bytes.
- signature: UNPADDED base64url of exactly 64 raw signature bytes.

Error contract
--------------
- Malformed records, invalid addresses, malformed encodings, or a
  public-key/sender mismatch raise ``InvalidTransactionError``.
- A well-formed record whose signature does not verify raises
  ``InvalidSignatureError``.

Security scope: no replay protection, issuance, fees, mining, networking,
consensus, or real-funds use. The private key never appears here.
"""

import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from core.exceptions import InvalidSignatureError, InvalidTransactionError

_BASE64URL = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


def is_valid_address(value: object) -> bool:
    """True iff *value* is exactly 40 lowercase hexadecimal characters."""
    if not isinstance(value, str) or len(value) != 40:
        return False
    return all(c in "0123456789abcdef" for c in value)


def encode_base64url(raw: bytes) -> str:
    """Canonical UNPADDED base64url encoding (RFC 4648 section 5)."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_base64url(value: object, expected_len: int) -> bytes:
    """Strictly decode UNPADDED base64url; reject padding and bad chars."""
    if not isinstance(value, str) or not value:
        raise InvalidTransactionError("field must be a non-empty base64url string")
    if "=" in value:
        raise InvalidTransactionError("field must be UNPADDED base64url (no '=')")
    if any(ch not in _BASE64URL for ch in value):
        raise InvalidTransactionError("field contains non-base64url characters")
    try:
        padded = value + "=" * (-len(value) % 4)
        raw = base64.urlsafe_b64decode(padded)
    except Exception as exc:
        raise InvalidTransactionError("field is not valid base64url") from exc
    if len(raw) != expected_len:
        raise InvalidTransactionError(
            f"expected {expected_len} bytes, got {len(raw)} bytes"
        )
    # Reject non-canonical encodings: re-encoding the decoded bytes must
    # reproduce the exact input. This catches trailing-bit variants that
    # decode to the same bytes but are not the canonical unpadded form.
    if encode_base64url(raw) != value:
        raise InvalidTransactionError(
            "field is not the canonical unpadded base64url representation"
        )
    return raw


def canonical_payload(
    *, sender: str, recipient: str, amount: int, public_key_bytes: bytes
) -> bytes:
    """Deterministic UTF-8 JSON bytes for the signed payload.

    Sorted keys and compact separators; contains only the four
    authorization-relevant fields (sender, recipient, integer amount, and
    the public key encoded as canonical UNPADDED base64url), never the
    signature.
    """
    return json.dumps(
        {
            "sender": sender,
            "recipient": recipient,
            "amount": amount,
            "public_key": encode_base64url(public_key_bytes),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class SignedTransaction:
    """Strict signed-record parsing, serialization, and verification."""

    def __init__(
        self,
        sender: str,
        recipient: str,
        amount: int,
        public_key_bytes: bytes,
        signature_bytes: bytes,
    ):
        if not is_valid_address(sender):
            raise InvalidTransactionError(
                f"sender must be 40 lowercase hex characters, got {sender!r}"
            )
        if not is_valid_address(recipient):
            raise InvalidTransactionError(
                f"recipient must be 40 lowercase hex characters, got {recipient!r}"
            )
        if type(amount) is not int or amount <= 0:
            raise InvalidTransactionError("amount must be a positive int")
        if not isinstance(public_key_bytes, bytes) or len(public_key_bytes) != 32:
            raise InvalidTransactionError("public_key must be exactly 32 raw bytes")
        try:
            Ed25519PublicKey.from_public_bytes(public_key_bytes)
        except Exception as exc:
            raise InvalidTransactionError(
                "public_key is not a valid Ed25519 public key"
            ) from exc
        if not isinstance(signature_bytes, bytes) or len(signature_bytes) != 64:
            raise InvalidTransactionError("signature must be exactly 64 raw bytes")

        self._sender = sender
        self._recipient = recipient
        self._amount = amount
        self._public_key_bytes = public_key_bytes
        self._signature_bytes = signature_bytes

    # ---- Properties ---------------------------------------------------
    @property
    def sender(self) -> str:
        return self._sender

    @property
    def recipient(self) -> str:
        return self._recipient

    @property
    def amount(self) -> int:
        return self._amount

    @property
    def public_key_bytes(self) -> bytes:
        return self._public_key_bytes

    @property
    def signature_bytes(self) -> bytes:
        return self._signature_bytes

    @property
    def public_key(self) -> str:
        """Canonical UNPADDED base64url public key (serialization field)."""
        return encode_base64url(self._public_key_bytes)

    @property
    def signature(self) -> str:
        """Canonical UNPADDED base64url signature (serialization field)."""
        return encode_base64url(self._signature_bytes)

    # ---- Construction from fields ------------------------------------
    @classmethod
    def from_fields(
        cls,
        sender: str,
        recipient: str,
        amount: int,
        public_key_bytes: bytes,
        signature_bytes: bytes,
    ) -> "SignedTransaction":
        return cls(sender, recipient, amount, public_key_bytes, signature_bytes)

    # ---- Payload and serialization -----------------------------------
    def payload_bytes(self) -> bytes:
        return canonical_payload(
            sender=self._sender,
            recipient=self._recipient,
            amount=self._amount,
            public_key_bytes=self._public_key_bytes,
        )

    def to_dict(self) -> dict:
        return {
            "sender": self._sender,
            "recipient": self._recipient,
            "amount": self._amount,
            "public_key": self.public_key,
            "signature": self.signature,
        }

    def to_bytes(self) -> bytes:
        return json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    # ---- Verification -------------------------------------------------
    def verify(self) -> bool:
        """Boolean convenience wrapper.

        Returns ``True`` only when the record is structurally valid, the
        embedded public key derives ``sender``, and the signature verifies.
        Any ``InvalidTransactionError`` or ``InvalidSignatureError`` is
        caught and reported as ``False``. Use :meth:`verify_strict` when the
        specific failure reason must be distinguished by exception type.
        """
        try:
            self.verify_strict()
        except (InvalidTransactionError, InvalidSignatureError):
            return False
        return True

    def verify_strict(self) -> None:
        """Strict verification with a precise exception contract.

        - Malformed records or a public-key/sender address mismatch raise
          ``InvalidTransactionError``.
        - A well-formed record whose signature does not verify raises
          ``InvalidSignatureError``.
        - Returns ``None`` on success.

        Order of checks: first derive the address from the embedded public
        key and compare it to ``sender`` (authorization binding), then verify
        the Ed25519 signature over the canonical payload using that key.
        """
        derived = hashlib.sha256(self._public_key_bytes).digest()[:20].hex()
        if derived != self._sender:
            raise InvalidTransactionError(
                "public key does not derive the claimed sender address"
            )
        try:
            Ed25519PublicKey.from_public_bytes(self._public_key_bytes).verify(
                self._signature_bytes, self.payload_bytes()
            )
        except InvalidTransactionError:
            raise
        except Exception as exc:
            raise InvalidSignatureError("signature verification failed") from exc

    def __repr__(self) -> str:
        return (
            f"SignedTransaction(sender={self._sender!r}, "
            f"recipient={self._recipient!r}, amount={self._amount!r})"
        )
