"""Signed transaction representation for the educational cryptocurrency.

A ``SignedTransaction`` is the authoritative, verifiable payment record that
travels through ``Block.transactions`` and through the ledger pipeline.

It contains exactly these fields (serialized record):

    sender, recipient, amount, nonce, chain_id, public_key, signature

The signature is over a domain-separated message made of two parts:

    signing_bytes = DOMAIN_PREFIX + canonical_payload(...)

where ``canonical_payload`` is deterministic UTF-8 JSON containing exactly:

    sender, recipient, amount, nonce, chain_id, public_key

Within that payload ``public_key`` is encoded as canonical UNPADDED base64url,
identical to the ``public_key`` serialization field. The ``signature`` field is
excluded from the payload so the record is never self-referential. The domain
prefix (see ``core.validation.DOMAIN_PREFIX``) binds every signature to the
OwnChain transaction context so the same key can never be tricked into signing
an identical-looking message for another purpose.

Two clearly distinguished builders are provided:

- ``canonical_payload(...)`` -> the sorted, compact UTF-8 JSON payload bytes.
- ``signing_bytes(payload)`` -> the domain prefix prepended to those bytes.

The wallet and the verifier both route through ``signing_bytes`` so they can
never disagree on the exact byte string that was signed.

Canonical encodings
-------------------
- JSON payload: sorted keys, compact separators, UTF-8 bytes.
- sender / recipient: exactly 40 lowercase hexadecimal characters.
- amount: a strictly positive integer (``bool`` rejected).
- nonce: an integer in ``[0, MAX_NONCE]`` (``bool`` rejected).
- chain_id: matches ``[a-z0-9][a-z0-9._-]{0,63}``.
- public_key: UNPADDED base64url of exactly 32 raw Ed25519 bytes.
- signature: UNPADDED base64url of exactly 64 raw signature bytes.

Error contract
--------------
- Malformed records, invalid addresses/nonce/chain_id, malformed encodings, or
  a public-key/sender mismatch raise ``InvalidTransactionError``.
- A well-formed record whose signature does not verify raises
  ``InvalidSignatureError``.

Sender/public-key correspondence is checked during *verification*
(``verify_strict``), not in the constructor, so a deliberately mismatched
record can still be constructed and then rejected with the precise exception.

Security scope: this module carries ``nonce`` and ``chain_id`` and binds them
into the signed message; the ledger enforces their continuity and chain match
within deterministic linear replay (see ``core.ledger``). No issuance, fees,
mining, networking, consensus, or real-funds use is provided, and the private
key never appears here.
"""

import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from core.exceptions import InvalidSignatureError, InvalidTransactionError
from core.validation import (
    DOMAIN_PREFIX,
    MAX_NONCE,
    is_positive_amount,
    is_valid_address,
    is_valid_chain_id,
    is_valid_nonce,
)

_BASE64URL = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)

__all__ = [
    "SignedTransaction",
    "canonical_payload",
    "signing_bytes",
    "encode_base64url",
    "decode_base64url",
    "is_valid_address",
]


def encode_base64url(raw: bytes) -> str:
    """Canonical UNPADDED base64url encoding (RFC 4648 section 5)."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_base64url(value: object, expected_len: int) -> bytes:
    """Strictly decode UNPADDED base64url; reject padding and bad chars.

    The decoded bytes are re-encoded and compared against the input, so any
    non-canonical form (padding, non-significant trailing bits, mixed
    alphabet) is rejected even when a lenient decoder would accept it.
    """
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
    if encode_base64url(raw) != value:
        raise InvalidTransactionError(
            "field is not the canonical unpadded base64url representation"
        )
    return raw


def canonical_payload(
    *,
    sender: str,
    recipient: str,
    amount: int,
    nonce: int,
    chain_id: str,
    public_key_bytes: bytes,
) -> bytes:
    """Deterministic UTF-8 JSON bytes for the signed payload.

    Sorted keys and compact separators; contains exactly the six
    authorization-relevant fields (sender, recipient, integer amount, integer
    nonce, chain id, and the public key encoded as canonical UNPADDED
    base64url), never the signature. ``nonce`` and ``chain_id`` are signed so a
    replayed or cross-chain record fails verification.
    """
    return json.dumps(
        {
            "sender": sender,
            "recipient": recipient,
            "amount": amount,
            "nonce": nonce,
            "chain_id": chain_id,
            "public_key": encode_base64url(public_key_bytes),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def signing_bytes(payload: bytes) -> bytes:
    """Domain-separated signing message: ``DOMAIN_PREFIX + payload``.

    Both the wallet and the verifier must call this so the exact bytes signed
    and the exact bytes verified are identical. ``payload`` is the output of
    :func:`canonical_payload`.
    """
    return DOMAIN_PREFIX + payload


class SignedTransaction:
    """Strict signed-record parsing, serialization, and verification."""

    def __init__(
        self,
        sender: str,
        recipient: str,
        amount: int,
        nonce: int,
        chain_id: str,
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
        if not is_positive_amount(amount):
            raise InvalidTransactionError("amount must be a positive int")
        if not is_valid_nonce(nonce):
            raise InvalidTransactionError(
                f"nonce must be an int in [0, {MAX_NONCE}], got {nonce!r}"
            )
        if not is_valid_chain_id(chain_id):
            raise InvalidTransactionError(
                f"chain_id must match [a-z0-9][a-z0-9._-]{{0,63}}, got {chain_id!r}"
            )
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
        self._nonce = nonce
        self._chain_id = chain_id
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
    def nonce(self) -> int:
        return self._nonce

    @property
    def chain_id(self) -> str:
        return self._chain_id

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
        nonce: int,
        chain_id: str,
        public_key_bytes: bytes,
        signature_bytes: bytes,
    ) -> "SignedTransaction":
        return cls(
            sender,
            recipient,
            amount,
            nonce,
            chain_id,
            public_key_bytes,
            signature_bytes,
        )

    @classmethod
    def from_dict(cls, record: object) -> "SignedTransaction":
        """Strictly parse a serialized signed-transaction *record*.

        This is the single parsing entry point shared by the ledger (and any
        future stateful block validator) so record-parsing and canonical
        encoding rules live in one place instead of being duplicated.

        ``record`` must be a JSON object (dict) containing *exactly* the seven
        serialized fields::

            sender, recipient, amount, nonce, chain_id, public_key, signature

        ``public_key`` and ``signature`` are canonical UNPADDED base64url.
        Every other field is validated by the constructor. Any malformed input
        (wrong container, missing/extra keys, bad base64url, invalid address,
        non-positive amount, out-of-range nonce, or invalid chain id) raises
        ``InvalidTransactionError``. Sender/public-key correspondence is NOT
        checked here (that is a verification-time concern); a deliberately
        mismatched record parses successfully and is later rejected by
        :meth:`verify_strict`.
        """
        if not isinstance(record, dict):
            raise InvalidTransactionError(
                "signed transaction record must be a JSON object (dict), got "
                f"{type(record).__name__}"
            )
        required = {
            "sender",
            "recipient",
            "amount",
            "nonce",
            "chain_id",
            "public_key",
            "signature",
        }
        keys = set(record.keys())
        if any(not isinstance(key, str) for key in keys):
            raise InvalidTransactionError(
                f"record keys must all be strings, got keys {list(record.keys())!r}"
            )
        if keys != required:
            missing = sorted(required - keys)
            unexpected = sorted(keys - required)
            raise InvalidTransactionError(
                "record must contain exactly "
                f"{sorted(required)}; missing={missing}, unexpected={unexpected}"
            )
        public_key_bytes = decode_base64url(record["public_key"], 32)
        signature_bytes = decode_base64url(record["signature"], 64)
        return cls.from_fields(
            sender=record["sender"],
            recipient=record["recipient"],
            amount=record["amount"],
            nonce=record["nonce"],
            chain_id=record["chain_id"],
            public_key_bytes=public_key_bytes,
            signature_bytes=signature_bytes,
        )

    # ---- Payload and serialization -----------------------------------
    def payload_bytes(self) -> bytes:
        """Canonical JSON payload bytes (excludes the signature)."""
        return canonical_payload(
            sender=self._sender,
            recipient=self._recipient,
            amount=self._amount,
            nonce=self._nonce,
            chain_id=self._chain_id,
            public_key_bytes=self._public_key_bytes,
        )

    def signing_bytes(self) -> bytes:
        """Domain-separated message that is actually signed and verified."""
        return signing_bytes(self.payload_bytes())

    def to_dict(self) -> dict:
        return {
            "sender": self._sender,
            "recipient": self._recipient,
            "amount": self._amount,
            "nonce": self._nonce,
            "chain_id": self._chain_id,
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
        Any ``InvalidTransactionError`` or ``InvalidSignatureError`` is caught
        and reported as ``False``. Use :meth:`verify_strict` when the specific
        failure reason must be distinguished by exception type.
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

        Order of checks: first derive the address from the embedded public key
        and compare it to ``sender`` (authorization binding), then verify the
        Ed25519 signature over the domain-separated signing bytes using that
        key.
        """
        derived = hashlib.sha256(self._public_key_bytes).digest()[:20].hex()
        if derived != self._sender:
            raise InvalidTransactionError(
                "public key does not derive the claimed sender address"
            )
        try:
            Ed25519PublicKey.from_public_bytes(self._public_key_bytes).verify(
                self._signature_bytes, self.signing_bytes()
            )
        except InvalidSignature as exc:
            raise InvalidSignatureError("signature verification failed") from exc

    def __repr__(self) -> str:
        # Public fields only; the private key never appears.
        return (
            f"SignedTransaction(sender={self._sender!r}, "
            f"recipient={self._recipient!r}, amount={self._amount!r}, "
            f"nonce={self._nonce!r}, chain_id={self._chain_id!r})"
        )
