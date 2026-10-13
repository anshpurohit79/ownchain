"""Transaction component for the educational cryptocurrency project.

A Transaction represents a single, structurally valid transfer:

    {"amount": int, "recipient": str, "sender": str}

Validation is strict and happens at construction time. The object is then
immutable: the public attributes are read-only properties over private
backing fields. Only ``to_dict()`` output is ever placed into
``Block.transactions``; the Block hashes a list of such dicts via
its existing JSON serialization.

Security boundary (documented, not implemented here):
- Structural validation ensures types, non-empty identifiers, and positive
  integer amounts.
- It does NOT check balances, signatures, authorization, replay
  protection, wallets, or networking. Those are separate responsibilities.
"""

import hashlib
import json


class Transaction:
    """A structurally valid, immutable transfer between two party identifiers.

    Amount is a positive integer in the smallest currency unit (no floats,
    no booleans, no string coercions).
    """

    def __init__(self, sender, recipient, amount):
        # ---- Strict type checks BEFORE any normalization ----------------

        if not isinstance(sender, str):
            raise ValueError("sender must be a str")
        if not isinstance(recipient, str):
            raise ValueError("recipient must be a str")
        if type(amount) is not int:
            # bool is a subclass of int, so type() is used to reject it.
            raise ValueError("amount must be an int")

        # ---- Normalize and apply domain rules --------------------------

        sender = sender.strip()
        recipient = recipient.strip()
        if not sender:
            raise ValueError(
                "sender must not be empty or whitespace-only"
            )
        if not recipient:
            raise ValueError(
                "recipient must not be empty or whitespace-only"
            )
        if amount <= 0:
            raise ValueError("amount must be a positive integer")

        # ---- Store in private backing attributes -----------------------

        self._sender = sender
        self._recipient = recipient
        self._amount = amount

    # ---- Read-only public properties ----------------------------------

    @property
    def sender(self):
        """Sender identifier, stripped of surrounding whitespace."""
        return self._sender

    @property
    def recipient(self):
        """Recipient identifier, stripped of surrounding whitespace."""
        return self._recipient

    @property
    def amount(self):
        """Positive integer amount in the smallest currency unit."""
        return self._amount

    # ---- Serialization ------------------------------------------------

    def to_dict(self):
        """Return a fresh, JSON-compatible dict for this transaction."""
        return {
            "amount": self._amount,
            "recipient": self._recipient,
            "sender": self._sender,
        }

    def to_bytes(self):
        """Return deterministic JSON bytes for this transaction."""
        text = json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        return text.encode("utf-8")

    # ---- Equality & representation -------------------------------------

    def __eq__(self, other):
        if not isinstance(other, Transaction):
            return NotImplemented
        return (
            self.sender == other.sender
            and self.recipient == other.recipient
            and self.amount == other.amount
        )

    def __repr__(self):
        return (
            f"{type(self).__name__}(sender={self.sender!r}, "
            f"recipient={self.recipient!r}, amount={self.amount!r})"
        )
