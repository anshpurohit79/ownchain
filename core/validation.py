"""Shared validation primitives for the educational cryptocurrency.

This module is the single source of truth for the structural rules that more
than one component needs (addresses, integer amounts, nonces, chain ids, and
the signing domain prefix). Keeping them here avoids divergent copies of the
same rule in different modules.

Exception ownership
-------------------
- The predicates here are pure boolean checks and never raise.
- Programmer misuse of a constructor (a wrong Python type) should raise a
  built-in ``TypeError``/``ValueError`` at the call site that chooses to.
- Malformed *serialized* transaction data raises ``InvalidTransactionError``
  (raised by ``core.signed_transaction`` when a predicate returns ``False``).
- ``InvalidNonceError`` and ``WrongChainError`` are defined in
  ``core.exceptions`` and re-exported here for the later ledger stage.
"""

from core.exceptions import InvalidNonceError, WrongChainError

__all__ = [
    "MAX_NONCE",
    "MAX_NEXT_NONCE",
    "DEFAULT_CHAIN_ID",
    "DOMAIN_PREFIX",
    "is_valid_address",
    "is_exact_int",
    "is_positive_amount",
    "is_valid_nonce",
    "is_valid_chain_id",
    "InvalidNonceError",
    "WrongChainError",
]

# ---- Nonce bounds -------------------------------------------------------
# A transaction nonce is an unsigned 64-bit integer. A real transaction nonce
# may not equal the maximum; ``MAX_NEXT_NONCE`` is the inclusive upper bound
# used when computing the *expected next* nonce after replaying a transaction.
MAX_NONCE = 2**64 - 2
MAX_NEXT_NONCE = 2**64 - 1

# ---- Chain identity -----------------------------------------------------
# Default development chain id. A chain id is bound into every signature so a
# record signed for one chain cannot be replayed on another.
DEFAULT_CHAIN_ID = "ownchain-devnet-1"

# ---- Domain separation --------------------------------------------------
# Prepended to the canonical payload before signing so bytes signed as an
# OwnChain transaction can never be re-interpreted as some other message by
# the same key. The ASCII prefix is terminated by exactly one NUL byte.
DOMAIN_PREFIX = b"OWNCHAIN:SIGNED-TRANSACTION:V1\x00"

_HEX_LOWER = frozenset("0123456789abcdef")
_CHAIN_ID_FIRST = frozenset("abcdefghijklmnopqrstuvwxyz0123456789")
_CHAIN_ID_REST = frozenset("abcdefghijklmnopqrstuvwxyz0123456789._-")


def is_valid_address(value: object) -> bool:
    """True iff *value* is exactly 40 lowercase hexadecimal characters."""
    if not isinstance(value, str) or len(value) != 40:
        return False
    return all(c in _HEX_LOWER for c in value)


def is_exact_int(value: object) -> bool:
    """True iff *value* is a real ``int`` and not a ``bool``.

    ``bool`` is a subclass of ``int`` in Python, so a bare ``isinstance``
    check would wrongly accept ``True``/``False``. Amounts and nonces must be
    genuine integers.
    """
    return type(value) is int


def is_positive_amount(value: object) -> bool:
    """True iff *value* is an exact positive integer amount."""
    return is_exact_int(value) and value > 0


def is_valid_nonce(value: object) -> bool:
    """True iff *value* is an integer nonce in ``[0, MAX_NONCE]``."""
    return is_exact_int(value) and 0 <= value <= MAX_NONCE


def is_valid_chain_id(value: object) -> bool:
    """True iff *value* matches the chain-id grammar ``[a-z0-9][a-z0-9._-]{0,63}``.

    A chain id is 1..64 ASCII characters; the first is ``[a-z0-9]`` and the
    remaining 0..63 are ``[a-z0-9._-]``.
    """
    if not isinstance(value, str) or not (1 <= len(value) <= 64):
        return False
    if value[0] not in _CHAIN_ID_FIRST:
        return False
    return all(c in _CHAIN_ID_REST for c in value)
