"""Account-based ledger: deterministic replay with replay protection.

This module processes transactions already stored in blocks that passed
``Chain.validate()`` and produces the final account state as a ``LedgerState``
value object. It is pure with respect to its trusted configuration: the
original bootstrap balances and chain id are stored once and never mutated;
every ``replay()`` starts from a fresh working copy.

Determinism and state-reset contract
-----------------------------------
- ``Ledger`` stores one private copy of the original bootstrap balances and the
  configured chain id. Neither is ever mutated.
- Every call to ``replay()`` starts from a *fresh working copy* of those
  balances and an empty next-nonce mapping.
- ``replay()`` returns a *new* ``LedgerState`` only when the whole replay
  succeeds. On any failure it raises and returns nothing; the original
  configuration and any previously returned state remain unchanged.
- Replaying the same valid chain with the same configuration on the same
  instance always produces an equal ``LedgerState``.

Scope and security boundary
--------------------------
This component does NOT implement signatures itself (it *verifies* them via
``SignedTransaction.verify_strict``), fees, mining, issuance, networking, or
consensus. It enforces nonce continuity and chain binding to provide replay
protection *within this prototype*, but it does not include nonce-state
persistence, network-level deduplication, or consensus-level finality.

Structural validity of a ``LedgerState`` does NOT prove that a chain produced
it; only a full replay of a valid chain against a trusted configuration can.

Security exclusions (Milestone 6)
---------------------------------
Implemented here: replay protection via per-account nonce sequencing and
chain-id binding.
Still out of scope: transaction nonces persisted across process restarts,
encrypted wallet files, recovery phrases, a finished issuance/reward
mechanism, fees, mining, peer-to-peer networking, consensus, and real-funds
use. Without persisted nonce state a signed transaction could still be
re-introduced into a *fresh* ledger; this prototype demonstrates the ordering
rule, not durable global replay protection.
"""

from typing import Dict, Iterator, Mapping, Optional, Tuple

from core.exceptions import (
    InsufficientFundsError,
    InvalidChainError,
    InvalidNonceError,
    InvalidSignatureError,
    InvalidTransactionError,
    WrongChainError,
)
from core.signed_transaction import SignedTransaction
from core.validation import (
    MAX_NEXT_NONCE,
    is_exact_int,
    is_valid_address,
    is_valid_chain_id,
    is_valid_nonce,
)


class LedgerState:
    """Immutable snapshot of account balances and next-expected nonces.

    A value object produced by a successful replay. It owns defensive copies of
    both input mappings and exposes only read-only accessors; it never hands
    back a mutable internal dictionary.

    Structural validity of a ``LedgerState`` does not prove a chain produced it;
    it is only a well-formed snapshot of the outcome of some replay.
    """

    __hash__ = None  # mutable-content value object: deliberately unhashable

    def __init__(
        self,
        balances: Mapping[str, int],
        next_nonces: Mapping[str, int],
    ):
        self._balances = self._normalize_balances(balances)
        self._next_nonces = self._normalize_nonces(next_nonces)

    # ---- Validation / normalization --------------------------------------
    @staticmethod
    def _require_mapping(value: object, name: str) -> None:
        if not isinstance(value, Mapping):
            raise TypeError(
                f"{name} must be a mapping, got {type(value).__name__}"
            )

    @classmethod
    def _normalize_balances(cls, balances: Mapping[str, int]) -> Dict[str, int]:
        cls._require_mapping(balances, "balances")
        out: Dict[str, int] = {}
        for raw_addr, raw_value in balances.items():
            if not is_valid_address(raw_addr):
                raise ValueError(
                    f"balance key must be a 40-char lowercase hex address, "
                    f"got {raw_addr!r}"
                )
            if not is_exact_int(raw_value):
                raise TypeError(
                    f"balance for {raw_addr!r} must be an int, got "
                    f"{type(raw_value).__name__}"
                )
            if raw_value < 0:
                raise ValueError(
                    f"balance for {raw_addr!r} must be non-negative"
                )
            if raw_value != 0:
                out[raw_addr] = raw_value
        return out

    @classmethod
    def _normalize_nonces(cls, next_nonces: Mapping[str, int]) -> Dict[str, int]:
        cls._require_mapping(next_nonces, "next_nonces")
        out: Dict[str, int] = {}
        for raw_addr, raw_value in next_nonces.items():
            if not is_valid_address(raw_addr):
                raise ValueError(
                    f"next-nonce key must be a 40-char lowercase hex address, "
                    f"got {raw_addr!r}"
                )
            if not is_exact_int(raw_value):
                raise TypeError(
                    f"next nonce for {raw_addr!r} must be an int, got "
                    f"{type(raw_value).__name__}"
                )
            if not (0 <= raw_value <= MAX_NEXT_NONCE):
                raise ValueError(
                    f"next nonce for {raw_addr!r} must be in "
                    f"[0, {MAX_NEXT_NONCE}], got {raw_value}"
                )
            if raw_value != 0:
                out[raw_addr] = raw_value
        return out

    # ---- Read-only public API -------------------------------------------
    def _check_address(self, address: object) -> str:
        if not is_valid_address(address):
            raise ValueError(
                f"lookup address must be a 40-char lowercase hex address, "
                f"got {address!r}"
            )
        return address

    def balance(self, address: str) -> int:
        """Return the balance for *address* (0 if absent).

        An invalid address argument raises ``ValueError``; a non-string raises
        ``TypeError`` implicitly via ``is_valid_address`` returning False and
        the explicit ``ValueError`` below.
        """
        self._check_address(address)
        return self._balances.get(address, 0)

    def next_nonce(self, address: str) -> int:
        """Return the next expected nonce for *address* (0 if absent)."""
        self._check_address(address)
        return self._next_nonces.get(address, 0)

    def iter_balances(self) -> Iterator[Tuple[str, int]]:
        """Yield ``(address, balance)`` pairs sorted by address."""
        for address in sorted(self._balances):
            yield address, self._balances[address]

    def iter_next_nonces(self) -> Iterator[Tuple[str, int]]:
        """Yield ``(address, next_nonce)`` pairs sorted by address."""
        for address in sorted(self._next_nonces):
            yield address, self._next_nonces[address]

    # ---- Equality -------------------------------------------------------
    def _canonical(self) -> Tuple[Tuple[str, int], Tuple[str, int]]:
        return (
            tuple(sorted(self._balances.items())),
            tuple(sorted(self._next_nonces.items())),
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, LedgerState):
            return NotImplemented
        return self._canonical() == other._canonical()

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __repr__(self) -> str:
        balances = dict(self._balances)
        nonces = dict(self._next_nonces)
        return f"LedgerState(balances={balances!r}, next_nonces={nonces!r})"


def _process_transaction(
    record: object,
    balances: Dict[str, int],
    next_nonces: Dict[str, int],
    chain_id: str,
) -> None:
    """Validate and apply one signed-transaction *record* to the working state.

    This is the single shared transaction-processing rule. It is deliberately
    kept as a free function operating on the supplied mutable working mappings
    so Milestone 7's stateful block validator can reuse it directly.

    Order of checks (exception ownership is exact and preserved):

    1. Strictly reconstruct the record via ``SignedTransaction.from_dict`` ->
       ``InvalidTransactionError`` on any malformed data.
    2. ``verify_strict()`` -> ``InvalidTransactionError`` on a sender/public-key
       address mismatch, or ``InvalidSignatureError`` on a bad signature.
    3. Compare ``signed.chain_id`` to the configured *chain_id* ->
       ``WrongChainError`` on mismatch. (Signature verification precedes this
       deliberately, so error semantics stay precise; Milestone 7 may add a
       cheap precheck for network traffic.)
    4. Require ``signed.nonce == next_nonces.get(sender, 0)`` ->
       ``InvalidNonceError`` on stale/duplicate/skipped/out-of-order nonces.
    5. Check sufficient funds -> ``InsufficientFundsError`` if the sender
       cannot pay.

    Only after ALL checks pass are the working mappings mutated, so any failure
    leaves both ``balances`` and ``next_nonces`` unchanged.
    """
    signed = SignedTransaction.from_dict(record)
    signed.verify_strict()

    if signed.chain_id != chain_id:
        raise WrongChainError(
            f"transaction chain_id {signed.chain_id!r} != configured {chain_id!r}"
        )

    sender = signed.sender
    recipient = signed.recipient
    amount = signed.amount
    nonce = signed.nonce

    expected = next_nonces.get(sender, 0)
    if nonce != expected:
        raise InvalidNonceError(
            f"nonce {nonce} is not the expected next nonce {expected} "
            f"for sender {sender!r}"
        )

    balance = balances.get(sender, 0)
    if balance < amount:
        raise InsufficientFundsError(
            f"insufficient funds for sender {sender!r}: have {balance}, "
            f"need {amount}"
        )

    # ---- All checks passed: now mutate the working mappings. -------------
    next_nonces[sender] = nonce + 1
    if sender == recipient:
        # Self-transfer: sufficient funds required, but the balance is
        # unchanged. The nonce above is still consumed exactly once. A
        # zero balance must NOT be deleted here; leave balances[sender] as-is.
        return
    balances[sender] = balance - amount
    balances[recipient] = balances.get(recipient, 0) + amount


class Ledger:
    """Deterministic, replay-protecting account-based ledger.

    The trusted initial configuration is an explicit set of bootstrap balances
    plus a validated, frozen chain id. It is stored once and never mutated.
    """

    def __init__(
        self,
        initial_balances: Mapping[str, int],
        chain_id: str = "ownchain-devnet-1",
    ):
        if not isinstance(initial_balances, Mapping):
            raise TypeError(
                "initial_balances must be a mapping of account address to "
                "non-negative integer balance, got "
                f"{type(initial_balances).__name__}"
            )
        if not is_valid_chain_id(chain_id):
            raise ValueError(
                f"chain_id must match [a-z0-9][a-z0-9._-]{{0,63}}, got "
                f"{chain_id!r}"
            )

        # Bootstrap addresses are NOT stripped or normalized; they must be
        # valid exactly as supplied. Zero balances are omitted. Validation is
        # delegated to LedgerState so the rules live in one place.
        bootstrap = LedgerState(initial_balances, {})
        self._initial_balances: Dict[str, int] = dict(bootstrap._balances)
        self._chain_id: str = chain_id

    @property
    def chain_id(self) -> str:
        return self._chain_id

    def replay(self, chain) -> LedgerState:
        """Replay *chain* from the bootstrap snapshot and return a LedgerState.

        Raises:
            InvalidChainError: the chain fails ``Chain.validate()``.
            InvalidTransactionError / InvalidSignatureError: malformed or
                cryptographically invalid transaction records.
            WrongChainError: a transaction was signed for a different chain id.
            InvalidNonceError: a nonce violates account continuity.
            InsufficientFundsError: a sender cannot pay.

        On any failure nothing is returned and the working state is discarded;
        the original configuration and any previously returned state are
        unchanged.
        """
        if not chain.validate():
            raise InvalidChainError(
                "cannot replay an invalid Chain (Chain.validate() returned False)"
            )

        # Fresh working copies on every call: balances seeded from the
        # bootstrap snapshot, next-nonces starting empty.
        balances: Dict[str, int] = dict(self._initial_balances)
        next_nonces: Dict[str, int] = {}

        for block in chain.blocks:
            for record in block.transactions:
                _process_transaction(
                    record, balances, next_nonces, self._chain_id
                )

        return LedgerState(balances, next_nonces)
