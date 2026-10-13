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

from core.block import Block
from core.exceptions import (
    InsufficientFundsError,
    InvalidBlockError,
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

    __hash__ = None  # deliberately unhashable: no canonical state-hash format is defined yet

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

        An invalid or non-string *address* raises ``ValueError``.
        """
        self._check_address(address)
        return self._balances.get(address, 0)

    def next_nonce(self, address: str) -> int:
        """Return the next expected nonce for *address* (0 if absent).

        An invalid or non-string *address* raises ``ValueError``.
        """
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
    if balances[sender] == 0:
        # Preserve canonical working balances: an ordinary transfer that
        # reduces the sender to zero omits their entry entirely.
        del balances[sender]
    balances[recipient] = balances.get(recipient, 0) + amount


class Ledger:
    """Deterministic, replay-protecting account-based ledger.

    The trusted initial configuration is an explicit set of bootstrap balances
    plus a validated, frozen chain id. It is stored once and never mutated.
    """

    def __init__(
        self,
        initial_balances: Mapping[str, int],
        chain_id: str,
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
    # ------------------------------------------------------------------
    # Stateful block validation (milestone 7)
    # ------------------------------------------------------------------
    def _check_block_transition(self, block: Block, prev_block: Block) -> None:
        """Raise ``InvalidBlockError`` if *block* is not a valid continuation
        of *prev_block*, ignoring ledger state.

        Checks run cheapest and most structural first, so a malformed block
        never pays for hashing:

        1. Both indices must be genuine ints (``bool`` is an ``int`` subclass
           and ``1.0 == 1``, so equality-based checks are unsound). This also
           guarantees ``prev_block.index + 1`` is well-defined below.
        2. The candidate's transaction container must be a real ``list`` --
           checked BEFORE hashing so a generator (which ``Block.to_dict``
           materialises and exhausts) is rejected without being consumed.
        3. The candidate must not be genesis (index 0); genesis is built and
           validated only by ``Chain``.
        4. The candidate must pass its own hash verification. A
           ``TypeError``/``ValueError`` from the single ``verify()`` call
           (non-canonical serialization) is translated into
           ``InvalidBlockError`` with its cause preserved; any other exception
           propagates unchanged so genuine bugs are never masked.
        5. The candidate's index must be exactly ``prev_block.index + 1``.
        6. The candidate's ``prev_hash`` must equal the predecessor's STORED
           ``block_hash`` snapshot (the same link rule as ``Chain.validate``).

        The predecessor is a trusted, previously accepted block and is NOT
        re-verified here, matching how ``Chain.validate`` trusts earlier
        positions.
        """
        if not is_exact_int(block.index):
            raise InvalidBlockError(
                f"candidate block.index must be an int, got {block.index!r}"
            )
        if not is_exact_int(prev_block.index):
            raise InvalidBlockError(
                f"prev_block.index must be an int, got {prev_block.index!r}"
            )
        if type(block.transactions) is not list:
            raise InvalidBlockError(
                "candidate block.transactions must be a list, got "
                f"{type(block.transactions).__name__}"
            )
        if block.index == 0:
            raise InvalidBlockError(
                "genesis (index 0) must not be validated as a candidate block"
            )
        try:
            verified = block.verify()
        except (TypeError, ValueError) as exc:
            raise InvalidBlockError(
                "candidate block contents cannot be canonically serialized"
            ) from exc
        if not verified:
            raise InvalidBlockError(
                "candidate block fails its own hash verification"
            )
        if block.index != prev_block.index + 1:
            raise InvalidBlockError(
                f"candidate index {block.index} does not follow "
                f"predecessor index {prev_block.index}"
            )
        if block.prev_hash != prev_block.block_hash:
            raise InvalidBlockError(
                "candidate prev_hash does not match the predecessor's "
                "block_hash"
            )

    def _apply_block(
        self,
        block: Block,
        balances: Dict[str, int],
        next_nonces: Dict[str, int],
    ) -> None:
        """Apply *block*'s transactions in list order to the working mappings.

        The single transaction authority ``_process_transaction`` is reused
        verbatim; no transaction-validation rule is duplicated here. Because it
        mutates the supplied mappings in sequence, a later transaction observes
        an earlier successful one in the same block. Any failure propagates and
        the caller discards the mutated working mappings.
        """
        for record in block.transactions:
            _process_transaction(
                record, balances, next_nonces, self._chain_id
            )

    def apply_block(
        self,
        block: Block,
        prev_block: Block,
        prior_state: LedgerState,
    ) -> LedgerState:
        """Validate a candidate *block* against its predecessor and prior state.

        Runs the structural checks in ``_check_block_transition`` and then
        applies the block's transactions -- in list order, via the shared
        ``_process_transaction`` rule -- to a fresh copy of *prior_state*.
        Returns a NEW ``LedgerState`` only after every transaction succeeds.

        Atomicity: ``prior_state`` is only ever read (via its public
        iterators) and is never mutated, on success or failure. If any check or
        transaction fails the working copy is discarded, an exception is
        raised, and nothing is returned. This method does not append or accept
        the block into any ``Chain``; it only computes the next state.

        Precondition (trusted inputs): *prev_block* must be a previously
        accepted block and *prior_state* the ``LedgerState`` immediately
        following it. ``apply_block`` trusts both and cannot prove their
        history -- it does not re-derive *prior_state* from a chain, and a
        well-formed but wrong *prior_state* would yield a wrong (but
        structurally valid) result.

        Raises:
            TypeError: a wrong argument type was supplied.
            InvalidBlockError: the candidate is not a valid continuation of
                *prev_block* (see ``_check_block_transition``).
            InvalidTransactionError / InvalidSignatureError / WrongChainError /
                InvalidNonceError / InsufficientFundsError: a transaction in
                the block is invalid (propagated unchanged from
                ``_process_transaction``).
        """
        if not isinstance(block, Block):
            raise TypeError(
                f"block must be a Block, got {type(block).__name__}"
            )
        if not isinstance(prev_block, Block):
            raise TypeError(
                f"prev_block must be a Block, got {type(prev_block).__name__}"
            )
        if not isinstance(prior_state, LedgerState):
            raise TypeError(
                "prior_state must be a LedgerState, got "
                f"{type(prior_state).__name__}"
            )

        # All structural checks precede any state work.
        self._check_block_transition(block, prev_block)

        # Copy prior state via public read-only interfaces only. The iterators
        # omit zeros, reproducing exactly the canonical working form that
        # _process_transaction maintains; prior_state itself has no mutators.
        balances: Dict[str, int] = {
            addr: bal for addr, bal in prior_state.iter_balances()
        }
        next_nonces: Dict[str, int] = {
            addr: n for addr, n in prior_state.iter_next_nonces()
        }

        self._apply_block(block, balances, next_nonces)

        return LedgerState(balances, next_nonces)
