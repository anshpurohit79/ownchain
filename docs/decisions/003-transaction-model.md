# ADR 003: Transaction Model

- **Status:** Accepted
- **Date:** 2026-10-13
- **Scope:** `core/transaction.py` (`Transaction`) and `tests/test_transaction.py`.
  Uses the existing `Block` only at the point where `to_dict()` output is
  placed into `Block.transactions`.

## Context

A native-cryptocurrency project needs a structural transaction model that
can travel inside a `Block` and be hashed by the existing block
implementation. The model must be explicit about sender, recipient, and
amount; deterministic for hashing; and free of monetary ambiguity.

## Decision

### `Transaction` attributes and validation

- `sender` and `recipient` are **strings**, stored stripped of surrounding
  whitespace. Empty or whitespace-only values are rejected with `ValueError`.
  Self-transfers are structurally valid (see below).
- `amount` is a **positive integer in the smallest currency unit**. It must
  satisfy `type(amount) is int`; booleans, floats, strings, and other types
  are rejected with `ValueError`. Negative or zero amounts are rejected.
- Validation happens at construction time. Invalid input raises `ValueError`.

### Immutability

- `sender`, `recipient`, and `amount` are read-only public properties over
  private backing attributes (`_sender`, `_recipient`, `_amount`).
- Ordinary reassignment is prevented with `AttributeError`.
- No deep immutability machinery is added; this matches the milestone
  scope and keeps the API simple.

### Serialization

- `to_dict()` returns a **fresh**, JSON-compatible dictionary containing
  only `sender`, `recipient`, and the integer `amount`.
- `to_bytes()` uses deterministic JSON serialization: `sort_keys=True`,
  `separators=(',', ':')`, `allow_nan=False`, UTF-8 encoded bytes.
- **Only `to_dict()` output is stored in `Block.transactions`.** Transaction
  objects are never stored or hashed directly.

### Boundary between structural validity and later checks

Structural validation guarantees:
- Type and format correctness (strings, positive integer amounts).
- Determinism and JSON compatibility.

It does **not** guarantee payment security. In particular, the following are
*deliberately out of scope* and left to later milestones:
- Sufficient balance / insufficient-balance checks.
- Digital signatures and sender authorization.
- Replay protection and nonces/sequence numbers.
- Wallets and key management.
- Networking and consensus.

This boundary is a design statement, not a claim that structurally valid
transactions are safe to execute.

### Self-transfers

Self-transfers (`sender == recipient`) pass structural validation because
they are well-formed data. Whether a self-transfer is *allowed* is a business
policy rule, not a structural one, and is outside this milestone's scope.

## Consequences

- `Transaction` objects are value-like, immutable, and deterministic.
- `Block.transactions` can contain a list of `to_dict()` dicts, which the
  existing `Block.to_bytes()` hashes with sorted keys and compact separators.
- Tests can assert `Transaction(...).raises(ValueError)` cleanly because
  construction is the gate.

## Known limitations

- Amounts are integers only; no decimal/subunit handling or arithmetic.
- Identifiers are opaque strings; no schema, length, or format checks.
- No cross-transaction consistency (double-spend, balances, ordering) is
  enforced.
- Immutability is via read-only properties; a caller with a direct reference
  can still mutate nested objects in a stored dict (the same shallow-copy
  consideration noted in the Block ADR).
