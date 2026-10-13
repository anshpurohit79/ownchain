# ADR 004: Account-Based Ledger and Balance Validation

- **Status:** Accepted
- **Date:** 2026-10-13
- **Scope:** `core/ledger.py` (`Ledger`) and `tests/test_ledger.py`.
  Uses `core.block.Block`, `core.chain.Chain`, and `core.transaction.Transaction`.

## Context

This milestone adds a deterministic, account-based balance ledger for the
educational cryptocurrency project. Transactions are already stored inside a
`Chain` using the existing `Transaction` model. The ledger computes final
balances from a bootstrap state and a valid chain, while enforcing money
movement rules such as sufficiency of funds and non-negative balances.

## Decision

### Bootstrap state and initialization

- `Ledger.__init__(initial_balances)` accepts a caller-supplied mapping of
  account name to non-negative integer balance.
- Bootstrap balances are treated as **trusted external state**. They are not
  issued by the chain, and no issuance or mining mechanism is implemented in
  this milestone.
- Account names are normalized with `str.strip()`. Empty names and duplicate
  normalized names are rejected with `ValueError`.
- Balances must satisfy `type(balance) is int` and be `>= 0`. Booleans and
  floats are rejected with `TypeError`; negative balances with `ValueError`.

### State-reset and repeatability contract

- The ledger keeps one private snapshot of the original bootstrap balances in
  `_initial_balances` and never mutates it.
- Every call to `Ledger.replay(chain)` starts from a **fresh working copy** of
  those original balances.
- On success, `replay()` returns a separate balance dictionary snapshot.
- On failure, the working dictionary is discarded and the original snapshot is
  untouched.
- Repeating a replay has no cumulative side effects. Two successful replays on
  the same `Ledger` instance return identical balances. A failed replay does
  not contaminate a later successful replay.

### Chain and transaction validation

- `replay()` first checks `chain.validate()` and raises `InvalidChainError`
  if the chain is invalid.
- Transactions are processed in `Chain.blocks` order and, within each block,
  in `block.transactions` list order.
- Each stored transaction dictionary is reconstructed against the existing
  `Transaction` model. Reconstruction is strict: a transaction must be a dict
  with exactly the keys `sender`, `recipient`, and `amount`, and the values
  must satisfy the existing `Transaction` string/amount rules.
- Malformed transaction dictionaries raise `InvalidTransactionError`.
- Sufficient funds are checked before each transfer, and balances are checked
  to remain non-negative. A failed transfer changes no balances within that
  replay.

### Transfer rules

- A transfer from `sender` to `recipient` of `amount` reduces `sender` by
  `amount` and increases `recipient` by `amount`.
- An unknown sender behaves as if it has zero funds and cannot make a positive
  transfer.
- A previously unknown recipient may receive funds and becomes a new account.
- Account names are case-sensitive.
- A self-transfer (`sender == recipient`) requires sufficient funds but leaves
  the sender's balance unchanged.

### Failure semantics

- `InvalidChainError` for an invalid chain.
- `InvalidTransactionError` for malformed transaction dictionaries.
- `InsufficientFundsError` for insufficient funds or a resulting negative
  balance.
- All three leave the ledger's bootstrap state untouched.

### Security boundary

This milestone does **not** implement:
- signatures, sender authorization, or key management;
- transaction fees or mining / proof-of-work;
- issuance, wallets, networking, or consensus.

A `sender` string alone does not prove ownership. External bootstrap balances
determine state beyond what the chain alone determines, so this ledger is a
deterministic money-movement simulation over a trusted starting point, not a
secure cryptocurrency implementation.

## Consequences

- The ledger is deterministic and repeatable for a fixed valid chain and
  bootstrap state.
- Failed replays are always atomic with respect to balances and cannot
  contaminate later replays.
- The public API returns a plain `dict` snapshot; internal balances are never
  exposed directly.
- The existing `Block`, `Chain`, and `Transaction` files are not modified.
