# ADR 002: Chain Integrity

- **Status:** Accepted
- **Date:** 2026-10-12
- **Scope:** `core/chain.py` (`Chain` class) and `tests/test_chain.py`
  (`Chain` unit tests). Uses the existing `Block` / `genesis_block()` from
  milestone 1.

## Context

A chain is an ordered, hash-linked list of `Block` objects. Mirana checks
validate the following invariants, which we implement as ordinary boolean
rules inside `Chain.validate()`:

1. **Genesis rules**: first block matches the fixed genesis spec
   (`index=0`, `timestamp="2021-01-01T00:00:00Z"`,
   `prev_hash="0"*64`, `transactions=[]`), and the genesis block itself
   verifies.
2. **Sequential indices**: `blocks[i].index == i` for every `i`.
3. **Self-verification**: `blocks[i].verify()` is `True` for every `i`.
4. **Hash links**: for every `i >= 1`, `blocks[i].prev_hash ==
   blocks[i-1].block_hash`, where the previous value is the **stored**
   `block_hash` snapshot.

The chain does not recompute or overwrite stored hashes; it compares stored
values against stored values (plus freshly computed per-block hashes only in
tests).

## Decision

### `Chain.__init__(genesis)`

- Stores the supplied genesis `Block` **by reference** in a private list.
- Immediately validates the genesis against the fixed spec and rejects with
  `ValueError` if:
  - `index != 0`, OR
  - `timestamp` is not the fixed genesis timestamp, OR
  - `prev_hash != "0" * 64`, OR
  - `transactions != []`, OR
  - `genesis.verify()` is `False`.

A genesis whose fields are correct but whose stored hash is corrupted fails
`verify()` and is therefore rejected, because the spec demands the genesis
block is self-consistent.

### `Chain.append(timestamp, transactions)`

- Uses `len(self._blocks)` as the next block's index, after the existing
  chain passes `validate()`.
- Computes `new.prev_hash = last.block_hash`, i.e. the previous block's
  **stored** hash snapshot, not a freshly recomputed value.
- Constructs the new `Block` (which shallow-copies the outer `transactions`
  list) and appends it to the internal list.
- If the existing chain fails `validate()`, raises `RuntimeError` with the
  documented message "cannot append to an invalid chain".

### `Chain.validate()`

- Returns `bool` only. It does not track or expose detailed error values.
- Reads the fixed genesis constants from `core.block` to avoid duplication.

### `Chain.blocks` property

- Returns `tuple(self._blocks)`.
- The tuple protects the collection structure (no resizes/reorders from the
  outside). It does **not** protect the `Block` objects inside, which remain
  mutable.
- The internal list is never shared with the caller.

## Known limitations

- Shallow `transactions` copy: `Block.__init__` copies the outer list but
  not nested objects. A caller mutating a nested dict through the original
  list **can** change the block's data. Outer-list add/remove isolation is
  tested and works; nested mutation is documented as out of scope.
- `Chain.__init__` retains the genesis object by reference. Passing a block
  created by the caller and then mutating it outside the chain affects the
  chain's stored reference.
- Chain validation is structural, not consensus-level trust. Rewriting a
  single block's contents and its subsequent `prev_hash` links would still
  break later validation, but an attacker who rewrites both contents and all
  dependent hashes passes. Real protection requires mining/consensus in a
  later milestone.
- Fixed genesis timestamp aids reproducibility but is not "real time."
