# ADR 001: Block Hashing

- **Status:** Accepted
- **Date:** 2026-10-12
- **Scope:** `core/block.py` (Block only; no chain, mining, wallets, networking)

## Context

A beginner-friendly blockchain needs a way to fingerprint a block's
contents so that later edits are detectable. Requirements for milestone 1:

- Standard library only (`json` + `hashlib`, SHA-256).
- Deterministic serialization: same contents always hash the same way.
- The stored hash must not be part of its own hash input (circular).
- Reproducible genesis block for tests.
- Tamper detection by comparing stored hash vs. recalculated hash.

## Decision

1. **Hashed payload is exactly four fields:** `index`, `timestamp`,
   `prev_hash`, `transactions`, via `to_dict()`. `block_hash` is excluded.
2. **Serialization:** `json.dumps(..., sort_keys=True,
   separators=(",", ":"), allow_nan=False).encode("utf-8")`.
   Sorted keys plus compact separators remove whitespace and ordering
   ambiguity; `allow_nan=False` rejects Python `NaN`/`Infinity`, which are
   not valid JSON and would serialize inconsistently.
3. **Hash function:** SHA-256 hex digest of those bytes
   (`hashlib.sha256(...).hexdigest()`).
4. **Stored snapshot:** `block_hash` is a plain instance attribute assigned
   once in `__init__` from `calculate_hash()`. `calculate_hash()` recomputes
   from current contents on demand; `verify()` returns
   `self.block_hash == self.calculate_hash()`.

## Why snapshot + recompute (key design change)

An earlier sketch made `block_hash` a recalculating property. That can never
detect tampering: after an edit, both sides of the comparison would reflect
the new contents and always agree. Freezing the snapshot at construction and
recomputing fresh in `verify()` is what makes the mismatch visible.

## Consequences

- Deterministic within our constrained Python implementation: identical
  blocks hash identically; mutating any one field changes the hash and makes
  `verify()` return `False`.
- Reproducible tests via fixed genesis values
  (`index=0`, `timestamp="2021-01-01T00:00:00Z"`,
  `prev_hash="0"*64`, `transactions=[]`).
- No dependencies beyond the standard library; `unittest` for tests.

## Corrections and limitations

1. **`block_hash` is a reassignable snapshot, not immutable.** A plain
   Python attribute can be overwritten. The verification guarantee holds
   only assuming the stored snapshot itself was not also modified: an
   attacker who rewrites both contents and snapshot passes `verify()`.
   Real protection against that comes later by chaining `prev_hash` across
   blocks, so rewriting one block breaks every later link.
2. **Deterministic for our constrained implementation, not universally
   canonical.** The `sort_keys` + compact-separator + UTF-8 recipe is
   reproducible for JSON-compatible data inside this codebase. It is not a
   cross-language canonical form (e.g. JCS / RFC 8785): float formatting,
   Unicode escaping, and type mappings can differ in other languages or JSON
   libraries. We stay inside the safe subset (dicts, lists, strings,
   numbers, booleans, `None`; `allow_nan=False`) and do not claim more.
3. **Shallow copy of `transactions`:** `list(...)` guards the outer list
   against caller aliasing but not nested dicts. Accepted for this
   milestone; a deep copy or immutable transaction type is future work.
4. **Fixed genesis timestamp** aids reproducibility but is not "real time".
5. **Out of scope:** mining / proof-of-work, wallets, networking,
   consensus, transaction validation. `Block` is one hash-linked unit only.
