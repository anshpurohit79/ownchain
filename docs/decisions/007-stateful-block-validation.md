# ADR 007: Stateful Block Validation

- **Status:** Accepted
- **Date:** 2026-10-13
- **Milestone:** 7
- **Scope:** `core/ledger.py` (the `Ledger.apply_block` entry point and its private helpers, plus the replay delegation), `core/exceptions.py` (the `InvalidBlockError` type), `core/chain.py` (the hardened structural checks reused by block validation), `tests/test_ledger.py` and `tests/test_chain.py`, and project documentation.
- **Implementation status:** Fully implemented. `Ledger.apply_block(block, prev_block, prior_state) -> LedgerState` validates a single candidate block against its predecessor and prior state, applies the block's transactions through the shared `_process_transaction` authority, and returns a new `LedgerState` only after every check and transaction succeeds. `Ledger.replay()` now delegates each non-genesis block through `apply_block()`. The design is covered by the test suite (see §Test coverage). This prototype is **not** production-ready and provides no consensus, fork choice, issuance, mining, networking, persistence, or timestamp-ordering policy (see §Consequences and limitations).

## 1. Context

Milestone 6 established pure, deterministic replay: `Ledger.replay(chain)` rebuilds an immutable `LedgerState` from a chain that already passed `Chain.validate()`, enforcing per-account nonce continuity and chain-ID binding through a single shared function, `_process_transaction`. That function was deliberately written as a free function operating on plain working dictionaries precisely so a future stateful block validator could reuse it (ADR 006 §8).

Two gaps remain:

- `Chain.validate()` answers only a **structural** question about a whole chain and returns a `bool`. It cannot express "is *this* detached candidate block a valid continuation of *that specific* predecessor, and what account state results?"
- Replay recomputes the state only for a complete chain. There is no way to validate one candidate block against a caller-supplied prior state and obtain the resulting next state without touching a `Chain`.

ADR 006 §11 explicitly deferred "a dedicated stateful block-validation entry point" to Milestone 7, and promised it "will validate a candidate block against a supplied prior state using the same transaction-processing function." This ADR records that decision as implemented.

The driving requirement is stated as a question: given a previously accepted block and the ledger state immediately before a candidate block, can the candidate be validated and the next ledger state obtained **without mutating the previous state if validation fails**? The answer, as built, is yes.

## 2. Decision: API and ownership

The implemented entry point is a method on `Ledger`:

```python
def apply_block(
    self,
    block: Block,
    prev_block: Block,
    prior_state: LedgerState,
) -> LedgerState:
```

### Why it lives on `Ledger`

- **Chain identity is owned by `Ledger`.** Stateful validation must reject transactions signed for a different chain id, and that configured id (`self._chain_id`) is stored once, frozen, on the `Ledger`. A free function taking a `chain_id` argument would create a second call site that can disagree with `replay()` about chain identity.
- **The transaction authority is private to `core.ledger`.** `_process_transaction` — the mandated single authority for signed-transaction validation and state mutation — is a module-private function. Placing `apply_block` in the same module reuses it without widening a private symbol's visibility or creating a new module boundary.
- **`replay()` must reuse it.** Co-locating the two makes the M7.4 delegation a small, reviewable change (see §Replay delegation) rather than a cross-module refactor.

### Method naming

The name is `apply_block`, not `validate_block`, because the repo already establishes a convention that `validate*` / `verify` methods return a `bool` (`Chain.validate() -> bool`, `Block.verify() -> bool`). `apply_block` returns a `LedgerState`, and the verb "apply … to a copy of the state and return the result" matches the operation without colliding with that boolean convention. It is also distinct from `Chain.append()`, which mutates the chain; `apply_block` mutates nothing and appends nothing.

### Copying the prior state through public interfaces only

`LedgerState` exposes no mutable dictionary and has no mutators at all, so the supplied `prior_state` cannot be modified by construction. `apply_block` therefore copies state exclusively through its public read-only iterators:

```python
balances    = {addr: bal for addr, bal in prior_state.iter_balances()}
next_nonces = {addr: n   for addr, n   in prior_state.iter_next_nonces()}
```

The iterators already omit zero-valued entries, reproducing exactly the canonical working form that `_process_transaction` maintains. No private attribute is read.


## 3. Decision: structural validation order

`apply_block` first type-checks its arguments (a wrong object type is programmer misuse and raises the built-in `TypeError`), then runs `_check_block_transition`, which performs all structural checks **before** any state is copied or processed. The validation sequence is fixed. Argument types are checked first; then `_check_block_transition` runs the cheapest structural checks — the exact-integer index domain, the plain-list transaction container, and genesis-candidate rejection (steps 2–4) — before hashing. A candidate caught by these checks never pays for `Block.verify()`. Hash integrity is checked next (step 5), followed by index continuity and previous-hash linkage (steps 6–7), so a candidate whose own hash is valid but whose index or link is wrong is still hashed before rejection:

1. **Argument types.** `block` must be a `Block`, `prev_block` a `Block`, `prior_state` a `LedgerState`; otherwise `TypeError`.
2. **Exact-integer indices.** `is_exact_int(block.index)` and `is_exact_int(prev_block.index)` must both hold, else `InvalidBlockError`. Because `bool` is a subclass of `int` and `1.0 == 1`, an equality-based index check is unsound; `prev_block.index` is checked too so that the `prev_block.index + 1` computed later is well-defined and a boolean predecessor index (`True + 1 == 2`) can never masquerade as a valid one.
3. **Plain-list transaction container.** `type(block.transactions) is list` must hold, else `InvalidBlockError`. This runs **before** `Block.verify()` (see §5).
4. **Genesis-candidate rejection.** A candidate with `index == 0` is rejected as `InvalidBlockError`; genesis is built and validated only by `Chain` (see §6).
5. **Candidate hash integrity.** `block.verify()` must be `True`. A `TypeError`/`ValueError` from the single `verify()` call (non-canonical serialization of mutated contents) is translated into `InvalidBlockError` with its cause preserved (`raise ... from exc`); any other exception propagates unchanged so genuine bugs are never masked (see §9).
6. **Index continuity.** `block.index == prev_block.index + 1`, else `InvalidBlockError`. This single rule rejects wrong, skipped, and duplicate indices.
7. **Previous-hash linkage.** `block.prev_hash == prev_block.block_hash`, using the predecessor's **stored** snapshot, else `InvalidBlockError`. This is the same link rule as `Chain.validate()`.

The predecessor is a trusted, previously accepted block and is **not** re-verified here, matching how `Chain.validate()` trusts earlier positions. No `Chain` object is touched.

## 4. Decision: state transition

After the structural checks pass, `apply_block` copies the prior state into fresh dictionaries and hands them to the private `_apply_block`, which processes transactions in **block-list order**:

```python
for record in block.transactions:
    _process_transaction(record, balances, next_nonces, self._chain_id)
```

`_process_transaction` is the sole transaction authority. No transaction-validation rule (signature, sender authorization, chain id, nonce continuity, sufficient funds, full-balance and self-transfer handling) is duplicated. Because it mutates the shared working dictionaries in sequence, a later transaction in the same block observes an earlier successful one. A new `LedgerState(balances, next_nonces)` is constructed and returned only after the loop completes; on any raised exception the working dictionaries are discarded and nothing is returned.

## 5. Decision: container integrity

`Block.__init__` normalizes its `transactions` argument with `list(...)`, but `Block.transactions` remains publicly mutable after construction, and `Block.to_dict()` calls `list(self.transactions)` during hashing. If a caller replaces the container with a generator yielding the original transactions, `block.verify()` reproduces the original hash **while consuming the generator**, and a later transaction loop would then silently process zero transactions.

The container check therefore must run **before** `block.verify()`:

```python
if type(block.transactions) is not list:
    raise InvalidBlockError(...)
```

`type(x) is list` never iterates, so a generator is rejected while intact and is never consumed. The check is deliberately strict: a `list` **subclass** is also rejected, because the rule is to accept exactly what `Block.__init__` produces and nothing else. `Chain.validate()` and `Chain._validate_genesis` enforce the same container rule (M7.0), so the two layers reject the identical hazard consistently — a generator substituted anywhere in a chain is refused as a chain-integrity failure and never reaches block application with its transactions silently skipped.


## 6. Decision: genesis handling

- Genesis is **never a candidate**. Submitting a genesis block to `apply_block` is rejected by rule 4 of §3. Genesis is constructed and validated in exactly one place, `Chain`, and no genesis constant is copied a third time into the ledger.
- Genesis is **only ever a predecessor**. The first real candidate (index 1) links to genesis through genesis's stored `block_hash`, which is the normal path.
- **Replay begins from bootstrap balances** because valid genesis is structurally required to carry an empty transaction list; the state immediately after genesis is therefore `LedgerState(bootstrap_balances, {})`, which is exactly how `replay()` seeds itself before folding block 1 onward (see §7).

## 7. Replay delegation

`Ledger.replay()` was refactored in this milestone to reuse `apply_block` over the non-genesis blocks, keeping replay deterministic and giving it a single source of truth for block validation:

```python
if not chain.validate():
    raise InvalidChainError(...)
state = LedgerState(dict(self._initial_balances), {})   # == state after genesis
prev_block = blocks[0]
for block in blocks[1:]:
    state = self.apply_block(block, prev_block, state)
    prev_block = block
return state
```

The whole-chain `Chain.validate()` gate is preserved, so `InvalidChainError` still signals a structurally invalid chain. Genesis transactions are not processed separately (valid genesis is empty). Determinism is unchanged: each call seeds a fresh copy of the trusted bootstrap balances and an empty nonce map, processes blocks in order and transactions in list order, and shares no mutable state between calls. Because `Chain.validate()` and `_check_block_transition` enforce the same exact-integer-index and plain-list-container rules, a chain that passed `validate()` satisfies every structural check `apply_block` performs; `InvalidBlockError` therefore cannot escape a `replay()` of a validated chain. One caveat is documented as an existing limitation, not a behavior changed here: if a **non-genesis** block's contents cannot be canonically serialized, `Chain.validate()` itself calls `verify()` without guarding serialization and can raise `TypeError`/`ValueError` directly rather than return `False`, and that exception then propagates unchanged through `replay()` (see §9).

## 8. Structural versus stateful validity

The boundary is explicit and is the reason for the separate exception type:

- `Chain.validate()` answers **structural** questions about a whole chain — genesis spec, sequential indices, self-verification, and hash links — and returns a `bool`.
- `Ledger.apply_block()` answers a **state-transition** question about one candidate block against a supplied predecessor and prior state, and returns a `LedgerState` (or raises).

The two are consistent, not competing: `apply_block`'s structural rules are the pairwise, per-block instance of `Chain.validate()`'s position and link rules, and both now share the hardened index and container checks from M7.0. `replay()` composes them: structural gate first, then state transition per block.

## 9. Error behavior

`InvalidBlockError` is a direct subclass of `Exception`, consistent with the existing flat exception hierarchy in `core/exceptions.py`. It is the per-block counterpart to `InvalidChainError` and is deliberately **not** nested under it, preserving the chain-structural versus block-structural distinction that ADR 002 and ADR 006 rely on. It is purely additive: no existing behavior or exception changes.

| Condition | Exception |
|---|---|
| `block` / `prev_block` not a `Block`; `prior_state` not a `LedgerState` | `TypeError` (built-in) |
| Non-integer `block.index` or `prev_block.index` | `InvalidBlockError` |
| `block.transactions` not a real `list` | `InvalidBlockError` |
| Genesis (`index == 0`) submitted as a candidate | `InvalidBlockError` |
| `block.verify()` returns `False`, or raises `TypeError`/`ValueError` | `InvalidBlockError` (cause preserved via `from exc`) |
| `verify()` raises anything else | propagates unchanged (never masked) |
| `block.index != prev_block.index + 1` | `InvalidBlockError` |
| `block.prev_hash != prev_block.block_hash` | `InvalidBlockError` |
| Malformed record / sender public-key mismatch | `InvalidTransactionError` (from `_process_transaction`) |
| Bad signature | `InvalidSignatureError` (from `_process_transaction`) |
| Wrong chain id | `WrongChainError` (from `_process_transaction`) |
| Stale / skipped / out-of-order nonce | `InvalidNonceError` (from `_process_transaction`) |
| Insufficient funds | `InsufficientFundsError` (from `_process_transaction`) |
| Whole chain invalid — `Chain.validate()` returns `False` (replay) | `InvalidChainError` (unchanged) |
| `Chain.validate()` itself raises `TypeError`/`ValueError` on non-serializable contents | propagates through `replay()` unchanged (see note below) |
| Genesis spec violated at `Chain` construction / position 0 | `ValueError` (unchanged) |

The `except (TypeError, ValueError)` around `verify()` is scoped to that single expression and covers exactly the serialization failures `to_dict`/`to_bytes` document (unserializable objects, `allow_nan` rejection, lone surrogates). A `RecursionError` (a `RuntimeError` subclass), `AttributeError`, or any other unexpected exception propagates untouched, and `from exc` keeps the original traceback visible.

**Asymmetry with `Chain.validate()` (existing limitation, not changed here).** `apply_block` narrows the serialization failures from its single `verify()` call into `InvalidBlockError` (§3, item 5), but `Chain.validate()` is deliberately left unchanged and calls `verify()` without that guard. As a result, a **non-genesis** block whose contents cannot be canonically serialized makes `Chain.validate()` raise `TypeError`/`ValueError` directly instead of returning `False`; because `replay()`'s first act is `chain.validate()`, that exception then propagates unchanged to the caller rather than being converted into `InvalidChainError`. This is a pre-existing Milestone 2 behavior carried forward and documented rather than fixed, since changing `Chain.validate()`'s boolean contract is out of scope for Milestone 7. Genesis is unaffected on this path: its transaction container must be an empty `list` (any non-empty or non-list container fails the genesis checks before hashing), so `validate()` returns `False` for genesis and never reaches a raising `verify()`.


## 10. Atomicity and trusted inputs

- **Atomicity.** All structural checks precede any state work; the prior state is only ever read. The block's transactions are applied to fresh working dictionaries, and a new `LedgerState` is returned only after every transaction succeeds. On any failure the working copy is discarded, an exception propagates, and nothing is returned. The supplied `prior_state` is unchanged on both success and failure because `LedgerState` has no mutators.
- **`apply_block` does not accept the block.** It computes a state; it does not append the block to any `Chain`. Acceptance remains the caller's decision.
- **Trusted-input precondition.** `apply_block` trusts both `prev_block` (a previously accepted block) and `prior_state` (the state immediately following it). It does not verify either and cannot prove their history; it does not re-derive `prior_state` from a chain. A well-formed but wrong `prior_state` would yield a wrong but structurally valid result.

## 11. Alternatives considered

- **Free function taking `chain_id`** instead of a `Ledger` method. Rejected: it duplicates the chain-identity configuration that `Ledger` owns, allowing `apply_block` and `replay` to disagree about chain id.
- **A new module** (e.g. `core/block_validation.py`). Rejected: `_process_transaction` is private to `core.ledger`; a new module would either widen that visibility or copy transaction rules. Keeping it on `Ledger` adds no module and no new test file.
- **Method on `Block` or `Chain`.** Rejected: state validation needs the ledger's chain id and the transaction authority, neither of which `Block` or `Chain` should own.
- **A `prev_block=None` genesis sentinel** and a separate genesis path. Rejected: it would create a second genesis authority and a special case; genesis-as-predecessor needs no special handling.
- **Two-phase "validate all, then apply all."** Rejected: `_process_transaction` is already all-or-nothing per transaction and the working copy is discarded on any raise, so a two-phase pass would double the cryptographic cost and duplicate the ordering rule for no observable benefit.
- **A cheap chain-id precheck before signature verification.** Rejected for now: it would introduce a second authority for the chain-id rule; error precision is worth more, and networking (the stated motivation) is out of scope.
- **Subclassing `InvalidChainError`** for block errors. Rejected: it would make `except InvalidChainError` wrongly catch single-block errors and erase the chain-vs-block boundary. A flat sibling type is used instead.
- **Validating the container after `verify()`.** Rejected: `verify()` consumes a generator while reproducing the hash, so the check must precede it to prevent a silent zero-transaction skip.

## 12. Consequences and limitations

- **Per-block state-copy cost.** `replay()` now copies and re-normalizes the working state once per block, making replay `O(blocks × accounts)` instead of `O(transactions + accounts)`. This is accepted for a single source of truth; the private `_apply_block` seam is the documented escape hatch if a future performance milestone prefers one long-lived working dict. This milestone deliberately does **not** optimize the copies away.
- **Trusted inputs.** `apply_block` cannot prove that `prev_block` and `prior_state` are authentic or that `prior_state` immediately follows `prev_block`; that requires full replay or consensus.
- **No chain binding on state.** `LedgerState` does not carry a chain id and does not prove provenance. A `prior_state` produced by a differently-configured `Ledger` (different chain id or bootstrap balances) is accepted silently. A genesis-derived state/chain commitment is the future fix.
- **Intra-block order is list order, not a consensus rule.** Reordering transactions within a block can change the outcome; canonical mempool ordering is out of scope.
- **Inherited tamper limitation.** Because `apply_block` trusts the predecessor's stored `block_hash`, an attacker who rewrites both a predecessor's contents and its stored snapshot is undetectable locally — the same limitation `Block.verify()` and ADR 002 document.
- **Out of scope.** This milestone adds no timestamp-ordering policy, coinbase or issuance transactions, mining, transaction-capacity limits, networking, consensus, fork choice, persistence, state hashing, or state-to-chain binding.
- **Not production-ready.** This is an educational prototype. Structural validity, signatures, and nonces alone do not constitute a decentralized consensus system, and the design makes no claim of resistance to all adversarial conditions.


## 13. Test coverage

- `tests/test_chain.py` — `TestChainIndexMustBeExactInteger` (Boolean/float index rejection at genesis and later positions) and `TestChainTransactionContainerMustBeList` (generator and list-subclass container rejection, including proof the container is not consumed). These establish the structural layer that `apply_block` shares.
- `tests/test_ledger.py`:
  - `TestApplyBlockStructure` — wrong/skipped/duplicate indices, broken previous-hash link, stale block hash, Boolean/float candidate and predecessor indices, genesis-as-candidate, wrong argument types (`TypeError`), generator-container rejection without consumption, non-serializable contents translated to `InvalidBlockError`, and an unexpected `RecursionError` propagating unchanged.
  - `TestApplyBlockStateTransition` — exact balance/nonce changes, prior-state immutability after success, an empty block returning an equal but distinct state, and repeat-application determinism.
  - `TestApplyBlockTransactionFailures` — invalid signature, malformed record, and wrong chain id, each preserving the prior state.
  - `TestApplyBlockNonceAndFunds` — stale/duplicate, skipped, and out-of-order nonces, and insufficient funds, each preserving the prior state.
  - `TestApplyBlockIntraBlockOrdering` — spending funds received earlier in the same block, the reversed order failing, and an early valid transaction followed by a failing one leaving the prior state unchanged.
  - `TestApplyBlockFullBalanceAndSelfTransfer` — full-balance transfer removing the zero entry, full-balance self-transfer preserving the balance and advancing the nonce once, and an over-balance self-transfer failing.
  - `TestReplayDelegatesToApplyBlock` — replay equals a manual `apply_block` fold, two equivalent chains replaying equally, a genesis-only chain returning the bootstrap state, and a generator-container chain raising `InvalidChainError`.

## 14. Documentation and implementation scope

### New files

- `docs/decisions/007-stateful-block-validation.md`

### Modified files

- `core/exceptions.py` — add `InvalidBlockError`.
- `core/chain.py` — enforce exact-integer indices and plain-list transaction containers (M7.0), aligning the structural layer with block validation.
- `core/ledger.py` — add `apply_block`, `_check_block_transition`, and `_apply_block`; refactor `replay()` to delegate non-genesis blocks through `apply_block()`.
- `tests/test_chain.py` — exact-integer-index and transaction-container regression tests.
- `tests/test_ledger.py` — the `apply_block` and replay-delegation test classes; relocate the `if __name__ == "__main__"` guard to end-of-file so direct execution includes the later classes.
- `README.md` — reflect `InvalidBlockError` in the architecture table, clarify exact-integer block indices, add stateful block validation to the features, mark it complete in the roadmap, remove the stale "next planned milestone" slot, add the caller-supplied-state limitation, and list ADR 007.

`core/block.py`, `core/transaction.py`, `core/signed_transaction.py`, `core/wallet.py`, and `core/validation.py` remain unchanged in this milestone. `requirements.txt` is unchanged.

## 15. Implementation order

1. Harden `core/chain.py` with exact-integer-index and plain-list-container checks, with regression tests that fail before and pass after.
2. Add the `InvalidBlockError` exception.
3. Implement `apply_block` with its structural checks, without changing `replay()`.
4. Add the block-boundary behavior tests (transaction failures, nonces, ordering, full-balance and self-transfer).
5. Refactor `replay()` to delegate through `apply_block`, with delegation tests.
6. Document the decision (this ADR), update the README, and relocate the test guard.
7. Run the full test suite and the direct-execution check, review the complete diff, then commit.

The milestone is complete only when the structural, state-transition, atomicity, ordering, and replay-delegation tests pass without weakening any earlier test, and the documentation matches the implemented code.
