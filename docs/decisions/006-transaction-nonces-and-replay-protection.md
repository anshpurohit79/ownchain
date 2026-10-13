# ADR 006: Transaction Nonces, Chain Binding, and Replay Protection

- **Status:** Accepted
- **Date:** 2026-10-13
- **Milestone:** 6
- **Scope:** Signed transactions, wallet signing, ledger replay, immutable ledger state, shared exceptions, tests, and project documentation.
- **Implementation status:** Fully implemented. The shared validation primitives (`core/validation.py`), the domain-separated signed-message format with `nonce` and `chain_id` in `core/signed_transaction.py`, the `InvalidNonceError`/`WrongChainError` exceptions, wallet signing of nonce/chain-ID-bound records (`core/wallet.py`), and ledger nonce/chain-ID enforcement with pure `LedgerState` replay (`core/ledger.py`) are all in place and covered by the test suite. Replay protection applies to deterministic linear-history replay only; it does not address competing chains or network-level double spends without consensus (see §Consequences and the security-boundary notes).

## 1. Context

OwnChain supports Ed25519-signed transfers. A transaction contains sender and recipient addresses, an integer amount, a public key, and a signature. The ledger verifies the signature and sender-address correspondence before checking funds and applying the transfer.

However, the same valid signed transaction can currently appear more than once in a chain and be applied repeatedly. A signature proves authorization of the signed fields; it does not prove that a transaction has not already been processed.

This milestone introduces per-account sequential nonces, binds signatures to a chain identifier and a specific message type, and makes ledger replay a pure state-transition operation.

The objectives are deterministic transaction ordering, replay rejection, atomic state transitions, and a state representation that can later support state comparison and hashing.

## 2. Decision: exact sequential nonces

Each account has a next expected transaction nonce. Nonces begin at zero for every address unless a future trusted state-snapshot mechanism explicitly supplies prior nonce state.

For an account address `a`, the acceptance rule is:

`transaction.nonce == next_nonce(a)`

After a transaction passes all validation rules and is accepted into the working state:

`next_nonce(a) = transaction.nonce + 1`

The next nonce is independent of the account's balance.

### Nonce bounds and validation

Define:

- `MAX_NONCE = 2**64 - 2`
- `MAX_NEXT_NONCE = 2**64 - 1`

A transaction nonce must satisfy `type(nonce) is int` and `0 <= nonce <= MAX_NONCE`. Booleans, floats, strings, negative values, and values above the maximum are rejected as malformed transaction data.

`MAX_NONCE` is deliberately one less than the maximum unsigned 64-bit value. This allows the next expected nonce to advance to `MAX_NEXT_NONCE` without exceeding the chosen state representation.

A state whose next expected nonce is `MAX_NEXT_NONCE` is exhausted: no further transaction nonce is valid under this protocol.

**Cross-language limitation.** JavaScript's standard JSON-number representation cannot exactly represent integer values above `2**53 - 1`. Because a permitted nonce can exceed that bound, a JavaScript implementation using ordinary JSON numbers could silently lose precision. OwnChain therefore makes **no cross-language nonce interoperability claim yet**; nonce-bearing records should only be exchanged between implementations that represent integers exactly until this is revisited.

### Exact equality versus alternatives

Exact equality provides one deterministic transaction order for every sender.

- A nonce below the expected value is stale or duplicated.
- A nonce above the expected value is skipped or out of order.
- A nonce equal to the expected value is eligible for further validation.

Allowing any nonce greater than the previous one would permit gaps and leave missing transactions unresolved. Maintaining only a set of previously seen transaction hashes would require unbounded history and would not enforce a natural per-account ordering. Timestamp and expiry schemes would introduce trusted-clock requirements, clock skew, and additional edge cases.

Exact sequential nonces are selected for this educational ledger.

### Unknown accounts and first transactions

An unknown sender has an expected nonce of zero and no spendable funds unless bootstrap state gives the address a balance. A previously unknown recipient may receive funds; its expected nonce remains zero until it sends its first accepted transaction.

An account whose first observed transaction has nonce five is rejected. OwnChain does not infer missing transactions.

Different sender addresses maintain independent nonce sequences.

## 3. Decision: chain ID and domain separation

### Chain ID format

Every signed transaction contains a `chain_id`. The ledger is configured with its expected chain ID.

The permitted format is ASCII lowercase text matching:

`[a-z0-9][a-z0-9._-]{0,63}`

The length is 1–64 characters. Uppercase characters, Unicode characters, whitespace, and other characters are rejected.

The initial development identifier is `ownchain-devnet-1`. The wallet receives the chain ID explicitly when signing; the ledger independently checks that it matches its configured value.

### Domain separation

Every signed message begins with this fixed byte prefix:

`b"OWNCHAIN:SIGNED-TRANSACTION:V1\x00"`

The complete signing message is:

`DOMAIN_PREFIX + canonical_json_payload`

The prefix separates transaction signatures from other potential message types signed with the same Ed25519 key. The `V1` component identifies the signed-message format.

Future signed message types must use distinct domain prefixes. Any future change to the transaction signing format must define a new version rather than silently reinterpret existing signatures.

### Chain identity limitation

A chain ID is a configured identifier, not a globally unique cryptographic identity. Two network instances could accidentally use the same string.

Once genesis rules and allocations are defined inside the committed chain state, a stronger design should derive or bind chain identity to the genesis block hash or an equivalent genesis-state commitment. Current bootstrap balances are external trusted input, so this milestone cannot yet derive complete chain identity from genesis alone.

## 4. Signed transaction schema

The serialized signed transaction contains exactly these fields:

- `sender`
- `recipient`
- `amount`
- `nonce`
- `chain_id`
- `public_key`
- `signature`

The existing unsigned `Transaction` API remains unchanged. It continues to describe a transfer with sender, recipient, and amount.

The wallet signing interface becomes:

`Wallet.sign_transaction(transaction, *, nonce, chain_id)`

The nonce and chain ID are supplied explicitly when signing. They are not added to the unsigned `Transaction` model because they belong to a signed transaction's execution and network context.

### Strict validation

A signed record must satisfy all of the following:

- Sender and recipient are exactly 40 lowercase hexadecimal characters.
- Amount is a positive integer; booleans and floats are rejected.
- Nonce is an integer within the specified nonce bounds.
- Chain ID matches the documented ASCII format.
- Public key is canonical unpadded base64url encoding of exactly 32 raw Ed25519 bytes.
- Signature is canonical unpadded base64url encoding of exactly 64 bytes.
- The decoded public key derives the claimed sender address.

Both encoded fields must be decoded strictly, then re-encoded and compared with the original representation. Padding, invalid characters, invalid lengths, and noncanonical encodings are rejected.

`SignedTransaction.from_fields` takes the nonce and chain ID alongside the existing transfer, public-key, and signature fields: `from_fields(sender, recipient, amount, nonce, chain_id, public_key_bytes, signature_bytes)`. A second classmethod, `SignedTransaction.from_dict(record)`, is the single strict parsing entry point for a serialized seven-field record (`sender, recipient, amount, nonce, chain_id, public_key, signature`); it centralizes record parsing and canonical base64url decoding so the ledger and any future stateful block validator share identical rules rather than duplicating them. `from_dict` does not check sender/public-key correspondence (that is a verification-time concern), so a deliberately mismatched record parses successfully and is later rejected by `verify_strict`.

The existing unsigned `Transaction` tests remain meaningful and do not imply that unsigned transactions are accepted by the ledger.

## 5. Canonical signed payload

The canonical JSON payload contains exactly:

`sender`, `recipient`, `amount`, `nonce`, `chain_id`, `public_key`

The `signature` field is excluded.

Serialization uses sorted keys, compact separators, and UTF-8 encoding. The `public_key` value in the JSON is its canonical unpadded base64url representation, not hexadecimal text.

The complete signing message consists of the fixed domain-separation prefix followed by these canonical JSON bytes.

The wallet and verifier must share one canonical message-construction function. Independent, handwritten payload construction is prohibited because apparently equivalent encodings may produce different bytes.

Changing the sender, recipient, amount, nonce, chain ID, or public key after signing must make signature verification fail, or cause structural validation to reject the record.

### Golden test vector

The test suite must freeze a deterministic Ed25519 signing vector using a fixed, test-only 32-byte private-key seed. The seed must never be used as a real wallet key.

The test fixture must contain literal expected values for:

- Raw public key bytes and derived address.
- Canonical base64url public-key representation.
- Exact canonical JSON payload bytes.
- Complete domain-separated signing message bytes.
- Deterministic signature bytes or their agreed hexadecimal representation.
- Serialized signed-transaction dictionary.

Expected values must be pinned as literals rather than calculated by calling the same production payload helper under test. The test must fail if an accidental serialization or domain-prefix change alters the protocol.

## 6. Decision: pure replay and immutable LedgerState

`Ledger` stores the trusted initial configuration, not the evolving result of earlier replay calls.

Its constructor receives:

`Ledger(initial_balances, chain_id)`

The constructor validates and privately copies the bootstrap balances, validates the chain ID, and retains both as its unchanged initial configuration. Bootstrap addresses must be valid addresses exactly as supplied; the constructor must reject malformed addresses rather than normalize them silently.

Bootstrap balance values must satisfy `type(balance) is int` and `balance >= 0`. Booleans, floats, negative values, and non-integer types are rejected. Zero-valued bootstrap entries are omitted from the canonical starting balances.

Every call to `Ledger.replay(chain)` starts with fresh working copies of the initial balances and an empty next-nonce mapping. It processes the entire supplied history in order and returns a new `LedgerState` on success.

If any transaction or block fails validation, replay raises an exception and returns no state. Its temporary working mappings are discarded. The original configuration and any previously returned state remain unchanged.

Therefore, replaying the same chain with the same initial configuration produces an equal state, even when called repeatedly on the same `Ledger` instance.

### LedgerState constructor and validation

`LedgerState(balances, next_nonces)` is a public value-object constructor and must validate its inputs using the shared address validator and the same integer constraints used by the ledger.

It must:

- Validate every address.
- Require balance values to be exact non-negative integers.
- Require next-nonce values to be exact integers between zero and `MAX_NEXT_NONCE`.
- Reject booleans, floats, malformed addresses, and invalid numeric ranges.
- Make defensive copies of both supplied mappings.
- Canonicalize both mappings by removing all zero-valued entries.
- Expose no public mutation methods or mutable mappings.

The state represents validated data, not proof that a valid chain produced that data. `Ledger.replay()` remains responsible for deriving state from the configured initial state and transaction history.

### Lookup and iteration API

The public API consists of:

- `balance(address) -> int`
- `next_nonce(address) -> int`
- `iter_balances()`
- `iter_next_nonces()`

Both lookup methods return zero for an absent valid address. Invalid address arguments are rejected rather than silently treated as unknown.

The iterators yield `(address, value)` pairs sorted by address. They expose no underlying mutable dictionaries. Sorting is explicit; insertion order must never determine the future canonical state representation.

### Equality and hashing

Two `LedgerState` instances compare equal when their canonical balance mappings and canonical next-nonce mappings are equal.

Equality returns `NotImplemented` for objects of unsupported types. The class is deliberately unhashable (`__hash__ = None`) because state hashing is not required by this milestone and must not be introduced without a defined canonical state-hash format.

## 7. Canonical state and zero-value rules

**Zero values are never stored in either balances or next nonces.**

The canonical balance lookup rule is:

`balance(a) = balances.get(a, 0)`

The canonical next-nonce lookup rule is:

`next_nonce(a) = next_nonces.get(a, 0)`

If an account spends its entire balance in an ordinary transfer, its balance entry is removed. If that account has sent transactions, its next-nonce entry remains even if its balance is zero.

The mappings have independent meanings:

- `balances` records current spendable value.
- `next_nonces` records transaction-sequence history needed to prevent replay.

When an account accepts its first transaction with nonce zero, its next expected nonce becomes one and is stored. A recipient that has never sent a transaction has no nonce entry and therefore has next nonce zero.

This canonical representation ensures that states with equivalent balances and nonce counters have the same mapping contents, regardless of whether their constructor inputs explicitly included zero-valued entries.

### State growth

The next-nonce mapping grows as new addresses successfully send transactions. Its entries are retained even if account balances reach zero, because forgetting nonce history could permit old transactions to be replayed after an account is funded again.

This growth is inherent to the design. Storage optimization or state pruning will require a separate design that preserves replay safety.

## 8. Stateful transaction processing

`Chain.validate()` remains responsible for structural validity: genesis rules, block hashes, sequential indices, and previous-hash links. It does not establish that every transaction is authorized or affordable.

`Ledger.replay()` performs the stateful checks. Transactions are processed in block order and then transaction-list order.

For each transaction, the ledger:

1. Parses and validates the signed record.
2. Verifies the public-key/sender-address correspondence and Ed25519 signature over the exact domain-separated canonical message.
3. Checks the configured chain ID.
4. Checks that the transaction nonce equals the sender's next expected nonce.
5. Checks sufficient funds.
6. Computes the resulting balance and next nonce.
7. Applies both updates to the private working state only after all validation has succeeded.

A single internal transaction-processing function must own these rules. Milestone 7's stateful block-validation API will reuse that function rather than duplicate the transaction rules.

### Normal transfers and self-transfers

For a normal transfer, the sender's balance decreases by the amount, the recipient's balance increases by the same amount, and the sender's next nonce advances by one.

If the sender's balance becomes zero, its balance entry is removed. Its nonce entry is not removed.

A self-transfer requires sufficient funds but does not change the account's balance. It still consumes one nonce.

The self-transfer implementation must not use an early return that skips the nonce update. Nor may a self-transfer of the entire balance remove the account's unchanged balance entry.

### Failure ordering and error semantics

Preserve clear distinctions between failure causes:

- `InvalidChainError`: structural chain validation fails.
- `InvalidTransactionError`: malformed transaction, invalid field, invalid address, invalid encoding, or sender/public-key mismatch.
- `InvalidSignatureError`: structurally valid transaction whose cryptographic signature does not verify.
- `WrongChainError`: well-formed and correctly signed transaction targets a different configured chain ID.
- `InvalidNonceError`: a transaction has a stale, duplicate, skipped, or out-of-order nonce.
- `InsufficientFundsError`: the sender cannot afford the transfer.

The ledger verifies the signature before comparing the transaction's `chain_id` to its configured chain ID. Consequently, changing a chain ID without re-signing produces an invalid signature, while a valid transaction signed for another chain raises `WrongChainError`.

This ordering is a deliberate trade-off. Verifying first keeps the error semantics precise: a genuine signature failure is always reported as `InvalidSignatureError`, never masked by a chain mismatch. The cost is that correctly signed traffic bound for a different chain still incurs a full Ed25519 verification before it is rejected. Milestone 7 should consider a cheap precheck — comparing the record's `chain_id` (and nonce range) against the configured chain before performing signature verification — once such a precheck cannot weaken the error guarantees. That optimization is intentionally deferred and is out of scope for this milestone.

No failed transaction may partially modify working balances or nonce counters. If a later transaction causes replay to fail, all earlier working changes from that replay are discarded as well.

## 9. State-transition invariants and acceptance criteria

The implementation and test suite must demonstrate the following invariants.

### Nonce sequencing

- A sender can successfully use nonces `0`, `1`, and `2` in order.
- Different senders maintain independent nonce sequences.
- An identical transaction appearing twice is rejected on its second occurrence.
- Stale and skipped nonces are rejected.
- Nonce order continues correctly across block boundaries.
- Altering a nonce without re-signing invalidates the signature.
- Altering a chain ID without re-signing invalidates the signature.
- A correctly signed transaction for another chain raises `WrongChainError`.
- Nonce boundary tests cover `0`, `MAX_NONCE`, `MAX_NONCE + 1`, `True`, `1.0`, `"0"`, and `None`.
- A transaction failing signature, chain, nonce, or funds validation consumes no nonce.

### Refund replay

A dedicated test must exercise this sequence:

1. Alice starts with 10 units and accepts a transfer of all 10 units to Bob using nonce zero.
2. Bob transfers the 10 units back to Alice using Bob's nonce zero.
3. Alice's original signed nonce-zero transaction is submitted again.

The final occurrence must be rejected as stale even though Alice has received funds again. This proves that nonce history survives an account balance reaching zero.

### Self-transfer of the entire balance

A test must verify that Alice, holding 10 units, sends all 10 units to herself with nonce zero.

The resulting state must still report Alice's balance as 10 and her next nonce as 1. The balance entry must not be deleted, while the nonce must still advance.

### Supply conservation

This milestone has no issuance, fees, or burn mechanism. Therefore, for every successful replay:

`sum(final balances) == sum(initial balances)`

A test must verify that total supply remains constant through multiple transfers, self-transfers, zero-balance accounts, and newly created recipients.

### Final nonce invariant

For every sender address, the final next expected nonce must equal the number of accepted transactions from that sender in the replay, since every sender begins at nonce zero and gaps are prohibited.

Tests must also cover failed replays, failure isolation, deterministic state equality across repeated replay calls, constructor-copy isolation, state immutability through the public API, canonical omission of zeros, sorted iteration, and equality behavior.

### Golden vector and regression coverage

Use test-only in-memory keys, including the fixed-seed golden vector described above. No real private key may appear in tests.

The complete existing Block, Chain, Transaction, Wallet, SignedTransaction, and Ledger integrity coverage must remain meaningful and passing. Update tests that assumed `Ledger.replay()` returns a dictionary so they use the new `LedgerState` lookup and iteration methods.

## 10. Alternatives considered

### Allow nonce gaps

**Rejected.** A greater-than rule would permit transactions to advance over missing nonces and make transaction ordering and recovery from skipped transactions less precise.

### Maintain a set of previously seen transaction hashes

**Rejected.** This requires retaining an ever-growing set of processed identifiers and does not naturally impose a sequential per-account order. Exact nonces reject both duplicates and skipped transaction sequences using compact per-account counters.

### Use timestamps and transaction expiry

**Rejected.** Timestamp-based validity requires trusted time assumptions, introduces clock skew and expiry-boundary behavior, and does not provide the same simple deterministic sequencing rule.

### Keep the Ledger stateful across replay calls

**Rejected.** Stateful replay would make outcomes depend on prior method calls, risk applying historical transactions more than once, and complicate recovery after failure. Pure replay from a fixed initial configuration provides a simple determinism guarantee.

### Store nonce counters only while balances are positive

**Rejected.** An account that spends everything would lose its replay-protection history. After receiving funds again, an old signed transaction could otherwise become acceptable.

## 11. Consequences and limitations

### Ordering and wallet behavior

Exact sequencing means that if an account creates a transaction with nonce `k` and that transaction never enters the accepted history, transactions from that account with nonces above `k` cannot be accepted.

Wallet software must therefore obtain the correct next nonce from a trusted state and track pending transactions carefully once transaction pools or networking are introduced.

For this milestone, callers use `LedgerState.next_nonce(address)` to obtain the next nonce for a new signed transaction. The wallet itself does not maintain an independent persistent nonce counter.

### Replay cost

Every replay processes the full history, so its time cost is `O(history)` in the number of blocks and transactions processed. Signature verification adds cryptographic work per signed transaction.

This is acceptable for the current educational implementation. Stage 4 must benchmark replay duration, signature-verification cost, and nonce-state growth before performance optimizations are introduced.

### Structural versus stateful block validity

A hash-valid chain is not necessarily a valid transaction history. `Chain.validate()` remains a structural check; `Ledger.replay()` determines whether the complete history is valid under signatures, chain identity, nonce rules, and balances.

A dedicated stateful block-validation entry point is deferred to Milestone 7. It will validate a candidate block against a supplied prior state using the same transaction-processing function.

### Supply and monetary limits

This milestone adds no issuance, fee, or burn mechanism. The total bootstrap supply is conserved by transfers.

The maximum transaction amount and eventual total supply remain to be specified as part of issuance and interoperability design, before cross-language network compatibility is claimed.

### Chain-ID uniqueness

A chain ID prevents replay across networks only when those networks use different configured identifiers. It does not solve replay across forks sharing the same ID. A genesis-derived identity is the stronger future design.

### No distributed consensus

Nonces protect replay within the validated linear ledger history. They do not by themselves solve network-level double spends, competing histories, fork choice, malicious peers, or decentralized consensus.

OwnChain remains an educational prototype and must not be used with real funds.

## 12. Documentation and implementation scope

### New files

- `docs/decisions/006-transaction-nonces-and-replay-protection.md`

### Modified files

- `core/signed_transaction.py` — nonce and chain ID fields, strict validation, canonical serialization, and domain-separated signing messages.
- `core/wallet.py` — require explicit keyword-only nonce and chain ID when signing.
- `core/ledger.py` — pure replay, chain-ID enforcement, nonce sequencing, canonical state handling, and immutable returned state.
- `core/exceptions.py` — add `InvalidNonceError` and `WrongChainError`.
- `tests/test_signed_transaction.py` — golden vector, nonce and chain-ID serialization, signature tampering, and encoding boundary tests.
- `tests/test_wallet.py` — signing API and domain-separation tests.
- `tests/test_ledger.py` — `LedgerState` API, replay behavior, nonces, refund replay, self-transfer, supply conservation, and failure isolation.
- `README.md` and relevant module docstrings — update limitations from “no replay protection” to describe nonce-based replay protection within the linear ledger history, while preserving the limitations around consensus, network double spends, and real-funds use.

`core/transaction.py`, `core/block.py`, and `core/chain.py` should remain unchanged during this milestone unless implementation reveals a genuine dependency that requires reconsideration. The stateful block-validation interface belongs to Milestone 7.

`requirements.txt` remains unchanged.

## 13. Implementation order

1. Extend the signed transaction fields and shared domain-separated canonical message builder. Add and verify the fixed golden test vector first.
2. Update wallet signing to require a nonce and chain ID.
3. Implement the validating, canonical `LedgerState` and pure replay with a shared transaction-processing function.
4. Add nonce sequencing, error types, chain-ID checks, and atomic state transitions.
5. Add replay, refund, self-transfer, boundary, conservation, and immutability tests.
6. Update README and module documentation.
7. Run the full test suite using the project's existing `.venv` environment.
8. Review the complete changes and test output before committing.

The milestone is complete only when the golden vector, nonce invariants, all-or-nothing replay, state canonicalization, and existing regression suite pass without weakening earlier tests.