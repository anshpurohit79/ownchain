# OwnChain (v1 Baseline)

Experimental Rust implementation of the OwnChain v1 consensus and proof-of-work protocol baseline specified in [`docs/protocol-v1.md`](docs/protocol-v1.md).

> [!NOTE]
> **Experimental status:** This repository contains consensus primitives, chain-state verification, difficulty retargeting arithmetic, RandomX proof-of-work integration, and consensus-integrated stateless Orchard shielded transaction verification. It is **not** a functioning peer-to-peer network, has no wallet or persistent database, does not enforce stateful Orchard anchor/nullifier checks, and is **not** a production-ready cryptocurrency.

---

## Implemented Milestones

1. **Canonical Encoding and Merkle Commitments (M1-A):**
   - 170-byte canonical header serialization and domain-separated BLAKE2b-256 block/tx hashing.
   - Transaction Merkle tree with level-by-level odd-node duplication and domain separation.
   - Independently verified golden vectors in `docs/test-vectors-m1a.json`.

2. **Block Validation & Atomic Chain State (M1-B):**
   - Structural header, transaction count, size caps, and coinbase rule validation (§6.1–§6.3).
   - Upper-median ancestor timestamp validation window (§4).
   - Atomic chain acceptance via `ChainState`: rejected blocks leave accepted state, cumulative work, and history completely untouched.

3. **Difficulty Adjustment Arithmetic (M1-C1):**
   - CryptoNote/Monero-style lagged difficulty retargeting (§4.1): 720-sample window, 15-block lag, 600-sample trim, and 120-second target interval.
   - Checked 256-bit unsigned integer arithmetic (`U256`) with correct multi-limb carry propagation and 257th-bit borrow handling.

4. **RandomX Proof-of-Work & Consensus Difficulty Enforcement (M1-C2):**
   - Vendored RandomX v1.2.3 C++ engine with `OwnChain-PoW-v1` Argon2 salt.
   - FFI bindings and thread-local cache supporting Light and Fast validation modes.
   - RandomX key-block rotation schedule (`key_height(h)`).
   - Exact mathematical proof-of-work target calculation: $T(d) = \lfloor (2^{256} - 1) / d \rfloor$.
   - **Network-computed expected difficulty enforcement:** Candidates must match the expected difficulty derived from accepted chain state; miner-selected difficulty is strictly rejected.
   - Cumulative work tracking across accepted blocks (genesis contributes zero work).

5. **Production Orchard Stateless Codec & Cryptographic Verification (M1-E Stage 1):**
   - Canonical ZIP-225 Orchard V2 bundle parsing and serialization in `src/orchard_tx.rs`.
   - Strict CompactSize canonicality, bounded action count, proof length, and input size handling.
   - Pinned `orchard = 0.16.0` with `OrchardCircuitVersion::FixedPostNu6_2` verifying key.
   - Domain-separated action effect digest `OwnChain/ActionEffect/v1` and transaction authorization digest `OwnChain/TxAuth/v1`.
   - Stateless cryptographic verification of Halo2 proofs, RedPallas spend authorization signatures, and RedPallas binding signatures.

6. **Consensus-Integrated Stateless Orchard Verification (M1-E Stage 2):**
   - **Block Validation Integration:** All candidate block transactions are validated through `validate_transaction_stateless` using the block's chain ID and pinned verifying key, returning structured `ValidationError::InvalidOrchardTransaction { index, error }`.
   - **Per-Transaction Fee Enforcement (§4):** Checked arithmetic verification that declared fee equals $\max(1\,000,\, 1\,000 \times \text{action\_count} + \text{canonical\_tx\_size})$.
   - **Aggregate Block Action Limit:** Early aggregate action counting against `MAX_ACTIONS_PER_BLOCK` (2,000 actions per block) to prevent proof verification resource exhaustion.
   - **Atomic State Preservation:** `ChainState::apply_block` guarantees failure of any transaction rejects the candidate block without mutating accepted state.

---

## Current Boundaries and Limitations

The following components belong to later milestones and are explicitly **out of scope / incomplete**:

- **Stateful Orchard Consensus Protections:**
  - *Historical Anchor Validation:* Transaction anchors are checked for canonical field encoding, but are not yet validated against historical Orchard commitment tree roots.
  - *Nullifier Set & Double-Spend Prevention:* Nullifiers are not yet tracked in `ChainState` or checked against historical nullifiers on the active chain.
  - *Incremental Commitment Tree & Header Root Enforcement:* Block headers currently require `EMPTY_ORCHARD_ROOT` pending implementation of the incremental Orchard commitment tree.
  - *Pool Balance & Subsidy Accounting:* `ChainState` does not yet account for shielded pool value balances or block subsidy limits.
- **P2P Networking:** No libp2p transport, gossipsub, bootstrap discovery, or synchronization protocols are active yet.
- **Mempool & Storage:** Transactions and blocks are validated against in-memory `ChainState`; there is no transaction pool or on-disk database engine.
- **Wallet & Mining Client:** No key management, note scanning, or standalone mining client exists.

---

## Repository Layout

```text
ownchain/
├── Cargo.toml                      # Package manifest
├── build.rs                        # Cross-platform RandomX C++ CMake build script
├── docs/
│   ├── protocol-v1.md              # OwnChain v1 protocol specification
│   ├── test-vectors-m1a.json       # Golden vectors for headers, Merkle roots, tx IDs
│   └── test-vectors-m1c2-randomx.json # Golden vectors for RandomX Light/Fast boundaries
├── src/
│   ├── block.rs                    # Canonical block serialization and sizing
│   ├── chain.rs                    # ChainState and atomic block acceptance
│   ├── difficulty.rs               # U256 checked arithmetic and next_difficulty (§4.1)
│   ├── error.rs                    # Canonical encode errors
│   ├── genesis.rs                  # DevNet/TestNet genesis constants
│   ├── hash.rs                     # Domain-separated BLAKE2b hashing
│   ├── header.rs                   # Canonical 170-byte block header
│   ├── lib.rs                      # Library entry point
│   ├── main.rs                     # Binary entry point
│   ├── merkle.rs                   # Transaction Merkle tree calculation
│   ├── orchard_root.rs             # Canonical empty Orchard commitment tree root
│   ├── orchard_tx.rs               # Production Orchard transaction parser & validator
│   ├── randomx.rs                  # RandomX C++ FFI wrapper and PoW verification
│   ├── tx.rs                       # Outer transaction envelope parser
│   └── validation.rs               # Consensus block validation pipeline
├── tests/
│   ├── difficulty.rs               # Arithmetic regression and golden vector tests
│   ├── golden_vectors.rs           # M1-A serialization and Merkle tests
│   ├── orchard_compat.rs           # Orchard codec, digest, and stateless verification tests
│   ├── randomx.rs                  # RandomX Light/Fast independent C++ parity tests
│   └── validation.rs               # Consensus validation and difficulty retarget tests
├── tools/
│   ├── gen_randomx_vectors.cpp     # Standalone C++ RandomX vector generator
│   └── gen_vectors.py              # Reference Python vector generator
└── vendor/
    └── randomx/                    # Pinned upstream RandomX v1.2.3 C++ source tree
```

---

## Building and Testing

### Prerequisites

- Rust stable toolchain (`cargo`, `rustc`), with `rustfmt` and `clippy`:
  ```sh
  rustup component add rustfmt clippy
  ```
- C++ build tools:
  - **Linux / macOS:** `cmake`, `make`, GCC or Clang
  - **Windows:** Visual Studio C++ Build Tools or MSVC, `cmake`

### Verification Commands

```sh
# Format check
cargo fmt --all -- --check

# Clippy linter (warnings are errors)
cargo clippy --locked --all-targets --all-features -- -D warnings

# Execute test suite
cargo test --locked --all-targets
```
