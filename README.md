# OwnChain (v1 Baseline)

Experimental Rust implementation of the OwnChain v1 consensus and proof-of-work protocol baseline specified in [`docs/protocol-v1.md`](docs/protocol-v1.md).

> [!NOTE]
> **Experimental status:** This repository contains consensus primitives, chain-state verification, difficulty retargeting arithmetic, and RandomX proof-of-work integration. It is **not** a functioning peer-to-peer network, has no wallet or persistent database, does not verify cryptographic Orchard shielded proofs, and is **not** a production-ready cryptocurrency.

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

---

## Current Boundaries and Limitations

The following components belong to later milestones and are explicitly **out of scope**:

- **Orchard Shielded Transactions:** The outer transaction envelope is validated, but cryptographic verification of Orchard V2 bundles, Action circuits, RedPallas signatures, Merkle commitment trees, and nullifiers is deferred to the §12 Orchard compatibility gate.
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
│   ├── randomx.rs                  # RandomX C++ FFI wrapper and PoW verification
│   ├── tx.rs                       # Outer transaction envelope parser
│   └── validation.rs               # Consensus block validation pipeline
├── tests/
│   ├── difficulty.rs               # Arithmetic regression and golden vector tests
│   ├── golden_vectors.rs           # M1-A serialization and Merkle tests
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
