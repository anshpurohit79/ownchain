# OwnChain (v1 Baseline)

Experimental Rust implementation of the OwnChain v1 consensus, node runtime, and proof-of-work protocol baseline specified in [`docs/protocol-v1.md`](docs/protocol-v1.md).

> [!NOTE]
> **Experimental status:** This repository implements the complete OwnChain M1-H hybrid consensus engine (shielded Orchard V2 and transparent account ledger, stateful anchors and nullifiers, cross-pool value conservation, composite state root) and the M1-I node runtime (embedded persistent storage, libp2p P2P networking, block synchronization, and mempool). It does **not** include wallet key management, note scanning, or a standalone mining daemon, and is **not** a production-ready cryptocurrency.

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
   - **Per-Transaction Fee Enforcement (§5, §7.6):** Checked arithmetic verification that declared fee satisfies the protocol minimum fee rule: $\text{fee} \ge \max(1\text{ atom},\, 100 \times \text{canonical\_signed\_tx\_size})$.
   - **Aggregate Block Action Limit:** Early aggregate action counting against `MAX_ACTIONS_PER_BLOCK` (2,000 actions per block) to prevent proof verification resource exhaustion.
   - **Atomic State Preservation:** `ChainState::apply_block` guarantees failure of any transaction rejects the candidate block without mutating accepted state.

7. **Cross-Pool Consensus Integration & Hybrid Ledger (M1-H):**
   - **Composite State Root Verification:** 32-byte header commitment uniting RFC 6962-style transparent account tree, depth-32 incremental Orchard commitment tree, recursive-split nullifier tree, and pool balance commitment.
   - **Stateful Shielded Accounting:** Cumulative nullifier set for double-spend prevention, 10-block ancestor anchor window $[h-10, h-1]$, and cumulative shielded pool balance tracking.
   - **Transparent Account Ledger:** Ed25519 addresses, sequential nonces, spend allowances, delayed withdrawals, per-transfer pending locks, opt-in 7-guardian governance (3-of-7 and 4-of-7 quorums), and 100-block coinbase maturity tranches.
   - **Atomic Cross-Pool Transfers:** Type 6 (Transparent-to-Shielded) and Type 7 (Shielded-to-Transparent) transfers with strict value conservation ($T + S = I$) and cross-pool authorization digests.
   - **Reorganization Rollback:** Exact historical state snapshots enabling atomic reorganization rollback.

8. **Node Runtime, Persistence and P2P Networking (M1-I):**
   - Modular node runtime architecture (`node`, `storage`, `p2p`, `mempool`).
   - Persistent embedded block and branch storage with atomic crash-safe commits and deterministic startup state reconstruction.
   - Rust libp2p networking with TCP transport, Noise security, Yamux multiplexing, Gossipsub message propagation (`blocks/v1`, `txs/v1`), application-level handshakes (`/ownchain/1`), request-response chain synchronization (`/ownchain/sync/1`), and Kademlia DHT routing table maintenance (with bootstrap-address dialing as the currently supported initial connectivity mechanism).
   - Fork-aware chain synchronization protocol with cumulative proof-of-work chain selection, common ancestor discovery, and atomic branch reorganization.
   - Bounded mempool with stateful admission, multi-type authorization checks, double-spend/conflict detection, and reorganization revalidation.

---

## Current Boundaries and Limitations

The following components belong to later milestones and are explicitly **out of scope / incomplete**:

- **Wallet Software:** Key management, BIP-39 seed generation, Orchard note scanning, and user-facing shielded transaction creation belong to a dedicated wallet milestone.
- **Mining Daemon:** RandomX mining daemon, miner thread orchestration, and stratum/pool RPCs belong to a dedicated mining milestone. The node runtime validates proof of work on received blocks but does not mine.
- **Production Network Launch:** Devnet proof-of-work uses the development salt `OwnChain-PoW-v1`. Production PoW configuration review, public testnet, and mainnet launch are future release gates. No claim of production readiness is made.

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
