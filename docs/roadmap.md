# OwnChain — Roadmap (decision-phase notes)

**Status:** informational, non-consensus.
**Purpose:** record high-level phase intent, engineering checklists, and explicitly out-of-scope / unavailable items.
**Not a spec:** nothing here changes `docs/protocol-v1.md`, and nothing here is approved or binding.

---

## Listing profile & Mainnet Scope

- **v1 (experimental network / devnet / testnet):** no exchange listing profile is defined. No exchange listing, no market-making, no price target, and no adoption guarantee. Listing is explicitly a post-v1 consideration, subject to a separate security and launch review.
- **Mainnet & Production PoW Approval:** Mainnet launch, production PoW approval, and commercial exchange listing remain strictly **out of scope** for OwnChain v1. Status: **not defined / unavailable**.

### 1.1 Profile & Scope

- **v1 (experimental network / devnet / testnet):** Supports both shielded and transparent transactions using the same native currency (OWN). Shielded transactions are the default wallet experience; transparent transactions remain available as an explicit user choice. No exchange listing profile is defined. No exchange listing, no market-making, no price target, and no adoption guarantee. Listing is explicitly a post-v1 consideration, subject to a separate security and launch review.

- **Hybrid architecture:** Shielded transactions are the default wallet experience; transparent transactions remain available as an explicit user choice. Both systems use the same native currency (OWN). One global issuance cap (21-million OWN) is enforced across both pool boundaries.

- **Hybrid wallet:** Wallets default to managing Orchard V2 shielded notes. Transparent account management requires explicit user opt-in. Shielded note synchronization requires nullifier tracking and commitment tree maintenance per ADR-004 §3.

- **Cross-pool validation:** Transparent-to-shielded and shielded-to-transparent transfers require value conservation checks per ADR-004 §4-5, atomic validation per ADR-004 §8, and fee accounting per ADR-004 §7.

---

## Demand-gate thresholds

- A search of the repository found **no demand-gate records** (no documented thresholds for activation, launch, fee changes, or guardian parameter changes).
- Per the decision-phase instruction, demand-gate thresholds are recorded here as **unavailable rather than invented**. No threshold values are proposed or assumed in this document.

---

## Checklist for standard RPC and API surfaces

- [ ] **JSON-RPC interface** — standard methods for `getblock`, `getblockcount`, `getblockhash`, `getblocktemplate`, `getrawtransaction`, `decoderawtransaction`, `submitblock`. No RPC method should accept or return fields that depend on consensus-critical state not yet committed.
- [ ] **Deposit detection** — mechanism for a downstream system to reliably detect when a transparent-account deposit has been included in a mined block and its `state_root` confirmed. Must rely on main-chain reorganization-safe confirmation depth, not on address scanning alone.
- [ ] **Explorer API** — read-only endpoints for block exploration, transaction detail, address activity, and `state_root` commitment visibility. No write endpoints; no balance-export that could imply consensus validity.
- [ ] **Reproducible builds** — `build.rs` CMake configuration for RandomX, compiler flags, and toolchain pins documented so that an independent build from source produces bitwise-identical binaries. No closed-source or vendor-locked build artifacts.
- [ ] **Licensing and confirmation guidance** — all third-party code (RandomX v1.2.3 vendor, BLAKE2, Ed25519 crates) carries its own license; no additional ownership claims are made. Users must confirm their local regulations before running a node or accepting mined blocks.
- [ ] **Confirmation guidance** — because OwnChain has probabilistic finality only, wallet-level confirmation counts are policy, not a consensus guarantee. A recommended minimum of 6–10 blocks for small transfers and 20+ for large transfers is advised until a separate launch review.

## Gate criteria

- **Gate 1 — Core serialization and vectors:** Publish canonical serialization and golden vectors for headers (including composite `state_root`), block IDs, transaction Merkle trees, account-state Merkle trees, Ed25519 signatures, minimum fees, subsidy schedules, coinbase maturity tranches, and cross-pool transfer validation vectors.
- **Gate 2 — Transparent state-tree consensus test harness:** Demonstrate complete atomic execution of transparent state transitions, nonce verification, allowance window enforcement, per-transfer pending records, coinbase maturity tracking (spendable vs immature balance), 3-of-7 and 4-of-7 quorums, cancellation authorization, and `state_root` calculation with known-good and known-bad test fixtures.
- **Gate 3 — Pre-public testnet gate:** Production PoW configuration review (salt, RandomX integration, merge-mining feasibility assessment), multi-node synchronization, reorganisation recovery, and resource caps.
- **Gate 4 — Pre-mainnet gate (Out of Scope for v1):** Full cryptographic audit, economic analysis, public threat model, and formal security sign-off. Must include review of hybrid architecture cross-pool transfer rules and guardian scope.
- **Gate 5 — Differentiation gate:** Explicit documentation of technical properties relative to other architectures, including the shielded-first hybrid design.
- **M1-H Milestone (Hybrid Architecture Prototype):**
  - **Phase 1: Specification & Reference Model (Unblocked while ADR-004 is PROPOSED):**
    - Authoritative transaction registry (Types 0 through 7) specified.
    - Independent Python reference model implementing composite state root, nullifier tracking, spendable balance, and global invariant ($T + S = I$).
    - Deterministic golden hybrid test vectors generated and verified reproducible.
  - **Phase 2: Rust Consensus Implementation (Gated):**
    - Rust consensus implementation may begin **only after**:
      1. ADR-004 is formally reviewed and marked ACCEPTED by repository owner.
      2. All consensus-critical accounting, fee formulas, and wire encodings are resolved.
      3. Independent hybrid golden test vectors exist and are asserted in tests.
      4. Independent reference model invariants pass without exception.
      5. Orchard V2 crate integration is verified against the pinned dependency (`orchard = 0.16.0`).
  - **Concrete Follow-up Tasks:**
    - [ ] `task-m1h-1`: Implement composite `state_root` calculation in `src/header.rs` and `src/block.rs`.
    - [ ] `task-m1h-2`: Update `src/tx.rs` envelope parser for transaction Types 0 through 7.
    - [ ] `task-m1h-3`: Implement `ChainState` depth-32 incremental commitment tree and nullifier set tracking.
    - [ ] `task-m1h-4`: Implement transparent account ledger state transitions and coinbase tranche maturity in `ChainState`.
    - [ ] `task-m1h-5`: Implement cross-pool atomic transfer validation (Types 6 and 7) with value conservation assertions.
