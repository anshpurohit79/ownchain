# OwnChain Independent Python Reference Model

## Overview

This directory contains the independent, standalone Python reference model for the **OwnChain Shielded-First Hybrid Architecture (v1)**.

It implements the complete consensus state transition logic, global monetary conservation invariant, 4-component composite state root, transparent account ledger, and cross-pool value accounting using only the Python standard library.

---

## File Structure

- **`merkle.py`**: Domain-separated recursive-split Merkle trees (RFC 6962-style with no odd-leaf duplication), nullifier-set Merkle trees, pool balance commitments, and composite state root computation using BLAKE2b-256 (`hashlib.blake2b(digest_size=32)`).
- **`transactions.py`**: Canonical outer envelope (35 bytes), transaction ID derivation, minimum fee formulas, and wire representations for all 8 authoritative transaction types (Types 0 through 7).
- **`hybrid_state.py`**: Full consensus state machine (`HybridChainState`, `AccountState`, `CoinbaseTranche`, `PendingTransfer`). Implements 100-block coinbase maturity, spendable balance tracking, guardian governance quorums (3-of-7 / 4-of-7), cross-pool transfer accounting, and atomic block execution.
- **`orchard_adapter.py`**: Clear boundary specification for Orchard V2 cryptographic operations (zero-knowledge Halo2 proofs, spend authorization signatures, binding signatures) delegated to the pinned Rust crate (`orchard = 0.16.0`).
- **`test_hybrid_state.py`**: Comprehensive unit test suite asserting all 14 mandatory protocol invariants, plus guardian, economic, and boundary properties.

---

## What Is Independently Modeled vs. Delegated

| Layer / Mechanism | Implementation Status | Notes |
|---|---|---|
| Transparent Account State | **Independently modeled in Python** | Canonical serialization matching §7.3, nonce sequencing, balances |
| Coinbase Maturity Tracking | **Independently modeled in Python** | Per-account tranches, 100-block unlock height, spendable balance deduction |
| Opt-in Guardian Governance | **Independently modeled in Python** | 7-key configuration, 3-of-7 strengthen, 4-of-7 weaken/freeze/recovery/cancel |
| Per-Transfer Pending Locks | **Independently modeled in Python** | First-time recipient delays, unrelated recipient funds remain spendable |
| Shielded Pool Accounting | **Independently modeled in Python** | Non-negative checked balance, sign convention: $\Delta S = -\text{valueBalanceOrchard}$ |
| Global Monetary Invariant | **Independently modeled in Python** | Verified at block boundary: $T + S = I$, checked arithmetic, 21M cap |
| Merkle & State Commitments | **Independently modeled in Python** | RFC 6962 recursive-split trees, sorted nullifier tree, pool commitment, composite root |
| Orchard Circuit & Halo2 Proofs | **Delegated to Rust crate** | Handled by pinned `orchard = 0.16.0` (`FixedPostNu6_2` circuit) |
| Orchard Action Cryptography | **Delegated to Rust crate** | RedPallas spend-auth signatures, binding signatures, Sinsemilla commitments |

---

## Running the Reference Model Tests

Run the test suite with Python's standard `unittest`:

```bash
python -m unittest discover -s refmodel -v
```

All 29 tests execute deterministically and assert every consensus rule and state transition.
