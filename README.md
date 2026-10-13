# OwnChain

**An educational cryptocurrency and blockchain implementation built from scratch in Python.**

OwnChain is a learning-focused project exploring how blockchain systems work internally, from cryptographic hashing and linked blocks to transaction validation, account balances, and digitally signed payments.

The goal is to understand and implement the fundamental components rather than build a token on an existing blockchain.

> **Status:** Educational prototype. Not suitable for real funds or production use.

## Features

- **Block integrity:** SHA-256 hashes of deterministic JSON representations of block contents.
- **Chain validation:** Exact-integer sequential block indices (Boolean and floating-point substitutes are rejected), previous-hash links, genesis rules, and per-block integrity checks.
- **Transaction model:** Validated transfers using positive integer amounts.
- **Account-based ledger:** Ordered transaction replay, sufficient-funds validation, and deterministic balance calculations.
- **Ed25519 signatures:** Wallet-generated digital signatures and public-key-based sender authorization.
- **Address derivation:** Deterministic account addresses derived from public keys.
- **Strict transaction encoding:** Validated transaction fields and canonical base64url encoding for public keys and signatures.
- **Chain-ID-bound signed transactions:** Domain-separated messages that bind signatures to a specific chain.
- **Sequential per-account nonces:** Replay protection within the validated linear ledger history.
- **Pure replay:** An immutable, canonical `LedgerState` returned by deterministic replay.
- **Atomic failure behavior:** Balances and nonce state are never partially updated.
- **Stateful block validation:** `Ledger.apply_block()` validates a candidate block against its predecessor and a supplied prior `LedgerState`, returning a new state without mutating the supplied one.
- **Automated tests:** Standard-library `unittest` suites covering block, chain, transaction, wallet, signature, and ledger behavior.
- **Architecture decision records:** Design choices and limitations documented in `docs/decisions/`.

## Architecture

The project separates the main responsibilities into independent components:

| Component | Responsibility |
|---|---|
| `core/block.py` | Block data, serialization, hashing, and integrity verification |
| `core/chain.py` | Ordered blocks, hash links, and chain validation |
| `core/transaction.py` | Structural validation of unsigned transfer descriptions |
| `core/signed_transaction.py` | Signed transaction representation, payload serialization, and signature verification |
| `core/wallet.py` | Ed25519 key generation, address derivation, and transaction signing |
| `core/ledger.py` | Transaction verification, nonce sequencing, balance validation, and deterministic replay |
| `core/exceptions.py` | Shared errors for invalid chains, invalid blocks, transactions, signatures, nonces, wrong chains, and insufficient funds |
| `core/validation.py` | Shared structural validators and constants for addresses, amounts, nonces, and chain IDs |

Blocks store transactions as JSON-compatible dictionaries. The ledger reconstructs and validates signed transactions before applying transfers.

## Requirements

- Python 3.13
- `cryptography>=50.0.2,<51`

## Setup

Clone the repository:

```bash
git clone https://github.com/anshpurohit79/ownchain.git
cd ownchain
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it in Windows Git Bash:

```bash
source .venv/Scripts/activate
```

On macOS or Linux, use:

```bash
source .venv/bin/activate
```

Install the dependency:

```bash
python -m pip install -r requirements.txt
```

## Run the tests

From the project root, run:

```bash
python -m unittest discover -s tests -v
```

At the initial Milestone 5 checkpoint, the reported test result was **110 tests passing** with Python 3.13.2 and `cryptography` 50.0.2.

## Current limitations

OwnChain is a local educational prototype, not a production cryptocurrency.

What Milestone 6 does and does not cover:

- **Replay protection** is implemented *within a single validated linear-history
  replay*: per-account sequential nonces reject duplicate or out-of-order
  transactions, and chain-ID-bound signatures tie messages to one chain.
- Nonces do **not** solve competing-chain or network double-spend problems
  without consensus. A signed transaction can still be reintroduced into a
  fresh ledger that has not seen it.

It does not yet implement:

- Peer-to-peer networking or distributed consensus, including a fork-choice rule.
- A complete, chain-defined coin issuance or reward mechanism.
- Transaction fees or mining.
- Encrypted private-key storage, wallet recovery, or seed phrases.
- Production-grade threat modeling, auditing, or security guarantees.

Initial ledger balances are supplied as trusted external state, so the chain does not yet determine the entire monetary state independently.

- **Stateful block validation** (`Ledger.apply_block`) trusts a caller-supplied predecessor and prior `LedgerState`; it does not re-derive provenance and provides no consensus or fork-choice rule on its own.

Digital signatures prove control of a private key; they do not establish trustworthiness. Hash links, signatures, and nonces alone do not provide a complete decentralized consensus system.

**Do not use this prototype to store or transfer real funds.**

## Design documentation

The `docs/decisions/` directory records the reasoning behind the initial architecture:

- ADR 001 — Block hashing
- ADR 002 — Chain integrity
- ADR 003 — Transaction model
- ADR 004 — Account-based ledger
- ADR 005 — Wallets and digital signatures
- ADR 006 — Transaction nonces and replay protection
- ADR 007 — Stateful block validation

## Project roadmap

Completed milestones:

- [x] Block integrity and SHA-256 hashing
- [x] Hash-linked chain validation
- [x] Transaction data model
- [x] Account-based ledger and balance checks
- [x] Wallets, Ed25519 signatures, and transaction authorization
- [x] Transaction nonces and replay protection (sequential per-account nonces, chain-ID-bound signatures, pure `LedgerState` replay)
- [x] Stateful block validation (`Ledger.apply_block()` validates a candidate block against its predecessor and prior state, returning a new immutable `LedgerState` without mutating the supplied one; `Ledger.replay()` delegates through it)

No single next milestone has been selected yet.

Further work will explore issuance, mining, networking, consensus, security testing, and performance evaluation.

## License

No license has been selected yet. Until one is added, do not assume that the repository grants permission to reuse, modify, or redistribute its contents.
