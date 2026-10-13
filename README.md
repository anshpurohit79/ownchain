# OwnChain

**An educational cryptocurrency and blockchain implementation built from scratch in Python.**

OwnChain is a learning-focused project exploring how blockchain systems work internally, from cryptographic hashing and linked blocks to transaction validation, account balances, and digitally signed payments.

The goal is to understand and implement the fundamental components rather than build a token on an existing blockchain.

> **Status:** Educational prototype. Not suitable for real funds or production use.

## Features

- **Block integrity:** SHA-256 hashes of deterministic JSON representations of block contents.
- **Chain validation:** Sequential block indices, previous-hash links, genesis rules, and per-block integrity checks.
- **Transaction model:** Validated transfers using positive integer amounts.
- **Account-based ledger:** Ordered transaction replay, sufficient-funds validation, and deterministic balance calculations.
- **Ed25519 signatures:** Wallet-generated digital signatures and public-key-based sender authorization.
- **Address derivation:** Deterministic account addresses derived from public keys.
- **Strict transaction encoding:** Validated transaction fields and canonical base64url encoding for public keys and signatures.
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
| `core/ledger.py` | Transaction verification, balance validation, and deterministic replay |
| `core/exceptions.py` | Shared errors for invalid chains, transactions, signatures, and insufficient funds |

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

It does not yet implement:

- Transaction nonces or replay protection. A valid signed transaction can be applied more than once.
- A complete, chain-defined coin issuance or reward mechanism.
- Transaction fees or mining.
- Peer-to-peer networking or distributed consensus.
- Encrypted private-key storage, wallet recovery, or seed phrases.
- Production-grade threat modeling, auditing, or security guarantees.

Initial ledger balances are supplied as trusted external state, so the chain does not yet determine the entire monetary state independently.

Digital signatures prove control of a private key; they do not establish trustworthiness. Hash links and signatures alone do not provide a complete decentralized consensus system.

**Do not use this prototype to store or transfer real funds.**

## Design documentation

The `docs/decisions/` directory records the reasoning behind the initial architecture:

- ADR 001 — Block hashing
- ADR 002 — Chain integrity
- ADR 003 — Transaction model
- ADR 004 — Account-based ledger
- ADR 005 — Wallets and digital signatures

## Project roadmap

Completed milestones:

- [x] Block integrity and SHA-256 hashing
- [x] Hash-linked chain validation
- [x] Transaction data model
- [x] Account-based ledger and balance checks
- [x] Wallets, Ed25519 signatures, and transaction authorization

Next planned milestone:

- [ ] Transaction nonces and replay protection

Further work will explore issuance, mining, networking, consensus, security testing, and performance evaluation.

## License

No license has been selected yet. Until one is added, do not assume that the repository grants permission to reuse, modify, or redistribute its contents.
