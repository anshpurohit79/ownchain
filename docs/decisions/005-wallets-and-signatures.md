# ADR 005: Wallets, Digital Signatures, and Transaction Authorization

- **Status:** Accepted
- **Date:** 2026-10-13
- **Scope:** `core/wallet.py` (`Wallet`), `core/signed_transaction.py`
  (`SignedTransaction`), `core/ledger.py` updates, and tests.

## Context

The ledger currently accepts unsigned `{sender, recipient, amount}` records.
This milestone adds cryptographic proof that a transaction's sender controls
the account being debited, while keeping the educational scope minimal.

## Dependency and environment

- Added dependency: ``cryptography`` (Ed25519).
- Python version: 3.13.2 (recorded from the environment).
- Tested dependency range: ``cryptography>=50.0.2,<51``.
- Installation procedure (run in a fresh virtual environment):

  ```bash
  python -m venv .venv
  source .venv/bin/activate      # Windows: .venv\\Scripts\\activate
  pip install -r requirements.txt
  pip install -r requirements-dev.txt   # if a dev requirement file is used
  ```

- Compatibility is verified only after a clean install and a full test run
  in that environment. Until then, compatibility claims are not made.

## Transaction architecture

- `core/transaction.py` keeps its existing unsigned `Transaction` API intact.
  It remains the transfer description.
- `core/signed_transaction.py` introduces `SignedTransaction`, which owns
  strict signed-record parsing, structural validation, canonical payload
  serialization, dictionary serialization, and signature verification.
- A wallet-generated transaction is created from an unsigned `Transaction`
  through `Wallet.sign_transaction(transaction)`.
- The ledger rejects unsigned transaction dictionaries and accepts only
  properly validated signed records.
- Existing `Transaction` tests and APIs are retained; tests are updated only
  where the transaction schema changes.

## Cryptographic design and signed payload

- Key type: Ed25519. Signing and verification use the ``cryptography``
  package; no elliptic-curve primitives are implemented by hand.
- Wallet-derived address rule:

    address = SHA-256(public_key_bytes).digest()[:20].hex()

  This is a 40-character lowercase hex string.

- Signed payload bytes are deterministic UTF-8 JSON containing exactly:

    sender, recipient, amount, public_key

  The `signature` field is excluded from the payload being signed.

- Full payload JSON is sorted by key, uses compact separators, and UTF-8.
- `amount` is a strictly positive integer (`bool` rejected as an integer
  subclass).
- Public key encoding: UNPADDED base64url, decodes to 32 bytes.
- Signature encoding: UNPADDED base64url, decodes to 64 bytes.
- Sender and recipient: exactly 40 lowercase hex characters.

## Verification

`SignedTransaction.verify()`:

1. Derives the address from the transaction's embedded public key.
2. Checks the derived address equals `sender`; mismatch raises
   `InvalidTransactionError`.
3. Verifies the signature against the embedded public key and the canonical
   payload; invalid signature raises `InvalidSignatureError`.

Malformed data or address mismatch raises `InvalidTransactionError`.
Structurally valid records with invalid signatures raise
`InvalidSignatureError`.

## Ledger integration

- Ledger bootstrap balance keys must be valid wallet addresses.
- Ledger rejects unsigned records; it reconstructs `SignedTransaction`
  records, verifies address/public-key correspondence and signatures, then
  checks balances.
- All earlier invariants remain: replay resets from the original bootstrap
  snapshot, working state is discarded on failure, transactions are ordered,
  sufficient-funds checks apply, and self-transfers require funds but leave
  the sender's balance unchanged.

## Security exclusions

This milestone does not implement:

- Transaction nonces or replay protection.
- Private-key encryption or recovery phrases.
- A finished issuance/reward mechanism.
- Transaction fees.
- Mining or proof-of-work.
- Peer-to-peer networking.
- Consensus.
- Real-funds use: this is an educational prototype and not ready for real
  funds. Signatures prove control of a key, not that the key owner is
  trustworthy.
