# OwnChain Protocol Specification — v1 (TEMPLATE)

> **Status: DRAFT TEMPLATE.** This document defines the structure of the
> OwnChain v1 protocol specification. Every protocol parameter that has
> not been decided yet is explicitly marked **`TBD`**. No values in this
> document are final, and no values have been invented to fill gaps.

## 1. Overview

### 1.1 Purpose
TBD — one-paragraph summary of what OwnChain is and why it exists.

### 1.2 Design goals
TBD — ordered list of goals (e.g. decentralization, throughput, privacy).

### 1.3 Non-goals
TBD — what OwnChain v1 explicitly will not do.

## 2. Terminology
TBD — glossary of terms used in this specification.

## 3. Cryptographic primitives

| Item | Choice | Status |
| --- | --- | --- |
| Hash function | TBD | Not decided |
| Signature scheme | TBD | Not decided |
| Key derivation | TBD | Not decided |
| Address encoding | TBD | Not decided |

Note: no cryptographic library has been selected or integrated yet.

## 4. Consensus

| Parameter | Value | Status |
| --- | --- | --- |
| Consensus model | TBD | Not decided |
| Proof-of-work algorithm (if any) | TBD | Not decided |
| Difficulty adjustment algorithm | TBD | Not decided |
| Target block time | TBD | Not decided |
| Finality rules | TBD | Not decided |
| Fork choice rule | TBD | Not decided |
| Validator/miner incentives | TBD | Not decided |

Note: RandomX and other proof-of-work constructions are *not* selected
and *not* integrated at this stage.

## 5. Ledger parameters

| Parameter | Value | Status |
| --- | --- | --- |
| Native unit name / symbol | TBD | Not decided |
| Smallest unit granularity | TBD | Not decided |
| Maximum supply | TBD | Not decided |
| Issuance / emission schedule | TBD | Not decided |
| Fee model | TBD | Not decided |
| Coinbase/maturity rules | TBD | Not decided |

## 6. Block structure

| Field | Type | Status |
| --- | --- | --- |
| Block header fields | TBD | Not decided |
| Transaction commitment | TBD | Not decided |
| Parent reference | TBD | Not decided |
| Timestamp rules | TBD | Not decided |
| Maximum block size | TBD | Not decided |

## 7. Transaction structure

| Field | Type | Status |
| --- | --- | --- |
| Inputs | TBD | Not decided |
| Outputs | TBD | Not decided |
| Amounts / encoding | TBD | Not decided |
| Signatures | TBD | Not decided |
| Replay / nonce rules | TBD | Not decided |
| Validation rules | TBD | Not decided |

## 8. Network / transport

| Item | Value | Status |
| --- | --- | --- |
| Peer-to-peer transport | TBD | Not decided |
| Discovery mechanism | TBD | Not decided |
| Message formats | TBD | Not decided |
| Default ports | TBD | Not decided |

Note: no networking library has been selected or integrated yet.

## 9. Wallet & key management

| Item | Value | Status |
| --- | --- | --- |
| Keystore format | TBD | Not decided |
| Backup/recovery scheme | TBD | Not decided |
| Signing interface | TBD | Not decided |

## 10. Genesis / bootstrapping

| Parameter | Value | Status |
| --- | --- | --- |
| Genesis block definition | TBD | Not decided |
| Chain identifier | TBD | Not decided |
| Bootstrapping peers / distribution | TBD | Not decided |

## 11. Security considerations
TBD — threat model, known risks, and mitigations.

## 12. Open questions
- All items in sections 3–10 are open; they are marked TBD deliberately.
- Decision process/owners for each TBD: TBD.

## 13. Change log
- v1 template created — all protocol parameters left as TBD.
