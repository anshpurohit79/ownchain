# OwnChain Protocol v1 — Experimental Network Baseline

**Status:** Consolidated review revision dated 2026-10-30. This document specifies the experimental-v1 consensus baseline adopting a hybrid shielded-first architecture that supports both shielded (Orchard V2) and transparent transactions using the same native currency (OWN). Shielded transactions are the default wallet experience; transparent transactions remain available as an explicit user choice. This specification integrates ADR-004 (Shielded-First Hybrid Architecture, PROPOSED) with the existing transparent-account ledger (ADR-001, SUPERSEDED) and guardian governance (ADR-002). All mechanisms enforce one global issuance cap and correct value conservation at both pool boundaries. This is an experimental network specification; it is **not** a declaration that OwnChain is production-secure or ready for a mainnet holding valuable funds.

**Decision rule:** The v1 baseline stays fixed unless a reproducible correctness, security, legal/licensing, or feasibility problem is demonstrated. Changes require a written decision record and updated test vectors. Do not add mechanisms because they sound interesting.

---

## 1. Overview

### 1.1 Purpose
OwnChain is an independent, permissionless, native-coin blockchain experiment. Its v1 engineering objective is to build and operate a real multi-node network with CPU-oriented proof of work and a hybrid ledger supporting both shielded (Orchard V2) and transparent account-based transactions using the same native currency (OWN). It is not a token on another chain. No claim is made that OwnChain is more private, decentralised, secure, or useful than established networks.

### 1.2 Ordered design goals
1. Correct, deterministic consensus that independent nodes can verify.
2. A working, permissionless peer-to-peer network and native coin with no premine or founder-only mint authority.
3. Shielded-first hybrid ledger supporting both Orchard V2 shielded transfers (default wallet experience) and transparent account ledger (Ed25519 authentication, deterministic composite `state_root`, 100-block coinbase maturity tracking, and opt-in per-account guardian security per ADR-002 and ADR-004).
4. CPU-oriented proof of work with public, deterministic validation rules.
5. Reproducible builds, protocol tests, and an auditable release process.

### 1.3 Non-goals for v1
- Smart contracts, EVM compatibility, general-purpose scripting, tokens, bridges, or cross-chain swaps.
- Proof of stake, committee consensus, proof of useful work, inclusion-list mechanisms, or bespoke zero-knowledge circuits.
- Claims of anonymity against network-level traffic analysis, a global observer, or a powerful mining majority.
- A mainnet launch, exchange listing, price target, or adoption guarantee before a separate security and launch review.

---

## 2. Terminology

- **Atom:** The smallest indivisible unit of the native coin ($10^{-8}$ OWN).
- **OWN:** The native coin's provisional display ticker ($1\text{ OWN} = 100,000,000\text{ atoms}$).
- **Transparent address:** A 32-byte address derived as $\text{BLAKE2b-256}(\text{UTF8("OwnChain/Address/v1")} \parallel ed25519\_public\_key[32])$.
- **Transparent account:** An account state holding balance (atoms), nonce, allowance and window usage, freeze/recovery state, guardian configuration, pending transfer records, and coinbase maturity tranches.
- **Orchard commitment root:** The 32-byte root committing to the Orchard note commitment tree (pinned crate `orchard = 0.16.0`), as committed to the block header.
- **Shielded note:** A note in the Orchard commitment tree, consisting of a ciphertext and value commitment, spendable by knowledge of the note's spending authorization.
- **Nullifier:** A unique value produced by a shielded spend; consumption of a nullifier prevents double-spending of the associated note.
- **state_root:** A 32-byte hash committed to the block header at offset 106. It is the composite state root committing to (1) transparent account-state tree root, (2) Orchard commitment-tree root, (3) nullifier-set Merkle root, and (4) shielded pool balance commitment via $\text{BLAKE2b-256}(\text{UTF8("OwnChain/CompositeStateRoot/v1")} \parallel T\_root \parallel O\_root \parallel NF\_root \parallel S\_comm)$ (see ADR-004 §7).
- **transaction_root:** A 32-byte hash committed to the block header that commits to all transactions included in the block in canonical block order, computed via RFC 6962-style recursive-split Merkle tree (see §6.2).
- **Coinbase maturity tranche:** A canonical record tracking an immature coinbase reward ($coinbase\_tx\_id, amount, unlock\_height = height + 100$) in the miner's account state until it matures.
- **Spendable balance:** The mature spendable balance of an account, defined precisely as $balance - \sum_{t \in coinbase\_tranches} t.amount$. Immature coinbase value cannot be spent even when combined with mature funds in the same account.
- **Pending transfer record:** A record representing an in-flight transfer under guardian protection that reserves only its own principal until its release height, leaving the recipient's existing unrelated funds spendable.
- **Target / difficulty:** The threshold and work requirement used to validate proof of work.
- **Cumulative work:** The sum of accepted per-block work along a chain; used for fork choice.
- **Experimental network:** The local development network (`devnet`) and subsequent public testnet. Test coins have no promised monetary value.
- **RFC 6962-style Merkle tree:** A hash tree where leaf and node hashing uses BLAKE2b-256 with domain separation (raw UTF-8 domain prefixes, no length prefix/terminator), recursive split at the largest power-of-2 strictly less than node count, with no odd-leaf duplication.

---

## 3. Cryptographic primitives

| Purpose | v1 decision | Requirements |
|---|---|---|
| General protocol hash | BLAKE2b with 32-byte output (BLAKE2b-256) | Domain-separate every OwnChain hash use. Specify exact byte encodings before implementation. |
| Proof of work | RandomX **algorithm v1**, using reference implementation release `v1.2.3` | RandomX algorithm v2 is not part of OwnChain v1. Use the v1.2.3 `configuration.h` defaults except `RANDOMX_ARGON_SALT`, which is the exact byte string `OwnChain-PoW-v1`. No other RandomX parameter may differ. Build from the pinned source commit `12f2c2ffe2108d6cf54c391fee33c8bc3646cdab` (RandomX v1.2.3); use the upstream-supported build configuration and record compiler/build flags in the implementation manifest. Verify every non-genesis block independently and publish cross-platform golden vectors before enabling mining. **Production (testnet/mainnet) RandomX configuration is a pre-public-testnet gate; the custom salt `OwnChain-PoW-v1` remains devnet-only. Salt match alone does not establish merge-mining feasibility.** |
| Account signatures | Ed25519 (standard RFC 8032) | Public keys are 32 bytes; signatures are 64 bytes. Signatures bind to the transaction signing preimage domain-separated by `OwnChain/TxAuth/v1` and including the active `chain_id`. |
| Address derivation | BLAKE2b-256 | `address = BLAKE2b-256(UTF8("OwnChain/Address/v1") || ed25519_public_key[32])`. |
| Address display encoding | Bech32m | Versioned network-specific human-readable prefix (`owndev` for devnet, `own` for testnet) containing the 32-byte transparent address. |
| Node identity | libp2p identity key, separate from coin ownership | Peer identity never grants transaction or consensus privileges. |

---

## 4. Consensus

| Parameter | v1 decision |
|---|---|
| Consensus model | Nakamoto-style proof of work; no validator set or privileged operator |
| PoW algorithm | RandomX algorithm v1; reference implementation release `v1.2.3`; v2 is excluded |
| Target block interval | 120 seconds |
| Difficulty retarget | Every block; exact algorithm defined in §4.1. The reference is the CryptoNote/Monero `next_difficulty` algorithm with a 720-sample window, 15-block lag, trimming to 600 samples, and a 120-second target. |
| RandomX seed rotation | Follow RandomX's recommended delayed key-block schedule. For block height `h`, `key_height(h) = 0` when `h < 64`; otherwise `key_height(h) = 2048 × floor((h − 64) / 2048)`. The RandomX key is the block ID at that height. This means key block 0 is used first, and key block 2048 becomes active at height 2112. |
| PoW check | Interpret RandomX's 32-byte result as a little-endian unsigned integer `h`; accept when `h <= floor((2^256 - 1) / difficulty)`. Difficulty must be the network-computed expected value, not a miner-selected value. |
| Per-block work | Each non-genesis block contributes its validated expected `difficulty`; genesis contributes zero work. Cumulative work is a checked unsigned 256-bit sum. |
| Fork choice | Valid chain with greatest cumulative work. If equal, compare block-ID sequences from genesis and select the lexicographically smaller sequence at the first differing height. This gives a deterministic total tie-break. |
| Finality | Probabilistic only; no block has absolute finality. Wallet confirmation counts are policy, not a consensus guarantee. |
| Timestamp rule | A block timestamp must be greater than the upper median of the available timestamps in the last 11 ancestor blocks (up to 11 for early heights); sort ascending and choose index `len / 2`. A node MUST defer accepting or relaying a block whose timestamp is more than two hours ahead of its adjusted local time, and retry it when local time catches up. |
| Network authority | No founder key, admin key, or company approval is required for valid transactions or blocks. |
| Subsidy | See §5. No premine, genesis allocation, developer tax, or founder-controlled issuance key. |

RandomX's official project documentation recommends a 2048-block key period with a 64-block delay and recommends a unique configuration per project. OwnChain v1 uses the RandomX v1.2.3 configuration with only the Argon2 salt changed to the exact UTF-8 bytes `OwnChain-PoW-v1`; all other parameter values come from that release's `configuration.h`. The custom salt `OwnChain-PoW-v1` remains devnet-only pending the production PoW gate.

### 4.1 Exact difficulty algorithm

For a candidate block at height `h`, use only ancestors at heights `max(0, h - 735)` through `h - 16`, inclusive. This excludes the most recent 15 ancestors (the lag) and provides at most 720 samples. If fewer than two samples remain, expected difficulty is `1`. For 2 or more samples, keep the samples in chronological block-height order for the cumulative-work array. Copy their timestamps and sort that timestamp array ascending. Let `n` be the sample count. If `n <= 600`, set `cut_begin = 0` and `cut_end = n`; otherwise set `cut_begin = floor((n - 600 + 1) / 2)` and `cut_end = cut_begin + 600`. The exclusive end index is used. Let `time_span = sorted_timestamps[cut_end - 1] - sorted_timestamps[cut_begin]`; if this equals zero, use `1`. Let `C_i` be cumulative accepted work through the sample block at height `i`, with genesis cumulative work equal to zero; let `total_work = C_(cut_end - 1) - C_(cut_begin)`, using sample blocks in block-height order (do not reorder cumulative work when sorting timestamps). The expected difficulty is `ceil(total_work * 120 / time_span)`. All intermediate arithmetic is checked and must not wrap. If the computed result is zero or exceeds `u128::MAX`, the implementation must fail closed and report a protocol-boundary error; it must never silently clamp or wrap. This is implemented in `src/difficulty.rs`.

---

## 5. Ledger parameters

| Parameter | v1 decision |
|---|---|
| Native coin | OwnCoin; provisional ticker `OWN` |
| Smallest unit | `1 OWN = 100,000,000 atoms` ($10^8$ atoms) |
| Genesis allocation | Zero. Genesis creates no spendable coins. |
| Starting block subsidy | 10 OWN per block ($1,000,000,000$ atoms) for block heights 1 through 1,050,000 |
| Halving interval | Every 1,050,000 blocks; subsidy halves by integer division by 2 at each era: `subsidy = 1,000,000,000 >> era` atoms, where `era = floor((h - 1) / 1,050,000)` |
| Hard cumulative issuance cap | 21,000,000 OWN ($2,100,000,000,000,000$ atoms). Integer floor division yields an actual cumulative total of $2,099,999,986,350,000$ atoms across eras 0 through 29, strictly below the 21,000,000 OWN hard cap. |
| Subsidy exhaustion | At era 30 (height 31,500,001), the calculated subsidy drops to 0 atoms (`1,000,000,000 >> 30 == 0`). After exhaustion, block producers receive only included transaction fees; the subsidy portion of the coinbase is zero. |
| Tail emission | None in v1. After integer subsidy reaches zero, miner revenue relies entirely on transaction fees. |
| Minimum fee policy | Minimum fee: `max(1, 100 * canonical_signed_tx_size_bytes)` atoms. Transactions offering less than this minimum are invalid and rejected by consensus. |
| Fee recipient | Included in the block producer's valid coinbase payout; fees are transfers of existing value from transaction spenders, not new issuance. |
| Coinbase payout | At most the scheduled block subsidy plus the sum of valid included transaction fees: `coinbase_payout <= scheduled_subsidy + sum(fees)`. The block producer may claim less than this maximum, but cannot claim more. Unclaimed subsidy is permanently unissued. Payout is credited to the miner's account and recorded in an immature tranche. |
| Ordinary transfer maturity | 1 block. An ordinary transparent spend is spendable at or after the block height following inclusion ($h_{spendable} \ge h_{included} + 1$). |
| Coinbase maturity | 100 blocks. Tracked per-account via `coinbase_tranches` records ($coinbase\_tx\_id, amount, unlock\_height = height + 100$). An account's spendable balance is defined as $spendable\_balance = balance - \sum_{t \in coinbase\_tranches} t.amount$. Immature coinbase value cannot be spent under any circumstances, even when combined with previously mature funds in the same account ($h_{spendable} \ge h_{coinbase} + 100$). |
| New-recipient delay | 10 blocks. When guardian protection is enabled on the sender account, a first-time spend to a new recipient address reserves the transfer's principal in a pending record until `release_height = height + 10`. Unrelated recipient funds remain spendable. |
| Delayed withdrawal | 144 blocks. A withdrawal request reserves principal in a pending record until `release_height = height + 144`. At 120-second target block time, 144 blocks $\approx 4.8$ hours. |

---

## 6. Block structure

### 6.1 Canonical header fields

The v1 header is exactly 170 bytes, serialized in this order:

1. `version`: unsigned 16-bit integer, little-endian (`u16_le`), initially `1` (2 bytes).
2. `chain_id`: 32 bytes.
3. `height`: unsigned 64-bit integer, little-endian (`u64_le`) (8 bytes).
4. `parent_block_id`: 32 bytes; all zero bytes only for genesis.
5. `transaction_root`: 32 bytes (see §6.2).
6. `state_root`: 32 bytes, **composite state root** committing to transparent account-state, Orchard commitment-tree root, nullifier-state, and shielded pool accounting state (see ADR-004 §5). Occupies the former `orchard_commitment_root` slot.
7. `timestamp`: unsigned 64-bit Unix seconds, little-endian (`u64_le`) (8 bytes).
8. `difficulty`: unsigned 128-bit integer, little-endian (`u128_le`) (16 bytes).
9. `nonce`: unsigned 64-bit integer, little-endian (`u64_le`) (8 bytes).

$$2 + 32 + 8 + 32 + 32 + 32 + 8 + 16 + 8 = 170\text{ bytes}$$

All fixed-width integers are little-endian. No platform-dependent struct layout or default serializer output may define consensus encoding. The canonical block encoding is:

$$\text{header\_bytes}[170] \parallel tx\_count:\text{u32\_le} \parallel \text{repeated}(tx\_length:\text{u32\_le} \parallel tx\_bytes)$$

The 2,000,000-byte consensus block limit applies to this canonical encoding, including length prefixes, but excludes peer-to-peer transport framing. The RandomX PoW input is the 170 canonical header bytes, including the nonce. The block ID is:

$$\text{block\_id} = \text{BLAKE2b-256}(\text{UTF8("OwnChain/Block/v1")} \parallel \text{canonical\_header\_bytes}[170])$$

### 6.2 Merkle tree constructions

OwnChain uses two distinct, domain-separated Merkle constructions: the established **Block Transaction Merkle Tree** (M1-A baseline) for header `transaction_root`, and the **RFC 6962-style Recursive-Split Trees** for consensus state commitments (`state_root`).

#### A. Block Transaction Merkle Tree (M1-A Established Baseline)
Used exclusively for computing the 32-byte `transaction_root` in the 170-byte block header:
- **Hash algorithm:** BLAKE2b-256, 32-byte digest, unkeyed, unpersonalized.
- **Domain prefixes:**
  - `DOM_TX_EMPTY = UTF8("OwnChain/TxEmpty/v1")`
  - `DOM_TX_LEAF = UTF8("OwnChain/TxLeaf/v1")`
  - `DOM_TX_NODE = UTF8("OwnChain/TxNode/v1")`
- **Empty tree root:**
  $$\text{EmptyTxRoot} = \text{BLAKE2b-256}(\text{DOM\_TX\_EMPTY})$$
  Hex: `fd16146c2f34c74d29527832237269497a38619743bd4636411c6347cc41a602`
- **Leaf hash:**
  $$\text{TxLeafHash}(tx\_id) = \text{BLAKE2b-256}(\text{DOM\_TX\_LEAF} \parallel tx\_id[32])$$
- **Node hash:**
  $$\text{TxNodeHash}(left, right) = \text{BLAKE2b-256}(\text{DOM\_TX\_NODE} \parallel left[32] \parallel right[32])$$
- **Pairwise grouping:** Pairwise bottom-up grouping. When a level has an odd number of nodes, the final node is duplicated: $\text{TxNodeHash}(last, last)$.
- **Compatibility:** Bit-for-bit compatible with the established M1-A Rust implementation in `src/merkle.rs` and golden test vectors in `docs/test-vectors-m1a.json`. Historical M1-A vectors remain frozen.

#### B. State Commitments (RFC 6962 Recursive-Split Trees)
Used for transparent accounts, nullifiers, pool balance commitments, and the composite state root (`state_root`):
- **Domain prefixes (Transparent accounts):**
  - `DOM_EMPTY = UTF8("OwnChain/Merkle/Empty/v1")`
  - `DOM_LEAF = UTF8("OwnChain/Merkle/Leaf/v1")`
  - `DOM_NODE = UTF8("OwnChain/Merkle/Node/v1")`
- **Empty transparent tree root:**
  $$\text{EmptyStateRoot} = \text{BLAKE2b-256}(\text{DOM\_EMPTY})$$
  Hex: `208ea77bfce02fbe7248f21e5e297a7605d4df48b89d81d2f8cb9fe2f7b4ec97`
- **Leaf hash:**
  $$\text{StateLeafHash}(data) = \text{BLAKE2b-256}(\text{DOM\_LEAF} \parallel 0x00 \parallel data)$$
  Where $data = address[32] \parallel \text{canonical\_account\_state\_bytes}$. Accounts are sorted strictly by `address` ascending.
- **Node hash:**
  $$\text{StateNodeHash}(left, right) = \text{BLAKE2b-256}(\text{DOM\_NODE} \parallel 0x01 \parallel left[32] \parallel right[32])$$
- **Recursive split rule:** For $n$ leaves:
  - If $n = 0$: Root is $\text{EmptyStateRoot}$.
  - If $n = 1$: Root is $\text{StateLeafHash}(leaf[0])$.
  - If $n > 1$: Split at $k = 1 \ll ((n - 1)\text{.bit\_length}() - 1)$ (the largest power of 2 strictly less than $n$):
    $$left\_root = \text{TreeHash}(leaves[0..k])$$
    $$right\_root = \text{TreeHash}(leaves[k..n])$$
    $$root = \text{StateNodeHash}(left\_root, right\_root)$$
  - No odd-leaf duplication is performed.
- **Nullifier-set tree:** Unique consumed nullifiers sorted lexicographically ascending. Uses recursive-split with domain prefixes:
  - `DOM_NF_EMPTY = UTF8("OwnChain/Nullifier/Empty/v1")` (Empty root: `BLAKE2b-256(DOM_NF_EMPTY)`)
  - `DOM_NF_LEAF = UTF8("OwnChain/Nullifier/Leaf/v1")` ($\text{BLAKE2b-256}(\text{DOM\_NF\_LEAF} \parallel 0x00 \parallel nullifier[32])$)
  - `DOM_NF_NODE = UTF8("OwnChain/Nullifier/Node/v1")` ($\text{BLAKE2b-256}(\text{DOM\_NF\_NODE} \parallel 0x01 \parallel left[32] \parallel right[32])$)
- **Shielded pool balance commitment:**
  $$C_{\text{pool}} = \text{BLAKE2b-256}(\text{UTF8("OwnChain/PoolBalance/v1")} \parallel \text{shielded\_pool\_balance}:\text{u128\_le})$$
- **Composite state root:**
  $$\text{state\_root} = \text{BLAKE2b-256}(\text{UTF8("OwnChain/CompositeStateRoot/v1")} \parallel transparent\_root \parallel orchard\_root \parallel nullifier\_root \parallel pool\_balance\_commitment)$$
  Where the domain prefix is exactly 30 raw UTF-8 bytes (no `0x0e` prefix).

### 6.3 Limits and ordering

- Maximum canonical serialized block size: 2,000,000 bytes.
- Maximum canonical serialized transaction size: 1,000,000 bytes.
- Transactions are serialized and committed in the exact order they appear in the block. Duplicate transaction IDs within a block or against the selected chain are invalid.
- Exactly one coinbase transaction is required at transaction index 0 in every non-genesis block.
- Ordinary transfer maturity: 1 block (spendable at height $\ge h_{included} + 1$).
- Coinbase maturity: 100 blocks (spendable at height $\ge h_{coinbase} + 100$). Tracked per-account via `coinbase_tranches`. Spends attempting to consume immature rewards exceeding `spendable_balance` are invalid.
- New-recipient delay: 10 blocks (under sender guardian protection).
- Delayed withdrawal: 144 blocks (under sender guardian protection).
- **Orchard 10-block ancestor anchor window policy:**
  - A shielded transaction may reference an Orchard commitment tree root from any of the 10 most recent ancestor blocks ($[h-10, h-1]$).
  - A root created by another transaction in the same block is not a valid anchor for that block.
  - The anchor must belong to the selected parent chain; reorganizations invalidate anchors not on the selected branch.
  - Duplicate nullifiers are permanently rejected even if transactions reference different valid anchors.
- **Cross-pool transfers:** Shielded (Orchard V2) and transparent value are atomically fungible via cross-pool transfers with enforced value conservation. Two transfer types are defined:
  - **Transparent-to-shielded (Type 6):** A transparent sender burns atoms from their balance; the exact atom amount must equal the total commitment value of newly created shielded notes, plus fee paid to the miner: $-(A + F)$. The fee is transferred to the block producer. Each transfer includes a nonce to prevent replay.
  - **Shielded-to-transparent (Type 7):** A shielded spender spends a note, releasing atoms to a transparent recipient: $+A$. The note's commitment value is transferred; a fee is deducted and paid to the block producer: $-(A + F)$. Each spend consumes a unique nullifier to prevent double-spending.
- **Cross-pool value conservation:** Strict invariant $T + S = I$ holds at every block boundary.

### 6.4 Genesis

Genesis has height 0, a zero parent ID (`[0u8; 32]`), no transactions, no subsidy, difficulty `1`, nonce `0`, timestamp `1792454400` (`2026-10-20T00:00:00Z`), `transaction_root = EmptyRoot`. Each network has a separate `chain_id` derived as $\text{BLAKE2b-256}(\text{UTF8("OwnChain/<network-name>/v1")})$. Genesis is a fixed protocol constant and skips RandomX validation. Startup must never regenerate genesis from the current clock.

The genesis `state_root` is calculated by evaluating all four component genesis commitments:
1. `transparent_root` = $\text{BLAKE2b-256}(\text{UTF8("OwnChain/Merkle/Empty/v1")})$
2. `orchard_root` = `ae2935f1dfd8a24aed7c70df7de3a668eb7a49b1319880dde2bbd9031ae5d82f` (pinned empty tree anchor)
3. `nullifier_root` = $\text{BLAKE2b-256}(\text{UTF8("OwnChain/Nullifier/Empty/v1")})$
4. `pool_balance_commitment` = $\text{BLAKE2b-256}(\text{UTF8("OwnChain/PoolBalance/v1")} \parallel 0:\text{u128\_le})$

Then combining them via the canonical composite formula:
$$\text{genesis\_state\_root} = \text{BLAKE2b-256}(\text{UTF8("OwnChain/CompositeStateRoot/v1")} \parallel transparent\_root \parallel orchard\_root \parallel nullifier\_root \parallel pool\_balance\_commitment)$$

---

## 7. Transaction structure and Transparent Account Ledger

### 7.0 Canonical outer envelope

Every transaction begins with:

$$\text{tx\_type}:\text{u8} \parallel \text{tx\_version}:\text{u16\_le} \parallel \text{chain\_id}:[u8; 32]$$

- `tx_type`: unsigned 8-bit integer identifying transaction type.
- `tx_version`: unsigned 16-bit integer, little-endian, fixed at `1` for OwnChain v1.
- `chain_id`: 32-byte active network ID. A transaction created for one network is invalid on any other network.

### 7.1 Transaction types and wire encoding

V1 defines the following authoritative transaction types:

| Type | Name | Purpose | `valueBalanceOrchard` | Authorization Mechanism |
|---|---|---|---|---|
| `0` | `Coinbase` | Block subsidy + fees | $v = 0$ | Block proof-of-work |
| `1` | `TransparentTransfer` | Transparent account transfer | $v = 0$ | Ed25519 signature of sender |
| `2` | `ConfigureGuardians` | Enable/configure guardian protection | $v = 0$ | Ed25519 signature of account owner |
| `3` | `GuardianAction` | Execute approved guardian action | $v = 0$ | Quorum of Ed25519 signatures (3-of-7 or 4-of-7) |
| `4` | `CancelPendingTransfer` | Cancel an unexpired pending transfer | $v = 0$ | 4-of-7 guardian quorum signatures |
| `5` | `ShieldedTransfer` | Pure shielded transfer within Orchard | $v = +fee\_atoms$ | Orchard spend auth + binding signature |
| `6` | `TransparentToShielded` | Deposit transparent funds into Orchard | $v = -shielded\_amount$ | Ed25519 signature (+ 4-of-7 if protected) + binding sig |
| `7` | `ShieldedToTransparent` | Withdraw Orchard funds to transparent | $v = +(release\_amount + fee\_atoms)$ | Orchard spend auth + binding signature |

#### Type 0: Coinbase
Position 0 in every non-genesis block. Collects actual claimed block subsidy plus included transaction fees.
- Payload:
  $$\text{height}:\text{u64\_le} \parallel \text{recipient}:[u8; 32] \parallel \text{payout\_atoms}:\text{u64\_le}$$
- Total canonical size: $1 + 2 + 32 + 8 + 32 + 8 = 83\text{ bytes}$.
- Verification: Authorized by proof of work on the block header. Payout must satisfy:
  $$\text{payout\_atoms} \le \text{scheduled\_subsidy}(height) + \sum_{tx \in block \setminus \{0\}} fee\_atoms(tx)$$
- State transition: Actual claimed subsidy advances cumulative issuance ($I_h = I_{h-1} + actual\_subsidy\_claimed_h$). Payout is credited to the recipient's `balance` and a new `CoinbaseTranche` record is created with $unlock\_height = height + 100$. Fees do NOT increase issuance. Underclaimed subsidy is permanently unissued. Overclaimed subsidy is rejected.

#### Type 1: Transfer (Ordinary & Protected Transfers)
Transfers atoms between transparent accounts.
- Unsigned payload:
  $$\text{sender\_pubkey}:[u8; 32] \parallel \text{recipient}:[u8; 32] \parallel \text{amount}:\text{u128\_le} \parallel \text{fee\_atoms}:\text{u64\_le} \parallel \text{nonce}:\text{u64\_le}$$
- Wire encoding (signed):
  $$\text{envelope}[35] \parallel \text{payload}[96] \parallel \text{signature}:[u8; 64]$$
- Total canonical size: $35 + 96 + 64 = 195\text{ bytes}$.
- Minimum fee: $\max(1, 100 \times 195) = 19,500\text{ atoms}$.

#### Type 2: ConfigureGuardians
Enables or reconfigures the opt-in 7-guardian protection set for an account.
- Payload:
  $$\text{account\_pubkey}:[u8; 32] \parallel \text{nonce}:\text{u64\_le} \parallel \text{fee\_atoms}:\text{u64\_le} \parallel \text{guardian\_keys}:[u8; 224] \parallel \text{new\_recipient\_delay}:\text{u32\_le} \parallel \text{withdrawal\_delay}:\text{u32\_le} \parallel \text{allowance\_limit}:\text{u128\_le} \parallel \text{allowance\_window\_len}:\text{u64\_le} \parallel \text{recovery\_key}:[u8; 32] \parallel \text{owner\_sig}:[u8; 64]$$
- Initial configuration requires owner signature. Reconfiguring an existing active guardian set requires owner signature plus a 4-of-7 guardian quorum.

#### Type 3: GuardianAction
Executes governance actions authorized by guardian quorum signatures:
- Payload:
  $$\text{account}:[u8; 32] \parallel \text{action\_type}:\text{u8} \parallel \text{fee\_atoms}:\text{u64\_le} \parallel \text{param\_len}:\text{u32\_le} \parallel \text{params} \parallel \text{quorum\_count}:\text{u8} \parallel \text{repeated}(\text{guardian\_index}:\text{u8} \parallel \text{sig}:[u8; 64])$$
- Action types and required quorums:
  - Strengthen protections (increase delays, decrease spend limit, lengthen window): **3-of-7 quorum**.
  - Weaken protections (decrease delays, increase spend limit, shorten window): **4-of-7 quorum**.
  - Freeze / Unfreeze: **4-of-7 quorum**.
  - Emergency recovery (transfer spendable balance to registered `recovery_key`): **4-of-7 quorum**.
  - Guardian set replacement / recovery key update: **4-of-7 quorum**.

#### Type 4: CancelPendingTransfer
Cancels an in-flight pending transfer before its release height.
- Payload:
  $$\text{sender\_pubkey}:[u8; 32] \parallel \text{transfer\_id}:[u8; 32] \parallel \text{fee\_atoms}:\text{u64\_le} \parallel \text{nonce}:\text{u64\_le} \parallel \text{sender\_sig}:[u8; 64] \parallel \text{quorum\_count}:\text{u8} \parallel \text{repeated}(\text{guardian\_index}:\text{u8} \parallel \text{sig}:[u8; 64])$$
- Requires sender signature and **4-of-7 guardian quorum**.
- State transition: Fee is debited from sender. The targeted pending transfer record is removed from `sender.pending_transfers`. Because transfer principal remained in `sender.balance` and was excluded only from `spendable_balance`, removal immediately restores spendability.

#### Type 5: ShieldedTransfer
Executes an Orchard-only shielded transaction. Spends and creates notes in the Orchard commitment tree without touching transparent account balances.
- Payload:
  $$\text{fee\_atoms}:\text{u64\_le} \parallel \text{orchard\_bundle\_bytes}$$
- Upstream value balance: Value leaves the shielded pool to pay the block producer fee:
  $$valueBalanceOrchard = +fee\_atoms > 0$$
- Pool delta:
  $$\text{shielded\_pool\_delta} = -valueBalanceOrchard = -fee\_atoms$$
- Authorization: ZK-SNARK Halo2 proofs (`FixedPostNu6_2`), RedPallas spend authorization signatures over action effects, and RedPallas binding signature over `OwnChain/TxAuth/v1`. Anchor must fall within the 10-block ancestor window $[h-10, h-1]$.
- State transition: $\text{shielded\_pool\_balance} \mathrel{-}= fee\_atoms$. Disclosed nullifiers are added to cumulative nullifier set. New note commitments are appended to the Orchard tree. The fee is credited to the block producer via block coinbase. Conservation $\Delta(T + S) = 0$ holds.

#### Type 6: TransparentToShielded
Moves value from a transparent account into the Orchard shielded pool.
- Payload:
  $$\text{sender\_pubkey}:[u8; 32] \parallel \text{nonce}:\text{u64\_le} \parallel \text{shielded\_amount}:\text{u128\_le} \parallel \text{fee\_atoms}:\text{u64\_le} \parallel \text{bundle\_len}:\text{u32\_le} \parallel \text{orchard\_bundle\_bytes} \parallel \text{sender\_sig}:[u8; 64] \parallel \text{quorum\_count}:\text{u8} \parallel \text{repeated}(\text{guardian\_index}:\text{u8} \parallel \text{sig}:[u8; 64])$$
- Upstream value balance: Value enters the shielded pool:
  $$valueBalanceOrchard = -shielded\_amount < 0$$
- Pool delta:
  $$\text{shielded\_pool\_delta} = -valueBalanceOrchard = +shielded\_amount$$
- Authorization: Sender Ed25519 signature and Orchard binding signature over `OwnChain/TxAuth/v1`. If the sender account is guardian-protected, a **4-of-7 guardian quorum** is strictly required. Output bundle verified via Orchard verifier (`FixedPostNu6_2`). Each action's SpendAuth signature is verified against the canonical authorization digest.
- State transition: Sender balance debited by $shielded\_amount + fee\_atoms$. Nonce incremented. $\text{shielded\_pool\_balance} \mathrel{+}= shielded\_amount$. Fee is paid to the block producer. All Orchard action nullifiers (including dummy-spend nullifiers derived under `Flags::SPENDS_DISABLED`) are checked for uniqueness within the transaction, rejected if already spent in candidate or chain state, and inserted into the active nullifier set. All Orchard action output commitments (including dummy outputs) are unconditionally appended to the incremental Orchard note commitment tree. Conservation $\Delta(T + S) = 0$ holds.

#### Type 7: ShieldedToTransparent
Moves value out of the Orchard shielded pool into a transparent recipient account.
- Payload:
  $$\text{recipient}:[u8; 32] \parallel \text{release\_amount}:\text{u128\_le} \parallel \text{fee\_atoms}:\text{u64\_le} \parallel \text{bundle\_len}:\text{u32\_le} \parallel \text{orchard\_bundle\_bytes}$$
- Upstream value balance: Value leaves the shielded pool to the recipient and block producer:
  $$valueBalanceOrchard = +(release\_amount + fee\_atoms) > 0$$
- Pool delta:
  $$\text{shielded\_pool\_delta} = -valueBalanceOrchard = -(release\_amount + fee\_atoms)$$
- Authorization: Orchard spend authorization signatures for all actions and binding signature over `OwnChain/TxAuth/v1`. Anchor must fall within the 10-block ancestor window $[h-10, h-1]$.
- State transition: Disclosed nullifiers (both real spends and dummy spends) are checked for uniqueness within the transaction and candidate block, rejected if already spent, and added to the cumulative nullifier set. All Orchard action output commitments (including dummy outputs under `Flags::OUTPUTS_DISABLED` and change note commitments) are unconditionally appended to the incremental Orchard note commitment tree. $\text{shielded\_pool\_balance} \mathrel{-}= (release\_amount + fee\_atoms)$. Recipient transparent balance credited by $release\_amount$. Fee is paid to the block producer. Guardian protections on the recipient do not restrict inbound transfers. Conservation $\Delta(T + S) = 0$ holds.

### 7.2 Address derivation and signing preimage

#### Address derivation
$$\text{address} = \text{BLAKE2b-256}(\text{UTF8("OwnChain/Address/v1")} \parallel ed25519\_public\_key[32])$$

#### Signing preimage
For any transaction signed by account owner or guardians, the signing preimage is:

$$\text{preimage} = \text{UTF8("OwnChain/TxAuth/v1")} \parallel chain\_id[32] \parallel \text{canonical\_unsigned\_tx\_bytes}$$

where `canonical_unsigned_tx_bytes` begins with `tx_type:u8 || tx_version:u16_le || chain_id:[u8;32]` and includes all consensus fields of the transaction except the signature(s). Signatures are verified as $\text{Ed25519Verify}(pubkey, preimage, signature)$. Binding `chain_id` into the preimage ensures cross-network replay protection.

The transaction ID is:

$$\text{tx\_id} = \text{BLAKE2b-256}(\text{UTF8("OwnChain/Tx/v1")} \parallel \text{canonical\_signed\_tx\_bytes})$$

### 7.3 Transparent account state and canonical serialization

Each transparent account state is canonically encoded with the following byte layout:

| Field | Type / Width | Byte Offset | Default Value | Description |
|---|---|---|---|---|
| `balance` | `u128_le` (16 bytes) | 0..16 | 0 | Total account balance in atoms (mature + immature coinbase) |
| `nonce` | `u64_le` (8 bytes) | 16..24 | 0 | Nonce incremented on each accepted spending transaction |
| `allowance_limit` | `u128_le` (16 bytes) | 24..40 | 0 | Max spendable atoms per window (0 = disabled/unlimited) |
| `allowance_window_start` | `u64_le` (8 bytes) | 40..48 | 0 | Block height where current window began |
| `allowance_window_len` | `u64_le` (8 bytes) | 48..56 | 0 | Window length in blocks (0 = disabled) |
| `allowance_spent` | `u128_le` (16 bytes) | 56..72 | 0 | Atoms spent in current window including fees |
| `is_frozen` | `u8` (1 byte) | 72..73 | 0 | 0 = unfrozen, 1 = frozen |
| `recovery_key` | `[u8; 32]` (32 bytes) | 73..105 | `00`*32 | Ed25519 recovery public key |
| `guardian_enabled` | `u8` (1 byte) | 105..106 | 0 | 0 = disabled, 1 = enabled |
| `new_recipient_delay` | `u32_le` (4 bytes) | 106..110 | 10 | Delay in blocks for first-time recipients |
| `withdrawal_delay` | `u32_le` (4 bytes) | 110..114 | 144 | Delay in blocks for withdrawal requests |
| `guardians` | `[u8; 224]` (224 bytes) | 114..338 | `00`*224 | Exactly 7 distinct Ed25519 guardian public keys |
| `pending_transfers_count` | `u32_le` (4 bytes) | 338..342 | 0 | Number of in-flight pending transfer records |
| `pending_transfers` | `repeated` (88 bytes each) | 342.. | empty | List of pending transfer records sorted by `transfer_id` ascending |
| `coinbase_tranches_count` | `u32_le` (4 bytes) | offset $P$ | 0 | Number of immature coinbase maturity records ($P = 342 + 88 \times pending\_count$) |
| `coinbase_tranches` | `repeated` (56 bytes each) | offset $P + 4$ | empty | List of immature coinbase tranches sorted by $(unlock\_height, coinbase\_tx\_id)$ |

**Pending transfer record layout (88 bytes):**
$$\text{transfer\_id}:[u8; 32] \parallel \text{recipient}:[u8; 32] \parallel \text{amount}:\text{u128\_le} \parallel \text{release\_height}:\text{u64\_le}$$

**Coinbase maturity record layout (56 bytes):**
$$\text{coinbase\_tx\_id}:[u8; 32] \parallel \text{amount}:\text{u128\_le} \parallel \text{unlock\_height}:\text{u64\_le}$$

- Standard account encoding size with 0 pending transfers and 0 coinbase tranches: **346 bytes**.
- Tranche deterministic ordering: sorted primarily by `unlock_height: u64` ascending, breaking ties by `coinbase_tx_id: [u8; 32]` ascending (raw byte comparison).
- Leaf payload in the state Merkle tree:
  $$\text{leaf\_payload} = address[32] \parallel \text{serialized\_account\_state}$$
- Accounts in the state tree are sorted strictly by `address` ascending (32-byte unsigned lexicographical comparison).

### 7.4 Coinbase maturity tracking and spendable balance

1. **Coinbase reward recording:** When a block is mined at height $h_{coinbase}$, its coinbase payout $P$ is credited to the recipient's `balance` and recorded in a new `CoinbaseTranche`:
   $$\text{CoinbaseTranche} = \{ coinbase\_tx\_id, amount: P, unlock\_height: h_{coinbase} + 100 \}$$
2. **Definition of spendable balance:** For any account at block height $H$:
   $$\text{immature\_coinbase\_balance}(H) = \sum_{t \in coinbase\_tranches, t.unlock\_height > H} t.amount$$
   $$\text{pending\_principal}(H) = \sum_{p \in pending\_transfers} p.amount$$
   $$\text{spendable\_balance}(H) = balance - \text{immature\_coinbase\_balance}(H) - \text{pending\_principal}(H)$$
3. **Consensus spend enforcement:** For any spending transaction submitted from an account at height $H$:
   $$\text{spend\_amount} + \text{fee\_atoms} \le \text{spendable\_balance}(H)$$
   A transaction attempting to spend more than `spendable_balance` is **invalid and rejected** (`ErrInsufficientSpendableBalance`), even when the account's total `balance` is sufficient. Immature coinbase value and pending principal cannot be spent or used for fees under any circumstances.
4. **Tranche maturity and removal:** At the beginning of block execution for height $H$, all tranches with $unlock\_height \le H$ mature and are removed from `coinbase_tranches`. Their amount remains in `balance` and automatically becomes spendable without requiring explicit transaction action.
5. **Reorganization rollback:** If a block containing a coinbase transaction is reorganized out, the corresponding tranche is removed from the miner's account and `balance` is decremented by $P$. If a chain reorganization rolls back past an unlock height, matured tranches are restored to immature status.

### 7.5 Guardian governance, recipient-lock semantics, and allowance windows

1. **Opt-in and per-account:** Guardian protection is opt-in per account. Guardians have authority only over the specific account that registered them; they possess no global authority over other accounts or chain consensus rules.
2. **Seven distinct keys:** An enabled guardian set consists of exactly 7 distinct Ed25519 public keys. Duplicate guardian keys in a set are invalid.
3. **Allowance window semantics and mathematical demonstration:**
   - Let $A_{\max}$ be `allowance_limit` (atoms) and $W$ be `allowance_window_len` (blocks).
   - The maximum permitted spending rate is:
     $$R = \frac{A_{\max}}{W}\text{ atoms/block}$$
   - **Weakening protections (4-of-7 quorum required):**
     - Increasing $A_{\max}$ ($A'_{\max} > A_{\max}$): allows more funds to be drained per window.
     - Shortening $W$ ($W' < W$): allowance window resets more rapidly, increasing the maximum spending rate ($R' = \frac{A_{\max}}{W'} > R$).
   - **Strengthening protections (3-of-7 quorum permitted):**
     - Decreasing $A_{\max}$ ($A'_{\max} < A_{\max}$): restricts spendable funds per window.
     - Lengthening $W$ ($W' > W$): allowance window takes longer to reset, lowering the maximum spending rate ($R' = \frac{A_{\max}}{W'} < R$).

4. **Authoritative Quorum Matrix:**

| Action | Quorum | Purpose / Justification |
|---|---:|---|
| **Strengthen protections** | **3-of-7** | Lower threshold to tighten security |
| **Increase delays** | **3-of-7** | Increase new-recipient or withdrawal delay |
| **Tighten allowance** | **3-of-7** | Lower spend limit or lengthen window duration |
| **Weaken protections** | **4-of-7** | Strict majority to reduce protections |
| **Decrease delays** | **4-of-7** | Decrease configured delays |
| **Increase allowance** | **4-of-7** | Increase spend limit or shorten window duration |
| **Freeze account** | **4-of-7** | Halt outgoing transfers from compromised account |
| **Unfreeze account** | **4-of-7** | Restore account operation after review |
| **Emergency recovery** | **4-of-7** | Sweep spendable balance to pre-registered recovery key |
| **Replace guardian set** | **4-of-7** | Update 7-guardian public key list |
| **Replace recovery key** | **4-of-7** | Update registered emergency recovery key |
| **Cancel pending transfer** | **4-of-7** | Revoke in-flight transfer before release height |
| **Cross-pool shielding** | **4-of-7** | Authorize funds leaving protected account to Orchard |

5. **Scope limitation:** Guardians govern only opted-in transparent accounts. Guardians do **NOT** follow or control shielded notes once funds enter Orchard. Shielded funds must never be advertised as guardian-protected.
6. **Per-transfer pending locks and principal accounting:**
   - When guardian protection is enabled on an account, a transfer to a recipient address that has not previously received a confirmed transfer from this sender creates a `PendingTransfer` record.
   - At inclusion (height $h$), the transaction fee `fee_atoms` is debited immediately from `sender.balance` and paid to the block producer.
   - **Principal treatment:** The principal `amount` remains within `sender.balance`, but is tracked in `sender.pending_transfers` with `release_height = h + new_recipient_delay` (default $h + 10$).
   - Because `amount` is deducted from `sender.spendable_balance(h)`, the sender cannot double-spend it.
   - Because `amount` is not yet credited to the recipient, it does not appear in recipient's balance.
   - **Proof of single-counting in global invariant:** In $T = \sum_{a \in Accounts} balance(a)$, the principal `amount` resides in `sender.balance` and nowhere else. It is counted **exactly once** in $T$. $T + S = I$ holds without anomaly.
   - At block height $\ge release\_height$, the pending transfer automatically matures during atomic block transition: `sender.balance -= amount`, `recipient.balance += amount`, and the pending record is removed. Net change to $T$ is $-amount + amount = 0$.
7. **Cancellation authorization and rules:**
   - A pending transfer may be cancelled prior to `release_height` via a `CancelPendingTransfer` transaction authorized by the sender and a **4-of-7 guardian quorum**.
   - **Principal restoration:** The pending record is removed from `sender.pending_transfers`. Because `amount` was already in `sender.balance`, removing the pending record immediately restores `amount` to `spendable_balance` without modifying `balance`. Single-counting in $T$ is preserved.
   - **Fee treatment:** The fee paid on the original transfer was consumed by the block producer at inclusion and is **non-refundable**. The cancellation transaction pays its own transaction fee.
   - **Nonce treatment:** The original transfer consumed its nonce; that nonce is **never reused**. The cancellation transaction consumes its own nonce.
8. **Overlapping delays:** Multiple transfers from an account may be pending concurrently. Each transfer has an independent `transfer_id`, `amount`, and `release_height`; each matures or cancels independently.
9. **Reorganization rollback:** If a block is reorganized out, all atomic state changes are rolled back cleanly: balances, nonces, allowance window spending, and pending records revert to their pre-block snapshot. Principal remains counted exactly once.

### 7.6 Transaction validation and atomic state transitions

Every validating node validates blocks and transactions according to these atomic transition rules:

1. **Transaction size and fee:** Verify $canonical\_size \le 1,000,000\text{ bytes}$ and $fee\_atoms \ge \max(1, 100 \times canonical\_size)$.
2. **Nonce and signature:** For each spending transaction, verify `tx.nonce == sender.nonce`. Verify the Ed25519 signature against `sender_pubkey` over the domain-separated preimage. Increment sender nonce by 1.
3. **Spendable balance and allowance:** Verify $amount + fee\_atoms \le sender.spendable\_balance(height)$. If allowance is configured and active, verify that $allowance\_spent + amount + fee\_atoms \le allowance\_limit$ for the active window; increment `allowance_spent`. If the window expired ($height \ge window\_start + window\_len$), reset `window_start = height` and `allowance_spent = 0` before checking.
4. **Freeze check:** Spends from a frozen account are rejected. Inbound transfers to a frozen account remain permitted.
5. **Atomic block execution:** All valid transactions in the block are applied in sequence. Matured pending transfers and matured coinbase tranches are processed. Coinbase payout is credited to the block producer and recorded as an immature tranche. Finally, `state_root` is recomputed over the complete account set and must match `header.state_root` exactly. If any check fails, the block is invalid and zero state changes are committed.

---

## 8. Network / transport

| Item | v1 decision |
|---|---|
| Framework | Rust `libp2p`, pinned by `Cargo.lock` at the reviewed version used in implementation |
| Transport | TCP with Noise secure channel and Yamux stream multiplexing for the first release; no custom transport protocol |
| Block/transaction gossip | libp2p Gossipsub with application-level validation before accepting data into local consensus state |
| Peer discovery | Kademlia DHT plus manually configured bootstrap peers; discovery nodes are not consensus authorities |
| Block synchronization | Versioned request/response messages for headers and block bodies; validate all received data locally |
| Application protocol | `/ownchain/1` with explicit protocol version and network/chain ID in handshake |
| Default ports | Development/testnet TCP `40333`; mainnet TCP `30333` if/when a mainnet is separately approved |
| Bootstrapping | Peer addresses may be supplied by the operator. Seed nodes are convenience infrastructure only. |
| Message encoding | Explicit versioned application messages with a `u32` little-endian length prefix; maximum application frame length is 2,100,000 bytes. Consensus serialization remains separate and does not include peer-to-peer framing. |

---

## 9. Wallet and key management

- Wallet keys use standard Ed25519 (RFC 8032) key generation from cryptographically secure entropy.
- The address envelope uses Bech32m with OwnChain network prefixes (`owndev` for devnet, `own` for testnet) and rejects addresses for different networks.
- Wallet files must be encrypted at rest with password-based key derivation (Argon2id) and authenticated encryption (ChaCha20-Poly1305). Never log private keys or seeds.
- Seed phrase backup format (BIP-39 mnemonic with standard derivation path) must be frozen in the wallet milestone.

---

## 10. Genesis and bootstrapping

- Genesis creates zero initial balance and zero spendable coins.
- Each network (`devnet`, `testnet`, future `mainnet`) has a distinct `chain_id` derived as $\text{BLAKE2b-256}(\text{UTF8("OwnChain/<network>/v1")})$. Blocks and transactions cannot be replayed across networks.
- Genesis header bytes, block ID, and Merkle roots are committed constants and verified by golden test vectors.
- Mainnet genesis is **not** approved by this document.

---

## 11. Security and privacy considerations

- **Shielded-first privacy by default:** Shielded transactions (Type 5) using Orchard V2 provide cryptographic confidentiality for note amounts, sender identities, and recipient addresses via zero-knowledge proofs (Halo2 `FixedPostNu6_2`). Ordinary shielded payments are the recommended and default wallet mode.
- **Transparent ledger observability:** Transparent account transfers (Type 1) publish all senders, recipients, amounts, and balances on-chain. Transparent accounts exist for public auditability, exchanges, and opt-in guardian protections.
- **Cross-pool linkability and best practices:** Moving value across pool boundaries (Types 6 and 7) discloses the transparent account address and the exact amount entering or exiting Orchard. Users must avoid trivial timing or value correlation when bridging between pools.
- **Guardian trust assumptions:** Guardians are per-account and opt-in only. If 4 of 7 guardians collude or are compromised, they can freeze the account, alter allowances, or execute emergency recovery. Guardians have **zero authority** over shielded notes once funds enter Orchard.
- **Quorum trade-offs:** 3-of-7 enables fast protection strengthening; 4-of-7 requires a strict majority to weaken protections or move funds.
- **Proof of work security:** Security relies on honest majority CPU work. On small testnets, hashpower rental attacks remain feasible.
- **No tail emission:** Miner revenue transitions to transaction fees after subsidy exhaustion; long-term security under low fees remains an open economic question.

---

## 12. Open items and release gates

1. **Gate 1 — Core serialization and vectors:** Publish canonical serialization and golden vectors for headers (including composite `state_root`), block IDs, transaction Merkle trees, account-state Merkle trees, Ed25519 signatures, minimum fees, subsidy schedules, coinbase maturity tranches, and cross-pool transfer validation vectors.

2. **Gate 2 — Transparent state-tree consensus test harness:** Demonstrate complete atomic execution of transparent state transitions, nonce verification, allowance window enforcement, per-transfer pending records, coinbase maturity tracking (spendable vs immature balance), 3-of-7 and 4-of-7 quorums, cancellation authorization, and `state_root` calculation with known-good and known-bad test fixtures.

3. **Gate 3 — Hybrid cross-pool validation gate:** Demonstrate shielded (Orchard V2) bundle validation, composite state root computation, transparent-to-shielded and shielded-to-transparent transfer logic with value conservation checks, guardian authorization for cross-pool transfers, and nullifier tracking across pool boundaries.

4. **Gate 4 — Pre-public testnet gate:** Production PoW configuration review (salt, RandomX integration, merge-mining feasibility assessment), multi-node synchronization, reorganisation recovery, and resource caps.

5. **Gate 5 — Pre-mainnet gate (Out of Scope for v1):** Full cryptographic audit, economic analysis, public threat model, and formal security sign-off. Must include review of hybrid architecture cross-pool transfer rules and guardian scope.

6. **Gate 6 — Differentiation gate:** Explicit documentation of technical properties relative to other architectures, including the shielded-first hybrid design.

---

## 13. Change log

- **2026-10-29 (Coinbase maturity state specification):**
  - Specified canonical per-account `coinbase_tranches` tracking in the transparent account ledger ($coinbase\_tx\_id[32] \parallel amount:\text{u128\_le} \parallel unlock\_height:\text{u64\_le}$).
  - Defined `spendable_balance` precisely as $balance - \sum immature\_coinbase\_tranches$, prohibiting spends of immature rewards even when mingled with mature funds.
  - Included `coinbase_tranches_count` and records in the canonical account state encoding committed to `state_root`.
  - Added test vectors for new coinbase reward, partially mature account, spending mature funds while reward is immature, rejection of spends exceeding mature funds, and exact unlock height boundary.
- **2026-10-29 (Experimental v1 baseline):**
  - Removed Orchard ordinary transfers, shielded coinbase, Orchard pool accounting, nullifiers, anchors, and Orchard compatibility gates from consensus specification (ADR-001).
  - Adopted transparent account ledger with Ed25519 signatures, nonces, spend allowances, delayed withdrawals, freeze/recovery, and 7-guardian governance (ADR-002).
  - Pinned header size at 170 bytes with `state_root` in the former `orchard_commitment_root` slot.
  - Specified RFC 6962-style domain-separated recursive-split Merkle tree with no odd-leaf duplication for both transaction and state trees.
  - Replaced recipient-wide activation lock with per-transfer pending records. Unrelated recipient funds remain spendable.
  - Standardized `tx_version: u16_le` consistently across all layouts and signing preimages.
  - Pinned consensus parameters: minimum fee `max(1, 100 * size)`, 10 OWN subsidy, 1,050,000-block halving, 21M OWN cap, 10-block delay, 144-block withdrawal delay, 1-block transfer maturity, 100-block coinbase maturity.
  - Retained Monero-style difficulty retarget and kept `OwnChain-PoW-v1` devnet-only pending production PoW gate (ADR-003).
- **2026-10-30 (Shielded-First Hybrid Architecture ADR-004):** Submitted ADR-004 for PROPOSED status, documenting the hybrid shielded-first architecture supporting both Orchard V2 shielded and transparent transactions. Includes composite state root design (ADR-004 §5), cross-pool transfer rules (ADR-004 §4), guardian scope clarifications (ADR-004 §6), coinbase/issuance parameters preserved provisionally (ADR-004 §7), and 5 explicit consensus blockers for future research. Transparent-only test vectors preserved as historical baseline (ADR-001). Entry criteria and milestone M1-H defined for prototype implementation.
