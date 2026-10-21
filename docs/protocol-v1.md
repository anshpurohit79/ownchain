# OwnChain Protocol v1 — Experimental Network Baseline

**Status:** Consolidated review revision dated 2026-10-20. The high-level architecture is fixed for OwnChain v1; the consensus-critical encoding and Orchard compatibility gates in §12 must pass before their corresponding implementation milestones. This is **not** a declaration that OwnChain is production-secure or ready for a mainnet holding valuable funds.

**Decision rule:** The v1 baseline stays fixed unless a reproducible correctness, security, legal/licensing, or feasibility problem is demonstrated. Changes require a written decision record and updated test vectors. Do not add mechanisms because they sound interesting.

## 1. Overview

### 1.1 Purpose
OwnChain is an independent, permissionless, native-coin blockchain experiment. Its v1 engineering objective is to build and operate a real multi-node network with CPU-oriented proof of work and shielded ordinary payments. It is not a token on another chain. No claim is made that OwnChain is more private, decentralised, secure, or useful than established networks.

### 1.2 Ordered design goals
1. Correct, deterministic consensus that independent nodes can verify.
2. A working, permissionless peer-to-peer network and native coin with no premine or founder-only mint authority.
3. Privacy for ordinary transfers using a maintained, established shielded-transaction implementation rather than custom cryptography.
4. CPU-oriented proof of work with public, deterministic validation rules.
5. Reproducible builds, protocol tests, and an auditable release process.

### 1.3 Non-goals for v1
- Smart contracts, EVM compatibility, general-purpose scripting, tokens, bridges, or cross-chain swaps.
- Proof of stake, committee consensus, proof of useful work, inclusion-list mechanisms, or bespoke zero-knowledge circuits.
- Transparent ordinary transfers. Ordinary transfer transactions use the shielded pool only.
- Claims of anonymity against network-level traffic analysis, a global observer, or a powerful mining majority.
- A mainnet launch, exchange listing, price target, or adoption guarantee before a separate security and launch review.

## 2. Terminology

- **Atom:** The smallest indivisible unit of the native coin.
- **OWN:** The native coin's provisional display ticker.
- **Orchard action:** The paired spend/output unit defined by the Orchard shielded protocol.
- **Nullifier:** A public value derived from a shielded spend that prevents the same note from being spent twice.
- **Commitment tree / anchor:** The Orchard tree of note commitments and a root identifying a tree state at a block boundary.
- **Target / difficulty:** The threshold and work requirement used to validate proof of work.
- **Cumulative work:** The sum of accepted per-block work along a chain; used for fork choice.
- **Experimental network:** The local development network and subsequent public testnet. Test coins have no promised monetary value.

## 3. Cryptographic primitives

| Purpose | v1 decision | Requirements |
|---|---|---|
| General protocol hash | BLAKE2b with 32-byte output (BLAKE2b-256) | Domain-separate every OwnChain hash use. Specify exact byte encodings before implementation. |
| Proof of work | RandomX **algorithm v1**, using reference implementation release `v1.2.3` | RandomX algorithm v2 is not part of OwnChain v1. Use the v1.2.3 `configuration.h` defaults except `RANDOMX_ARGON_SALT`, which is the exact byte string `OwnChain-PoW-v1`. No other RandomX parameter may differ. Build from the pinned source commit `12f2c2ffe2108d6cf54c391fee33c8bc3646cdab` (RandomX v1.2.3); use the upstream-supported build configuration and record compiler/build flags in the implementation manifest. Verify every non-genesis block independently and publish cross-platform golden vectors before enabling mining. |
| Shielded payment cryptography | Rust crate `orchard = 0.16.0`, pinned in `Cargo.lock` | Select `BundleVersion::orchard_v2()` / `ProtocolVersion::V2` and explicitly select `OrchardCircuitVersion::FixedPostNu6_2`. Enforce canonical proof length and all V2 validation rules. Never select `BundleVersion::orchard_insecure_v1()` (the historical pre-NU6.2 unsound protocol) or Orchard V3/Ironwood in OwnChain v1. Updates require security review and new vectors. |
| Orchard protocol version | Orchard **V2** (the corrected post-NU6.2 Orchard protocol version) within OwnChain protocol v1 | `orchard_v2()` is the intended upstream bundle version, not the insecure historical `orchard_insecure_v1()`. The terms “OwnChain v1” and “Orchard V2” refer to different version namespaces. Orchard V3/Ironwood and its post-NU6.3 circuit are excluded. |
| Shielded authorization | Orchard's RedPallas-based authorization and proof rules | No custom signatures, curves, hash functions, or proof circuits. |
| Node identity | libp2p identity key, separate from coin ownership | Peer identity never grants transaction or consensus privileges. |
| Address checksum/encoding | Bech32m envelope with OwnChain-specific network prefix and a versioned payload containing the canonical Orchard payment-address bytes | The exact payload encoding and test vectors must be written before wallet implementation. Do not claim compatibility with Zcash address strings. |

### Security-critical Orchard rule
A soundness vulnerability affecting Orchard's Action circuit was disclosed in 2026. The corrected post-NU6.2 circuit is required. The current crate exposes distinct bundle/protocol versions, including the historical insecure V1 and corrected V2, so the implementation must explicitly use `BundleVersion::orchard_v2()` and the corresponding fixed post-NU6.2 circuit; do not infer circuit safety from the crate version alone. Enforce canonical proof length, canonical point/scalar encodings, non-identity/valid authorization keys where required by upstream consensus, and all current validation checks incorporated by this chosen profile. Run upstream plus OwnChain-specific test vectors. See [ZIP 257](https://zips.z.cash/zip-0257), the [Orchard crate changelog](https://github.com/zcash/orchard/blob/main/CHANGELOG.md), and the [Orchard protocol ZIP](https://github.com/zcash/zips/blob/main/zips/zip-0224.rst).

## 4. Consensus

| Parameter | v1 decision |
|---|---|
| Consensus model | Nakamoto-style proof of work; no validator set or privileged operator |
| PoW algorithm | RandomX algorithm v1; reference implementation release `v1.2.3`; v2 is excluded |
| Target block interval | 120 seconds |
| Difficulty retarget | Every block; exact algorithm defined in §4.1. The reference is the CryptoNote/Monero `next_difficulty` algorithm with a 720-sample window, 15-block lag, trimming to 600 samples, and a 120-second target. |
| RandomX seed rotation | Follow RandomX's recommended delayed key-block schedule. For block height `h`, `key_height(h) = 0` when `h < 64`; otherwise `key_height(h) = 2048 × floor((h − 64) / 2048)`. The RandomX key is the block ID at that height. This means key block 0 is used first, and key block 2048 becomes active at height 2112. Publish golden vectors for boundary heights 63, 64, 2111, 2112, and 4160. |
| PoW check | Interpret RandomX's 32-byte result as a little-endian unsigned integer `h`; accept when `h <= floor((2^256 - 1) / difficulty)`. Difficulty must be the network-computed expected value, not a miner-selected value. |
| Per-block work | Each non-genesis block contributes its validated expected `difficulty`; genesis contributes zero work. Cumulative work is a checked unsigned 256-bit sum. |
| Fork choice | Valid chain with greatest cumulative work. If equal, compare block-ID sequences from genesis and select the lexicographically smaller sequence at the first differing height. This gives a deterministic total tie-break. |
| Finality | Probabilistic only; no block has absolute finality. Wallet confirmation counts are policy, not a consensus guarantee. |
| Timestamp rule | A block timestamp must be greater than the upper median of the available timestamps in the last 11 ancestor blocks (up to 11 for early heights); sort ascending and choose index `len / 2`. A node MUST defer accepting or relaying a block whose timestamp is more than two hours ahead of its adjusted local time, and retry it when local time catches up. This local-clock rule can cause temporary node disagreement and is not a permanent consensus invalidity; the median-time rule above remains the deterministic consensus timestamp rule. |
| Network authority | No founder key, admin key, or company approval is required for valid transactions or blocks. |
| Subsidy | See §5. No premine, genesis allocation, developer tax, or founder-controlled issuance key. |

RandomX's official project documentation recommends a 2048-block key period with a 64-block delay and recommends a unique configuration per project. OwnChain v1 uses the RandomX v1.2.3 configuration with only the Argon2 salt changed to the exact UTF-8 bytes `OwnChain-PoW-v1`; all other parameter values come from that release's `configuration.h`. This customization makes the reference output vectors OwnChain-specific and must be tested in both fast and light modes on supported architectures. It does not make rented hashpower or mining concentration impossible. See the [RandomX specification](https://github.com/tevador/RandomX/blob/v1.2.3/doc/specs.md), [configuration guide](https://github.com/tevador/RandomX/blob/v1.2.3/doc/configuration.md), and [release v1.2.3](https://github.com/tevador/RandomX/releases/tag/v1.2.3).

## 4.1 Exact difficulty algorithm

For a candidate block at height `h`, use only ancestors at heights `max(0, h - 735)` through `h - 16`, inclusive. This excludes the most recent 15 ancestors (the lag) and provides at most 720 samples. If fewer than two samples remain, expected difficulty is `1`. For 2 or more samples, keep the samples in chronological block-height order for the cumulative-work array. Copy their timestamps and sort that timestamp array ascending. Let `n` be the sample count. If `n <= 600`, set `cut_begin = 0` and `cut_end = n`; otherwise set `cut_begin = floor((n - 600 + 1) / 2)` and `cut_end = cut_begin + 600`. The exclusive end index is used. Let `time_span = sorted_timestamps[cut_end - 1] - sorted_timestamps[cut_begin]`; if this equals zero, use `1`. Let `C_i` be cumulative accepted work through the sample block at height `i`, with genesis cumulative work equal to zero; let `total_work = C_(cut_end - 1) - C_(cut_begin)`, using sample blocks in block-height order (do not reorder cumulative work when sorting timestamps). The expected difficulty is `ceil(total_work * 120 / time_span)`. All intermediate arithmetic is checked and must not wrap. If the computed result is zero or exceeds `u128::MAX`, the implementation must fail closed and report a protocol-boundary error; it must never silently clamp or wrap. Golden vectors must cover startup heights, lengths 600/601/720, duplicate timestamps, fast/slow blocks, and integer boundary cases. This is a precise OwnChain rule based on the cited Monero algorithm, not a dependency on a moving `master` branch.

## 5. Ledger parameters

| Parameter | v1 decision |
|---|---|
| Native coin | OwnCoin; provisional ticker `OWN` |
| Smallest unit | `1 OWN = 100,000,000 atoms` |
| Genesis allocation | Zero. Genesis creates no spendable coins. |
| Starting block subsidy | 10 OWN for block heights 1 through 1,051,200 |
| Halving interval | Every 1,051,200 blocks; subsidy is integer-divided by 2 at each new era, in atoms, rounding down |
| Theoretical subsidy cap | 21,024,000 OWN before atom-level rounding; actual total is no greater. This is an upper bound on subsidy issuance, not a promise of market value. |
| Tail emission | None in v1. After integer subsidy reaches zero, miner revenue relies on transaction fees. This long-term security risk must be stated publicly. |
| Fees | Exact public consensus fee in atoms: `max(1,000, 1,000 × action_count + canonical_transaction_size_in_bytes)`. `action_count` is the Orchard action count. `fee_atoms` is a fixed-width unsigned 64-bit field; canonical transaction size includes that field but excludes the surrounding block length prefix and peer-to-peer transport framing. Arithmetic is checked; overflow invalidates the transaction. This is a fixed formula, not a dynamic fee market. |
| Fee recipient | Included in the block producer's valid coinbase payout; fees are transfers of existing value, not new issuance. |
| Coinbase payout | At most the scheduled subsidy plus the sum of valid included transaction fees. No other coin creation is permitted. |
| Shielded-pool accounting | All spendable value is held in the single Orchard V2 pool. Define pool balance as the negation of the sum of all accepted `valueBalanceOrchard` fields on the selected chain, following ZIP 209's sign convention. Require `0 <= pool_balance <= 2,102,400,000,000,000 atoms` after each accepted block. For an ordinary transfer with no transparent inputs/outputs, the public Orchard value balance must equal `+fee_atoms` (value leaving the pool); the coinbase value balance is the negative of its publicly recovered payout (value entering the pool). Enforce value conservation and the subsidy-plus-fees payout bound. Amounts of ordinary transfers remain hidden. |
| Coinbase privacy | OwnChain defines a chain-specific shielded coinbase rule inspired by ZIP 213; it is not a claim that OwnChain uses all current Zcash coinbase rules unchanged. The Orchard V2 coinbase bundle must have spends disabled, exactly one Orchard action, and exactly one real reward output (the action's spend side is the protocol-required dummy). Every node must recover and validate its note/value using the all-zero outgoing viewing key; the reward destination and value are therefore publicly recoverable. This custom rule must pass the Orchard V2 compatibility gate in §12 before it is implemented. Miner reward privacy is not claimed. |
| Coinbase maturity | No separate 100-block maturity rule for shielded coinbase notes in v1. Reorganizations roll back the Orchard tree and descendants together. Wallets should still wait for confirmations before relying on a reward. |

The emission constants are a deliberately explicit experimental baseline, not a claim that these are optimal tokenomics. Any change before a public mainnet requires a documented economics/security review; changing them after launch would require a planned consensus upgrade and community coordination.

## 6. Block structure

### 6.1 Canonical header fields

The v1 header contains, in this order:

1. `version`: unsigned 16-bit integer, initially `1`.
2. `chain_id`: 32 bytes.
3. `height`: unsigned 64-bit integer.
4. `parent_block_id`: 32 bytes; all zero bytes only for genesis.
5. `transaction_root`: 32 bytes.
6. `orchard_commitment_root`: 32 bytes, after appending all Orchard commitments in canonical transaction/action order.
7. `timestamp`: unsigned 64-bit Unix seconds.
8. `difficulty`: unsigned 128-bit integer, little-endian encoded.
9. `nonce`: unsigned 64-bit integer, little-endian encoded.

All fixed-width integers are little-endian. No platform-dependent struct layout or default serializer output may define consensus encoding. The header is exactly 170 bytes. The canonical block encoding is `header_bytes || tx_count:u32_le || repeated(tx_length:u32_le || tx_bytes)`. `tx_count` and `tx_length` use fixed-width unsigned 32-bit little-endian fields. The 2,000,000-byte consensus block limit applies to this canonical encoding, including these fields, but excludes any libp2p message/transport framing. The RandomX input is the 170 canonical header bytes, including the nonce. The block ID is BLAKE2b-256 over `"OwnChain/Block/v1" || canonical_header_bytes`.

### 6.2 Transaction commitment

Transaction IDs are BLAKE2b-256 over `"OwnChain/Tx/v1" || canonical_transaction_bytes`. The transaction Merkle tree is domain-separated: leaves use `"OwnChain/TxLeaf/v1"`, inner nodes use `"OwnChain/TxNode/v1"`, odd final nodes are duplicated, and the empty-tree root is BLAKE2b-256 of `"OwnChain/TxEmpty/v1"`. Publish test vectors for empty, one-, two-, and three-transaction blocks.

### 6.3 Limits and ordering

- Maximum canonical serialized block size: 2,000,000 bytes, including the 170-byte header, transaction count, each transaction-length field, coinbase, transactions, proofs, and authorizing data. Excludes outer peer-to-peer transport framing.
- Maximum canonical serialized non-coinbase transaction size: 1,000,000 bytes, including its transaction envelope, proof, and authorization data, but excluding the enclosing block's `tx_length` field.
- Maximum Orchard actions per transaction: 50.
- Maximum total Orchard actions per block: 2,000.
- The coinbase is transaction index 0 and exactly one coinbase is required in every non-genesis block.
- Transactions are serialized and committed in the exact order they appear in the block. A node must reject duplicate transaction IDs and duplicate nullifiers within a block or against the selected chain.
- The Orchard commitment tree uses the upstream Orchard tree rules and its fixed depth of 32. The header root is the tree state after processing the complete block.

### 6.4 Genesis

Genesis has height 0, a zero parent ID, no transactions, no subsidy, difficulty `1`, nonce `0`, timestamp `1792454400` (`2026-10-20T00:00:00Z`), and the canonical empty Orchard tree root. Each network has a separate `chain_id` derived as `BLAKE2b-256(UTF8("OwnChain/<network-name>/v1"))`. The first development network is named `devnet`; its ID is therefore derived from `OwnChain/devnet/v1`. Genesis is a fixed protocol constant and skips RandomX validation. Its computed header and block ID must be committed as golden constants before node synchronization is implemented; startup must never regenerate genesis from the current clock.

## 7. Transaction structure

### 7.0 Canonical outer envelope

Every transaction begins with `tx_type:u8 || tx_version:u16_le || chain_id:[u8;32]`; `tx_version` is `1` and `chain_id` must equal the active network's 32-byte ID. `tx_type=0` is Coinbase and its payload is `height:u64_le || Orchard-V2-bundle-bytes`. `tx_type=1` is OrchardTransfer and its payload is `fee_atoms:u64_le || Orchard-V2-bundle-bytes`. The Orchard bundle uses the canonical Orchard V2 encoding specified by the Orchard protocol and the V5 Orchard-component serialization rules in the cited Zcash transaction specifications; transparent inputs/outputs and other pools are forbidden. The transaction byte length is supplied by the enclosing canonical block encoding. Unknown types/versions are invalid. `fee_atoms` is fixed width, so including it in the transaction size does not create a variable-length fee/size cycle.

The exact Orchard V2 bundle/effects encoding and the OwnChain transaction authorization digest are covered by the mandatory compatibility gate in §12. They must be pinned in test vectors before any spendable Orchard-transfer implementation is merged; no hand-invented signature or proof serialization is permitted.

### 7.1 Transaction types

V1 supports only:
- `Coinbase`: only at block position 0; creates the permitted scheduled subsidy and collects included transaction fees.
- `OrchardTransfer`: a shielded-only ordinary payment using the selected corrected Orchard V2 profile.

There are no transparent ordinary inputs or outputs, account balances, account nonces, public sender/recipient fields, or smart-contract calls in v1. The OwnChain transaction envelope is not a complete Zcash transaction; it embeds only the defined Orchard V2 bundle component in the specified envelope.

### 7.2 Ordinary transfer visibility

A transaction reveals its ID, inclusion height, time, serialized size, action count, public fee, Orchard nullifiers, commitment data, anchor, and proof/signature fields. It is intended to conceal ordinary payment sender, recipient, and transferred amounts, subject to Orchard's documented assumptions. Transaction timing/size analysis, network-layer IP metadata, wallet compromise, and a global traffic observer are not hidden by this protocol.

### 7.3 Validation

Every validating node must, at minimum:
1. Enforce the canonical outer envelope, Orchard V2 bundle encoding, transaction size/action caps, and active chain ID. The Orchard spend-authorization digest must be domain-separated by `OwnChain/TxAuth/v1` and must commit to the active chain ID plus every consensus-relevant transaction effect (type/version, fee or coinbase height, Orchard value balance, anchor, action effect fields and flags). The exact effect-byte encoding and API compatibility are gated by §12. Use Orchard's RedPallas authorization primitive; do not invent a new signature scheme.
2. Verify the bundle using `BundleVersion::orchard_v2()` and `OrchardCircuitVersion::FixedPostNu6_2`, including canonical proof size, canonical point/scalar encodings, non-identity/valid authorization-key checks required by the selected upstream consensus rules, and all Orchard V2 validation checks selected by this specification.
3. Verify the anchor is an Orchard commitment-tree root recorded at the end of any ancestor block on the selected chain. Retain or deterministically reconstruct these roots, and roll them back during reorganisation.
4. Reject every nullifier already used on the selected chain or earlier in the same block.
5. Enforce the public fee formula exactly and enforce value conservation through Orchard's specified public value-balance relation. There must be no alternate/custom proof path that bypasses the Orchard relation.
6. Update the Orchard commitment tree and pool-value state in deterministic transaction/action order. Validation is atomic: a rejected block applies no partial state changes.
7. Reject unsupported transaction versions, unknown fields, oversized counts, duplicate IDs, integer overflows, negative/out-of-range values, and malformed proofs.

The outer envelope is fixed in §7.0. Before Orchard transfers are integrated, a compatibility harness must establish the exact Orchard V2 bundle/effects byte encoding and show known-good and known-bad vectors for: one valid shielded action bundle; altered and invalid proofs; a non-canonical proof length; invalid/identity authorization keys; a duplicate nullifier; stale/unknown anchors; cross-chain replay; and fee/value-balance sign handling. For an ordinary transfer with no transparent flows, the consensus rule is `valueBalanceOrchard = +fee_atoms`; for the coinbase, it is `valueBalanceOrchard = -payout_atoms`. Confirm these signs against the selected API and its upstream test vectors before merging implementation. If the pinned Orchard V2 API cannot realize these stated rules, stop and report that one concrete blocker; do not change the architecture silently.

### 7.4 Pool-value conservation and fees

The only spendable pool in OwnChain v1 is Orchard V2. Following the chain-pool convention in ZIP 209, the chain's Orchard pool balance is `-sum(valueBalanceOrchard)` over all accepted transactions on the selected chain. The genesis balance is zero. It must never be negative and must never exceed `2,102,400,000,000,000` atoms (the theoretical issuance upper bound).

For an ordinary transfer, the only external flow is the public fee: `valueBalanceOrchard` is positive and exactly equal to `fee_atoms`. For the coinbase, `valueBalanceOrchard` is negative and equal in magnitude to the value recoverable from its all-zero-OVK reward output. The block producer's payout must be at least the sum of included transaction fees and must not exceed the scheduled subsidy plus those fees; the miner may leave some or all of its subsidy unclaimed, but cannot redirect or destroy included fees by underclaiming them. Nodes must validate the whole block transition atomically, including the pool-balance bound and the subsidy bound; there is no transparent pool or alternate path for issuing spendable value. The fee formula is consensus-fixed for the experimental baseline and provides no dynamic bid market; this is a known economic limitation to review before any mainnet proposal.

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
| Bootstrapping | Peer addresses may be supplied by the operator. Seed nodes are convenience infrastructure only; any single seed may fail without changing consensus rules. |
| Message encoding | Explicit versioned application messages with a `u32` little-endian length prefix; maximum application frame length is 2,100,000 bytes. Consensus serialization remains separate and does not include peer-to-peer framing. Reject oversize frames before allocating their payload. |

## 9. Wallet and key management

- Use Orchard's documented key/address derivation and signing facilities; never invent a cryptographic derivation scheme.
- The wallet generates spending keys using a cryptographically secure random generator and displays the recovery material only at the user's explicit request.
- The address envelope must use a distinct OwnChain prefix for each network and reject an address for the wrong network.
- Wallet files must be encrypted at rest with a reviewed password-based key derivation and authenticated-encryption construction from maintained libraries. Never log seeds, spending keys, plaintext notes, or decrypted transaction amounts.
- The seed phrase / backup format, derivation path, encryption parameters, and wallet file format are non-consensus wallet specifications to be frozen in the wallet milestone before a usable wallet is released. No wallet may ship before recovery tests prove that a backup restores the same spending keys and viewing state.

## 10. Genesis and bootstrapping

- Genesis creates no spendable balance and no coin allocation.
- `devnet`, `testnet`, and any future `mainnet` must have different chain IDs and genesis hashes. A block or transaction from one network must not be accepted on another.
- Genesis is checked against committed constants and golden vectors, not generated dynamically at startup.
- The initial devnet can be bootstrapped by manually configured local node addresses. The future public testnet may publish multiple independent bootstrap addresses; these are not privileged in consensus.
- A mainnet genesis is **not** approved by this document. It requires the pre-mainnet gates in §12.

## 11. Security and privacy considerations

- Proof of work gives probabilistic reorganisation resistance, not deterministic finality. Security depends on a sustained honest-majority-work assumption; a small testnet has little attack cost and must never be treated as safe for valuable funds.
- RandomX is CPU-oriented, not guaranteed ASIC-proof or decentralised. Mining concentration, rented hashpower, botnets, and network partitions remain risks.
- The fixed-supply/no-tail-emission design means miner revenue can fall after subsidy issuance declines; fee-market adequacy is unproven.
- Shielded transaction correctness depends on using the explicitly fixed and corrected Orchard circuit version, canonical proof-length checks, upstream validation rules, and tested public value-balance accounting. Orchard's historical soundness vulnerability shows why this code must be kept current and reviewed; test vectors do not replace an independent audit.
- Shielded coinbase data is deliberately publicly recoverable for consensus reward validation, so mining payouts do not have the same privacy as ordinary transfers.
- Payment privacy does not imply IP-address privacy. The first peer that observes a transaction may infer its origin; v1 does not promise Dandelion++, Tor, or I2P anonymity.
- Traffic analysis can use transaction timing, size, fees, action counts, and block inclusion. Wallet compromise exposes plaintext data.
- Consensus serialization, hash domain separation, integer arithmetic, difficulty retargeting, fork choice, reorg state rollback, nullifier tracking, and Orchard pool balances require adversarial tests and independent review.
- Dependency updates affecting proof verification, consensus, RandomX, serialization, or networking must be reviewed as protocol-sensitive changes, not blindly auto-updated.
- No mainnet deployment or valuable-funds recommendation until the pre-mainnet gates below pass.

## 12. Open items and release gates

These are **gated deliverables**, not permission to change the architecture casually:

1. **Before M1 implementation:** publish canonical serialization and hash test vectors for genesis, headers, block IDs, transaction IDs, Merkle roots, and the RandomX input blob.
2. **Before Orchard transaction integration:** a bounded compatibility implementation must build against `orchard = 0.16.0`, use `BundleVersion::orchard_v2()` and `FixedPostNu6_2`, prove and verify one valid transfer bundle and one output-only coinbase bundle, reject an invalid proof/non-canonical proof length/invalid authorization key/duplicate nullifier/unknown anchor/cross-chain replay, and demonstrate the fee/value-balance sign convention with vectors. If the selected API cannot realize the stated rules, stop and document the exact blocker before changing architecture.
3. **Before public testnet:** add multi-node synchronization, persistence/recovery, reorganisation tests, mining tests, difficulty edge cases, malformed network-message tests, resource caps, and an operator guide.
4. **Before mainnet:** independent protocol/cryptography audit, review of current Orchard advisories and circuit version, review of RandomX integration/licensing, fee/emission and low-hashrate analysis, wallet recovery and privacy review, a public threat model, and a fixed mainnet genesis. A failed gate blocks mainnet; it does not automatically authorize a new architecture.
5. **Differentiation gate:** OwnChain has not yet demonstrated a unique advantage over Monero, Zcash, or other privacy coins. No novelty or superiority claim may be made until supported by evidence. This does not block building an experimental network, but it does block marketing a proven advantage.

## 13. Change log

- v1 baseline drafted 2026-10-20; consolidated technical review revision 2026-10-20: Rust; RandomX algorithm v1 with pinned reference release/configuration; 120-second target; exact lagged CryptoNote/Monero-style retarget; corrected Orchard V2 (post-NU6.2) shielded payments; libp2p transport; no premine/founder mint authority; 10 OWN starting subsidy with 1,051,200-block halvings; canonical block serialization and explicit transport limit; experimental-network-only status.

## Primary references

- [RandomX reference release v1.2.3](https://github.com/tevador/RandomX/releases/tag/v1.2.3), pinned commit `12f2c2ffe2108d6cf54c391fee33c8bc3646cdab`
- [ZIP 225: Version 5 Transaction Format](https://github.com/zcash/zips/blob/main/zips/zip-0225.rst)
- [ZIP 244: Transaction Identifier Non-Malleability](https://github.com/zcash/zips/blob/main/zips/zip-0244.rst)
- [RandomX v1 configuration](https://github.com/tevador/RandomX/blob/v1.2.3/doc/configuration.md)
- [RandomX v1 specification](https://github.com/tevador/RandomX/blob/v1.2.3/doc/specs.md)
- [Monero technical specification](https://github.com/monero-project/monero-docs/blob/master/docs/en/technical-specs.md)
- [Monero difficulty reference implementation](https://github.com/monero-project/monero/blob/master/src/cryptonote_basic/difficulty.cpp)
- [Orchard protocol ZIP 224](https://github.com/zcash/zips/blob/main/zips/zip-0224.rst)
- [Orchard crate changelog](https://github.com/zcash/orchard/blob/main/CHANGELOG.md)
- [ZIP 257: Orchard temporary vulnerability mitigation and NU6.2](https://zips.z.cash/zip-0257)
- [ZIP 213: shielded coinbase](https://github.com/zcash/zips/blob/main/zips/zip-0213.rst)
- [Orchard commitment tree](https://zcash.github.io/orchard/design/commitment-tree.html)
- [Rust libp2p](https://github.com/libp2p/rust-libp2p)


## Consolidated review notes (2026-10-20)

This revision resolves the prior document's internal naming conflict between OwnChain v1 and Orchard's upstream protocol versions, makes the RandomX algorithm/configuration explicit, specifies the lagged difficulty calculation and startup behavior, defines canonical block framing and separates it from transport framing, and makes the intended fee/value-balance sign rules explicit.

The remaining Orchard gates are intentional and narrow: the exact V2 bundle/effects serialization and authorization-digest integration must be proven against the pinned `orchard` crate, including an output-only shielded coinbase. These are compatibility checks, not an invitation to redesign the chain. No production-security, privacy-superiority, or adoption claim is implied.
